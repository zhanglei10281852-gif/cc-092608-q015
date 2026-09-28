from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.clock import FrozenClock, to_storage
from app.database import get_connection
from app.network.analytics import NetworkAnalytics
from app.network.retention import (
    DEFAULT_RETENTION_DAYS,
    PrivacyRetentionService,
)

DUE = "subscriber-due-000000000001"
RECENT = "subscriber-recent-0000000002"
HELD = "subscriber-held-000000000003"
DISPUTE = "subscriber-dispute-000000004"

NOW = datetime(2027, 4, 1, 8, 0, tzinfo=UTC)
OLD = NOW - timedelta(days=200)
NEW = NOW - timedelta(days=7)


def _seed(client) -> int:
    client.post(
        "/api/network/scenarios",
        json={"code": "rail-x", "name": "试验高铁", "scene_type": "railway", "timezone": "Asia/Shanghai", "max_concurrent_sessions": 100, "capacity_mbps": 1000},
    )
    client.post(
        "/api/network/scenarios/rail-x/segments",
        json={"code": "seg-a", "name": "甲区段", "sequence_no": 1, "expected_dwell_seconds": 300, "capacity_mbps": 400},
    )
    client.post(
        "/api/network/applications",
        json={"app_code": "game-fast", "name": "加速游戏", "category": "game", "latency_target_ms": 60, "packet_loss_target": 0.01, "min_downlink_mbps": 5, "min_uplink_mbps": 2, "default_priority": 80},
    )
    policy = client.post(
        "/api/network/scenarios/rail-x/policies",
        json={"rules": {
            "score": {"latency_weight": 0.35, "packet_loss_weight": 0.30, "downlink_weight": 0.20, "uplink_weight": 0.15, "major_threshold": 1.5, "critical_threshold": 2.5},
            "allocation": {"minor_multiplier": 1.15, "major_multiplier": 1.5, "critical_multiplier": 2.0, "duration_seconds": 180, "max_downlink_mbps": 200.0, "max_uplink_mbps": 50.0},
        }, "actor": "tests"},
    ).json()
    client.post(f"/api/network/policies/{policy['id']}/publish", json={"actor": "tests", "effective_from": "2026-01-01T00:00:00Z"})
    return policy["id"]


def _insert_subject(connection, *, subscriber: str, observed: datetime, incident_state: str, order_seq: int, with_session: bool = False):
    scenario = connection.execute("SELECT id FROM network_scenarios WHERE code='rail-x'").fetchone()[0]
    segment = connection.execute("SELECT id FROM network_segments WHERE scenario_id=? AND code='seg-a'", (scenario,)).fetchone()[0]
    app = connection.execute("SELECT id FROM application_profiles WHERE app_code='game-fast'").fetchone()[0]
    policy = connection.execute("SELECT id FROM policy_versions WHERE scenario_id=?", (scenario,)).fetchone()[0]
    observed_at = to_storage(observed)
    cursor = connection.execute(
        "INSERT INTO experience_samples(sample_key,scenario_id,segment_id,app_id,subscriber_hash,device_class,"
        "train_speed_kmh,latency_ms,packet_loss,downlink_mbps,uplink_mbps,observed_at,received_at,payload_digest) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (f"sample-{order_seq:04d}", scenario, segment, app, subscriber, "phone", 300,
         350, 0.08, 1.0, 0.3, observed_at, observed_at, f"digest-{order_seq}"),
    )
    sample_id = cursor.lastrowid
    incident = connection.execute(
        "INSERT INTO quality_incidents(sample_id,scenario_id,segment_id,app_id,severity,reasons_json,state,opened_at,resolved_at) "
        "VALUES(?,?,?,?, 'major','{}',?,?,?)",
        (sample_id, scenario, segment, app, incident_state, observed_at,
         observed_at if incident_state == "resolved" else None),
    )
    connection.execute(
        "INSERT INTO subscriber_entitlements(subscriber_hash,scenario_id,product_code,valid_from,valid_until,"
        "source_order_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
        (subscriber, scenario, "rail-boost", to_storage(observed - timedelta(days=1)),
         to_storage(observed + timedelta(days=1)), f"order-{order_seq:04d}", observed_at, observed_at),
    )
    if with_session:
        session = connection.execute(
            "INSERT INTO acceleration_sessions(incident_id,subscriber_hash,app_id,scenario_id,segment_id,"
            "policy_version_id,status,allocated_downlink_mbps,allocated_uplink_mbps,priority,started_at,expires_at,ended_at,end_reason) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (incident.lastrowid, subscriber, app, scenario, segment, policy, "completed",
             12.0, 4.0, 90, observed_at, to_storage(observed + timedelta(minutes=3)),
             to_storage(observed + timedelta(minutes=3)), "finished"),
        )
        session_id = session.lastrowid
        connection.execute(
            "INSERT INTO capacity_reservations(session_id,scenario_id,segment_id,downlink_mbps,uplink_mbps,state,held_at,released_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (session_id, scenario, segment, 12.0, 4.0, "released", observed_at,
             to_storage(observed + timedelta(minutes=3))),
        )
        connection.execute(
            "INSERT INTO session_events(session_id,event_type,actor,detail_json,created_at) VALUES(?,?,?,?,?)",
            (session_id, "completed", "tests",
             f'{{"subscriber_hash": "{subscriber}", "note": "line-{subscriber}"}}', observed_at),
        )


def _populate(client):
    connection = get_connection()
    _insert_subject(connection, subscriber=DUE, observed=OLD, incident_state="resolved", order_seq=1, with_session=True)
    _insert_subject(connection, subscriber=RECENT, observed=NEW, incident_state="resolved", order_seq=2)
    _insert_subject(connection, subscriber=HELD, observed=OLD, incident_state="resolved", order_seq=3)
    _insert_subject(connection, subscriber=DISPUTE, observed=OLD, incident_state="open", order_seq=4)
    service = PrivacyRetentionService(connection, FrozenClock(NOW))
    service.add_legal_hold({"subscriber_hash": HELD, "reason": "监管协查工单 J-2027-0001", "actor": "compliance"})
    return service


def _aggregate_report(connection) -> dict:
    analytics = NetworkAnalytics(connection)
    return {
        "overview": analytics.quality_overview(),
        "scenarios": analytics.scenario_breakdown(),
        "applications": analytics.application_breakdown(),
        "segments": analytics.segment_breakdown(None),
        "severity": analytics.severity_distribution(),
        "capacity": analytics.capacity_snapshot(),
        "outcomes": analytics.acceleration_outcomes(),
    }


def test_preview_classifies_subjects_and_tables(client):
    _seed(client)
    service = _populate(client)
    preview = service.preview(retention_days=DEFAULT_RETENTION_DAYS)
    assert preview["state"] == "preview"
    assert preview["subjects_total"] == 4
    assert preview["due_subjects"] == 1
    reasons = {item["reason"]: item["count"] for item in preview["skipped"]}
    assert reasons == {"active_legal_hold": 1, "active_dispute": 1, "retention_not_reached": 1}
    tables = preview["tables"]
    assert tables["experience_samples"]["scanned"] == 1
    assert tables["experience_samples"]["updated"] == 1
    assert tables["acceleration_sessions"]["scanned"] == 1
    assert tables["quality_incidents"]["scanned"] == 1
    assert tables["capacity_reservations"]["scanned"] == 1
    assert tables["session_events"]["scanned"] == 1
    assert tables["subscriber_entitlements"]["scanned"] == 1
    # 预演不改变任何数据
    connection = get_connection()
    assert connection.execute("SELECT COUNT(*) FROM experience_samples WHERE subscriber_hash=?", (DUE,)).fetchone()[0] == 1


def test_execute_deidentifies_identity_query_empty_aggregates_unchanged(client):
    _seed(client)
    service = _populate(client)
    connection = get_connection()
    before = _aggregate_report(connection)

    report = service.execute(actor="compliance-batch", retention_days=DEFAULT_RETENTION_DAYS)

    assert report["state"] == "completed"
    assert report["processed_subjects"] == 1
    assert report["skipped_subjects"] == 3
    assert report["verification"] == {
        "projected_hashes_match": True,
        "aggregates_match": True,
        "identity_columns_replaced": True,
        "audit_links_preserved": True,
    }
    tables = report["tables"]
    assert tables["experience_samples"] == {"scanned": 1, "updated": 1}
    assert tables["acceleration_sessions"] == {"scanned": 1, "updated": 1}
    assert tables["subscriber_entitlements"] == {"scanned": 1, "updated": 1}
    assert tables["session_events"]["updated"] == 1
    assert tables["quality_incidents"] == {"scanned": 1, "updated": 0}
    assert tables["capacity_reservations"] == {"scanned": 1, "updated": 0}
    assert report["checksums"]["before"] != report["checksums"]["after"]
    assert report["projected_checksums"]["before"] == report["projected_checksums"]["after"]

    # 身份查询找不到该用户
    footprint = service.subject_footprint(DUE)
    assert footprint == {
        "subscriber_hash": DUE, "found": False, "samples": 0, "incidents": 0,
        "sessions": 0, "entitlements": 0, "active_legal_holds": 0,
    }
    # 被暂缓的主体仍可定位
    assert service.subject_footprint(HELD)["found"] is True
    assert service.subject_footprint(HELD)["active_legal_holds"] == 1
    assert service.subject_footprint(DISPUTE)["sessions"] == 0
    assert service.subject_footprint(DISPUTE)["samples"] == 1
    assert service.subject_footprint(RECENT)["found"] is True

    # 统计键批次隔离、不可逆：密钥已清除，键带批次前缀
    run = connection.execute("SELECT batch_secret FROM privacy_retention_runs WHERE id=?", (report["run_id"],)).fetchone()
    assert run["batch_secret"] == ""
    stat_rows = connection.execute(
        "SELECT DISTINCT subscriber_hash FROM experience_samples WHERE subscriber_hash LIKE 'stat-b%'"
    ).fetchall()
    assert len(stat_rows) == 1
    key = stat_rows[0][0]
    assert key.startswith(f"stat-b{report['run_id']:06d}-")
    sample_key = connection.execute("SELECT subscriber_hash FROM experience_samples WHERE sample_key='sample-0001'").fetchone()[0]
    assert sample_key == key
    # 同一主体在样本/会话/权益/事件中收敛为同一个统计键
    session_key = connection.execute("SELECT subscriber_hash FROM acceleration_sessions WHERE incident_id=(SELECT id FROM quality_incidents WHERE sample_id=(SELECT id FROM experience_samples WHERE sample_key='sample-0001'))").fetchone()[0]
    entitlement_key = connection.execute("SELECT subscriber_hash FROM subscriber_entitlements WHERE source_order_id='order-0001'").fetchone()[0]
    assert session_key == key == entitlement_key
    event_detail = connection.execute(
        "SELECT detail_json FROM session_events WHERE session_id=(SELECT id FROM acceleration_sessions WHERE subscriber_hash=?)",
        (key,),
    ).fetchone()[0]
    assert DUE not in event_detail
    assert key in event_detail

    # 质差链、容量预留、策略版本关联保持不变
    link = connection.execute(
        "SELECT s.policy_version_id,r.state,r.downlink_mbps,i.state FROM acceleration_sessions s "
        "JOIN capacity_reservations r ON r.session_id=s.id "
        "JOIN quality_incidents i ON i.id=s.incident_id WHERE s.subscriber_hash=?",
        (key,),
    ).fetchone()
    assert link["state"] == "released"
    assert link["downlink_mbps"] == 12.0
    assert link["policy_version_id"] > 0

    # 聚合报表数值保持不变
    after = _aggregate_report(connection)
    assert after == before

    # 检查点在完成后清理
    assert connection.execute("SELECT COUNT(*) FROM privacy_retention_checkpoints").fetchone()[0] == 0


def test_repeated_execution_does_not_change_digests_again(client):
    _seed(client)
    service = _populate(client)
    connection = get_connection()
    first = service.execute(actor="compliance-batch")
    key_after_first = connection.execute("SELECT subscriber_hash FROM experience_samples WHERE sample_key='sample-0001'").fetchone()[0]
    snapshot_after_first = first["checksums"]["after"]

    second = service.execute(actor="compliance-batch")
    assert second["processed_subjects"] == 0
    assert second["skipped_subjects"] == 3
    key_after_second = connection.execute("SELECT subscriber_hash FROM experience_samples WHERE sample_key='sample-0001'").fetchone()[0]
    assert key_after_second == key_after_first
    assert second["checksums"]["before"] == snapshot_after_first
    assert second["checksums"]["after"] == snapshot_after_first
    assert second["verification"]["aggregates_match"] is True


def test_interrupted_run_resumes_from_checkpoint(client):
    _seed(client)
    service = _populate(client)
    connection = get_connection()
    try:
        service.execute(actor="compliance-batch", _interrupt_after=2)
        assert False, "应当在检查点处中断"
    except Exception as exc:
        assert getattr(exc, "context", {}).get("resumable") is True

    progress = service.report(1)
    assert progress["state"] == "failed"
    assert progress["resumable"] is True
    assert progress["processed_checkpoints"] == 2
    # 已完成的主体已经去关联，中断不回滚
    processed_key = connection.execute("SELECT subscriber_hash FROM experience_samples WHERE sample_key='sample-0001'").fetchone()[0]
    assert processed_key.startswith("stat-b000001-")

    report = service.resume(1)
    assert report["state"] == "completed"
    assert report["resumed_from_checkpoint"] is True
    assert report["processed_subjects"] == 1
    assert report["verification"]["aggregates_match"] is True
    assert service.subject_footprint(DUE)["found"] is False
    assert service.subject_footprint(RECENT)["found"] is True
    assert connection.execute("SELECT COUNT(*) FROM privacy_retention_checkpoints").fetchone()[0] == 0


def test_legal_hold_release_allows_later_batch(client):
    _seed(client)
    service = _populate(client)
    first = service.execute(actor="compliance-batch")
    assert service.subject_footprint(HELD)["found"] is True

    hold = service.list_legal_holds("active")[0]
    service.release_legal_hold(hold["id"], "compliance", "协查结束")
    second = service.execute(actor="compliance-batch")
    assert second["run_id"] == first["run_id"] + 1
    assert second["processed_subjects"] == 1
    key = get_connection().execute(
        "SELECT subscriber_hash FROM experience_samples WHERE sample_key='sample-0003'"
    ).fetchone()[0]
    assert key.startswith(f"stat-b{second['run_id']:06d}-")
    assert service.subject_footprint(HELD)["found"] is False
    # DISPUTE 仍被暂缓
    assert service.subject_footprint(DISPUTE)["found"] is True


def test_preview_and_execute_require_authentication(client):
    response = client.post("/api/network/privacy/retention/preview", json={"retention_days": 180})
    assert response.status_code == 401
    login = client.post("/api/auth/bootstrap", json={"username": "admin", "password": "Admin!23456", "client_label": "tests"})
    assert login.status_code == 201
    token = client.post("/api/auth/login", json={"username": "admin", "password": "Admin!23456", "client_label": "tests"}).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    preview = client.post("/api/network/privacy/retention/preview", json={"retention_days": 180}, headers=headers)
    assert preview.status_code == 200
    runs = client.get("/api/network/privacy/retention/runs", headers=headers)
    assert runs.status_code == 200
    holds = client.get("/api/network/privacy/legal-holds", headers=headers)
    assert holds.status_code == 200
    footprint = client.get("/api/network/privacy/subjects/footprint", params={"subscriber_hash": DUE}, headers=headers)
    assert footprint.status_code == 200
    assert footprint.json()["found"] is False
