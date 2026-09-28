from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.clock import FrozenClock
from app.database import get_connection
from app.network.analytics import NetworkAnalytics
from app.network.retention import RetentionService
from app.network.retention_keys import derive_stat_key, is_stat_key, key_batch

NOW = "2026-09-28T00:00:00Z"
PEPPER = "test-retention-pepper-0000000000000001"


@pytest.fixture()
def clock():
    return FrozenClock(datetime(2026, 9, 28, tzinfo=UTC))


@pytest.fixture()
def seeded(client, clock):
    connection = get_connection()
    now = NOW
    cursor = connection.execute(
        "INSERT INTO network_scenarios(code,name,scene_type,timezone,max_concurrent_sessions,capacity_mbps,created_at,updated_at) "
        "VALUES('gdh-rail','广深高铁','railway','Asia/Shanghai',100,1000,?,?)",
        (now, now),
    )
    scenario_id = cursor.lastrowid
    segment_id = connection.execute(
        "INSERT INTO network_segments(scenario_id,code,name,sequence_no,expected_dwell_seconds,capacity_mbps,created_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (scenario_id, "seg-1", "区段一", 1, 600, 500, now, now),
    ).lastrowid
    app_id = connection.execute(
        "INSERT INTO application_profiles(app_code,name,category,latency_target_ms,packet_loss_target,min_downlink_mbps,min_uplink_mbps,default_priority,created_at,updated_at) "
        "VALUES('video-call','视频通话','video_call',100,0.01,8,4,70,?,?)",
        (now, now),
    ).lastrowid
    policy_id = connection.execute(
        "INSERT INTO policy_versions(scenario_id,version_no,state,rules_json,rules_digest,created_by,published_by,effective_from,created_at,updated_at) "
        "VALUES(?,1,'published','{}','rules-digest-1','tester','tester','2026-01-01T00:00:00Z',?,?)",
        (scenario_id, now, now),
    ).lastrowid

    def add_sample(key, subscriber, observed, *, incident_state=None, severity="major"):
        sample_id = connection.execute(
            "INSERT INTO experience_samples(sample_key,scenario_id,segment_id,app_id,subscriber_hash,device_class,"
            "train_speed_kmh,latency_ms,packet_loss,downlink_mbps,uplink_mbps,observed_at,received_at,payload_digest) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (key, scenario_id, segment_id, app_id, subscriber, "phone", 300, 200, 0.03, 9.0, 4.0, observed, observed, f"digest-{key}"),
        ).lastrowid
        if incident_state:
            connection.execute(
                "INSERT INTO quality_incidents(sample_id,scenario_id,segment_id,app_id,severity,reasons_json,state,opened_at,resolved_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (sample_id, scenario_id, segment_id, app_id, severity, "{}", incident_state, observed,
                 observed if incident_state == "resolved" else None),
            )
        return sample_id

    def add_session(subscriber, sample_id, *, status, ended_at):
        incident_id = connection.execute(
            "SELECT id FROM quality_incidents WHERE sample_id=?", (sample_id,)
        ).fetchone()[0]
        session_id = connection.execute(
            "INSERT INTO acceleration_sessions(incident_id,subscriber_hash,app_id,scenario_id,segment_id,policy_version_id,"
            "status,allocated_downlink_mbps,allocated_uplink_mbps,priority,started_at,expires_at,ended_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (incident_id, subscriber, app_id, scenario_id, segment_id, policy_id, status, 10.0, 4.0, 80,
             "2026-05-01T00:00:00Z", ended_at or "2026-05-01T01:00:00Z", ended_at),
        ).lastrowid
        connection.execute(
            "INSERT INTO capacity_reservations(session_id,scenario_id,segment_id,downlink_mbps,uplink_mbps,state,held_at,released_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (session_id, scenario_id, segment_id, 10.0, 4.0,
             "released" if status != "active" else "held", "2026-05-01T00:00:00Z", ended_at),
        )
        connection.execute(
            "INSERT INTO session_events(session_id,event_type,actor,detail_json,created_at) VALUES(?,?,?,?,?)",
            (session_id, "started", "tester", "{}", "2026-05-01T00:00:00Z"),
        )
        return session_id

    def add_entitlement(order_id, subscriber, *, state, updated_at, valid_until):
        return connection.execute(
            "INSERT INTO subscriber_entitlements(subscriber_hash,scenario_id,product_code,valid_from,valid_until,state,source_order_id,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (subscriber, scenario_id, "boost", "2026-01-01T00:00:00Z", valid_until, state, order_id, updated_at, updated_at),
        ).lastrowid

    # 到期、无争议：样本 2026-08-01（30 天前已到期）
    old_sample = add_sample("sample-old", "subscriber-old-0001", "2026-08-01T00:00:00Z")
    # 未到期：保留
    add_sample("sample-new", "subscriber-new-0001", "2026-09-20T00:00:00Z")
    # 到期但质差争议未关闭：暂缓
    dispute_sample = add_sample("sample-dispute", "subscriber-dispute-0001", "2026-08-01T00:00:00Z", incident_state="open")
    # 到期且已解决事件 + 已完成会话：应去关联（样本与会话到期批次同为 2026-08，统计键一致）
    resolved_sample = add_sample("sample-done", "subscriber-done-0001", "2026-07-15T00:00:00Z", incident_state="resolved")
    add_session("subscriber-done-0001", resolved_sample, status="completed", ended_at="2026-06-01T01:00:00Z")
    # 活动会话：暂缓
    active_sample = add_sample("sample-active", "subscriber-active-0001", "2026-05-01T00:00:00Z", incident_state="accelerating")
    add_session("subscriber-active-0001", active_sample, status="active", ended_at=None)
    # 法律保全旅客
    add_sample("sample-hold", "subscriber-hold-0001", "2026-08-01T00:00:00Z")
    # 同一旅客跨两个到期批次 + 同批跨表
    add_sample("sample-batch-jul", "subscriber-batch-0001", "2026-07-01T00:00:00Z")
    add_sample("sample-batch-aug", "subscriber-batch-0001", "2026-08-01T00:00:00Z")
    add_entitlement("order-batch-1", "subscriber-batch-0001", state="expired",
                    updated_at="2026-01-15T00:00:00Z", valid_until="2026-01-15T00:00:00Z")
    # 活动权益：暂缓
    add_entitlement("order-active-1", "subscriber-ent-active-0001", state="active",
                    updated_at="2026-01-01T00:00:00Z", valid_until="2027-01-01T00:00:00Z")
    # 到期权益（另一批次）
    add_entitlement("order-expired-1", "subscriber-ent-old-0001", state="expired",
                    updated_at="2026-01-01T00:00:00Z", valid_until="2026-02-01T00:00:00Z")

    return {
        "scenario_id": scenario_id,
        "segment_id": segment_id,
        "app_id": app_id,
        "policy_id": policy_id,
        "old_sample": old_sample,
        "dispute_sample": dispute_sample,
    }


def analytics_snapshot():
    analytics = NetworkAnalytics(get_connection())
    return {
        "quality": analytics.quality_overview(),
        "scenarios": analytics.scenario_breakdown(),
        "applications": analytics.application_breakdown(),
        "segments": analytics.segment_breakdown(),
        "severity": analytics.severity_distribution(),
        "capacity": analytics.capacity_snapshot(),
        "outcomes": analytics.acceleration_outcomes(),
    }


def make_service(clock, **kwargs):
    return RetentionService(get_connection(), clock, pepper=PEPPER, **kwargs)


# --------------------------------------------------------------------- 预演

def test_preview_counts_and_changes_nothing(client, seeded, clock):
    before = analytics_snapshot()
    service = make_service(clock)
    report = service.preview(actor="compliance")
    assert report["mode"] == "preview"
    by_category = {item["category"]: item for item in report["tables"]}
    samples = by_category["experience_samples"]
    # 候选=8（7 到期、1 未到期），到期中 2 条争议暂缓，净到期 5 条
    assert samples["candidate_rows"] == 8
    assert samples["within_retention"] == 1
    assert samples["skipped_active_dispute"] == 2
    assert samples["skipped_legal_hold"] == 0
    assert samples["due"] == 5
    sessions = by_category["acceleration_sessions"]
    assert sessions["skipped_active_dispute"] == 1
    entitlements = by_category["subscriber_entitlements"]
    assert entitlements["skipped_active_dispute"] == 1
    assert report["checks"]["aggregate_unchanged"] is True
    # 预演不落任何标识变更
    assert service.locate_identity("subscriber-old-0001")["total_remaining"] == 1
    assert analytics_snapshot() == before
    # 预演任务可重复取回且内容稳定
    again = service.preview(actor="compliance", run_id=report["run_id"])
    assert again["report_digest"] == report["report_digest"]


def test_legal_hold_skips_subscriber_and_global(client, seeded, clock):
    service = make_service(clock)
    service.add_legal_hold({
        "scope": "subscriber", "subscriber_hash": "subscriber-hold-0001",
        "reason": "监管协查 2026-09", "actor": "compliance",
    })
    report = service.preview(actor="compliance")
    samples = next(item for item in report["tables"] if item["category"] == "experience_samples")
    assert samples["skipped_legal_hold"] == 1
    assert samples["due"] == 4
    # 全局保全：所有到期行暂缓
    service.add_legal_hold({"scope": "global", "reason": "全量取证", "actor": "compliance"})
    report = service.preview(actor="compliance", run_id="rr-global-preview")
    assert report["totals"]["due"] == 0
    # 全局保全下所有到期评估行（7 样本 + 完成与活动会话 2 + 3 权益）暂缓
    assert report["totals"]["skipped_legal_hold"] == 12


# --------------------------------------------------------------------- 执行

def test_apply_deidentifies_and_preserves_aggregates(client, seeded, clock):
    before = analytics_snapshot()
    service = make_service(clock)
    report = service.apply(actor="compliance", run_id="rr-apply-1")
    assert report["state"] == "completed"
    assert report["totals"]["transformed"] == 8  # 5 样本 + 1 会话 + 2 到期权益
    assert report["checks"]["residual_due_rows"] == 0
    assert report["checks"]["aggregate_unchanged"] is True
    for table, info in report["checks"]["association_tables"].items():
        assert info["unchanged"] is True, table

    # 身份查询：原始标识在到期数据中消失
    assert service.locate_identity("subscriber-old-0001")["total_remaining"] == 0
    assert service.locate_identity("subscriber-done-0001")["total_remaining"] == 0
    # 未到期 / 暂缓数据仍可按原标识定位
    located = service.locate_identity("subscriber-new-0001")
    assert located["remaining_rows"]["experience_samples"] == 1
    assert service.locate_identity("subscriber-dispute-0001")["total_remaining"] == 1
    assert service.locate_identity("subscriber-active-0001")["total_remaining"] >= 1
    assert service.locate_identity("subscriber-ent-active-0001")["remaining_rows"]["subscriber_entitlements"] == 1

    # 所有聚合报表数值保持不变
    assert analytics_snapshot() == before

    # 容量、质差、策略版本关联仍在，且指向统计键行
    connection = get_connection()
    session = connection.execute(
        "SELECT s.subscriber_hash,s.policy_version_id,r.state AS reservation_state,i.state AS incident_state "
        "FROM acceleration_sessions s JOIN capacity_reservations r ON r.session_id=s.id "
        "JOIN quality_incidents i ON i.id=s.incident_id WHERE s.id IN "
        "(SELECT s2.id FROM acceleration_sessions s2 WHERE s2.subscriber_hash LIKE 'stat:%')"
    ).fetchone()
    assert session is not None
    assert is_stat_key(session["subscriber_hash"])
    assert session["policy_version_id"] == seeded["policy_id"]
    assert session["reservation_state"] == "released"
    assert session["incident_state"] == "resolved"


def test_stat_keys_are_irreversible_and_batch_isolated(client, seeded, clock):
    service = make_service(clock)
    service.apply(actor="compliance", run_id="rr-batch-1")
    connection = get_connection()
    keys = [row[0] for row in connection.execute(
        "SELECT DISTINCT subscriber_hash FROM experience_samples WHERE sample_key IN ('sample-batch-jul','sample-batch-aug') "
        "AND subscriber_hash LIKE 'stat:%' ORDER BY subscriber_hash"
    ).fetchall()]
    assert len(keys) == 2
    assert {key_batch(key) for key in keys} == {"2026-07", "2026-08"}
    # 同旅客跨批键不同
    assert keys[0] != keys[1]
    # 同旅客同批跨表键一致：7 月到期的样本与 1 月 15 日权益（+180 天同为 2026-07 批）
    sample_jul = connection.execute(
        "SELECT subscriber_hash FROM experience_samples WHERE sample_key='sample-batch-jul'"
    ).fetchone()[0]
    entitlement = connection.execute(
        "SELECT subscriber_hash FROM subscriber_entitlements WHERE source_order_id='order-batch-1'"
    ).fetchone()[0]
    assert sample_jul == entitlement
    assert key_batch(sample_jul) == "2026-07"
    # 与直接派生出的键一致（不可逆 HMAC，不含原始标识）
    expected = derive_stat_key(PEPPER, batch_key="2026-07", subscriber_hash="subscriber-batch-0001")
    assert sample_jul == expected
    assert "subscriber-batch-0001" not in sample_jul


def test_apply_is_idempotent(client, seeded, clock):
    service = make_service(clock)
    first = service.apply(actor="compliance", run_id="rr-idem")
    digest_after_first = {t["category"]: t["final_digest"] for t in first["tables"]}
    # 相同 run_id 重放：返回原报告，不再改动
    replay = service.apply(actor="compliance", run_id="rr-idem")
    assert replay["report_digest"] == first["report_digest"]
    # 新任务重跑：没有剩余到期行，转换数为 0，各表摘要与首次执行后完全一致
    second = service.apply(actor="compliance", run_id="rr-idem-2")
    assert second["totals"]["transformed"] == 0
    assert second["checks"]["aggregate_unchanged"] is True
    assert {t["category"]: t["final_digest"] for t in second["tables"]} == digest_after_first


def test_resume_from_checkpoint_after_interruption(client, seeded, clock):
    connection = get_connection()
    calls = {"n": 0}
    original = derive_stat_key

    def flaky_derive(pepper, *, batch_key, subscriber_hash):
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("simulated interruption")
        return original(pepper, batch_key=batch_key, subscriber_hash=subscriber_hash)

    service = RetentionService(connection, clock, pepper=PEPPER, page_size=1, derive_key=flaky_derive)
    with pytest.raises(RuntimeError):
        service.apply(actor="compliance", run_id="rr-resume")
    failed = service.attestation("rr-resume")
    assert failed["state"] == "failed"
    assert "simulated interruption" in failed["error_message"]
    # 失败页回滚，但已提交页与检查点保留
    assert any(value > 0 for value in failed["checkpoint"].values())

    # 用正常服务按同一 run_id 续跑
    resumed = make_service(clock, page_size=2)
    report = resumed.apply(actor="compliance", run_id="rr-resume")
    assert report["state"] == "completed"
    assert report["totals"]["transformed"] == 8
    assert report["checks"]["residual_due_rows"] == 0
    assert report["checks"]["aggregate_unchanged"] is True
    assert resumed.locate_identity("subscriber-old-0001")["total_remaining"] == 0
    # 去关联记录与变更行数一致，且不存在重复映射
    mapping_count = connection.execute(
        "SELECT COUNT(*) FROM retention_records WHERE run_id='rr-resume'"
    ).fetchone()[0]
    assert mapping_count == 8
    assert connection.execute(
        "SELECT COUNT(*) FROM (SELECT table_name,row_id FROM retention_records GROUP BY table_name,row_id HAVING COUNT(*)>1)"
    ).fetchone()[0] == 0


# --------------------------------------------------------------------- 接口

def test_resume_uses_original_cutoff_across_retention_boundary(client, seeded, clock):
    connection = get_connection()
    calls = {"n": 0}
    original = derive_stat_key

    def flaky_derive(pepper, *, batch_key, subscriber_hash):
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("stop")
        return original(pepper, batch_key=batch_key, subscriber_hash=subscriber_hash)

    flaky = RetentionService(connection, clock, pepper=PEPPER, page_size=1, derive_key=flaky_derive)
    with pytest.raises(RuntimeError):
        flaky.apply(actor="compliance", run_id="rr-boundary")

    # 时钟推进 40 天：原本未到期的 sample-new（2026-09-20）此刻已超过 30 天保留期。
    clock.advance(days=40)
    resumed = make_service(clock, page_size=3)
    report = resumed.apply(actor="compliance", run_id="rr-boundary")
    assert report["state"] == "completed"
    # 续跑只处理首次 cutoff 之前到期的 8 行，不卷入新到期数据
    assert report["totals"]["transformed"] == 8
    assert report["policy"]["experience_samples"]["cutoff_at"] == "2026-08-29T00:00:00+00:00"
    # 首跑时尚未到期的样本仍保留原始标识
    assert resumed.locate_identity("subscriber-new-0001")["remaining_rows"]["experience_samples"] == 1


def test_retention_api_endpoints(client, seeded, admin, clock):
    headers = admin["headers"]
    preview = client.post("/api/network/retention/preview", json={"actor": "compliance", "run_id": "rr-api"}, headers=headers)
    assert preview.status_code == 200, preview.text
    assert preview.json()["tables"][0]["candidate_rows"] >= 1

    identity_before = client.get("/api/network/retention/identity", params={"subscriber_hash": "subscriber-old-0001"}, headers=headers)
    assert identity_before.json()["total_remaining"] == 1

    applied = client.post("/api/network/retention/apply", json={"actor": "compliance", "run_id": "rr-api-apply"}, headers=headers)
    assert applied.status_code == 200, applied.text
    assert applied.json()["checks"]["aggregate_unchanged"] is True

    attestation = client.get("/api/network/retention/runs/rr-api-apply/attestation", headers=headers)
    assert attestation.status_code == 200
    body = attestation.json()
    assert body["report_digest"] == applied.json()["report_digest"]
    assert any(table["transformed"] for table in body["tables"])
    assert "skipped_reasons" in body

    identity_after = client.get("/api/network/retention/identity", params={"subscriber_hash": "subscriber-old-0001"}, headers=headers)
    assert identity_after.json()["total_remaining"] == 0

    runs = client.get("/api/network/retention/runs", headers=headers)
    assert runs.status_code == 200
    assert any(item["run_id"] == "rr-api-apply" for item in runs.json()["items"])


def test_retention_requires_permission(client, seeded):
    # 无令牌拒绝
    assert client.post("/api/network/retention/preview", json={"actor": "x"}).status_code == 401
    assert client.get("/api/network/retention/identity", params={"subscriber_hash": "subscriber-old-0001"}).status_code == 401
