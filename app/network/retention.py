"""分级保留与去关联服务。

合规要求：网络体验数据在排障保留期内可以关联到脱敏旅客标识；超过保留期、
且不存在法律保全或活动争议时，将同一脱敏标识替换为不可逆、批次隔离的统计键，
同时保留质差链、容量预留与策略版本等审计关联，聚合统计数值保持不变。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from datetime import timedelta
from typing import Any

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.database import transaction
from app.network.analytics import NetworkAnalytics

DEFAULT_RETENTION_DAYS = 180
STAT_PREFIX = "stat-b"

# 携带脱敏标识、需要替换的表
IDENTITY_TABLES = ("experience_samples", "acceleration_sessions", "subscriber_entitlements")
# 出现在证明报告中的全部业务表
TRACKED_TABLES = IDENTITY_TABLES + (
    "quality_incidents",
    "capacity_reservations",
    "session_events",
    "privacy_legal_holds",
)
# 去除标识列后用于校验“统计数值不变”的投影列；投影哈希执行前后必须一致
PROJECTED_COLUMNS: dict[str, tuple[str, ...]] = {
    "experience_samples": (
        "sample_key", "scenario_id", "segment_id", "app_id", "device_class",
        "train_speed_kmh", "latency_ms", "packet_loss", "downlink_mbps", "uplink_mbps",
        "observed_at", "received_at", "payload_digest",
    ),
    "acceleration_sessions": (
        "incident_id", "app_id", "scenario_id", "segment_id", "policy_version_id",
        "status", "allocated_downlink_mbps", "allocated_uplink_mbps", "priority",
        "started_at", "expires_at", "ended_at", "end_reason", "version",
    ),
    "subscriber_entitlements": (
        "scenario_id", "product_code", "valid_from", "valid_until", "state",
        "source_order_id", "created_at", "updated_at",
    ),
    "session_events": ("session_id", "event_type", "actor", "created_at"),
    "quality_incidents": (
        "sample_id", "scenario_id", "segment_id", "app_id", "severity",
        "reasons_json", "state", "opened_at", "resolved_at", "version",
    ),
    "capacity_reservations": (
        "session_id", "scenario_id", "segment_id", "downlink_mbps", "uplink_mbps",
        "state", "held_at", "released_at",
    ),
    "privacy_legal_holds": (
        "reason", "state", "created_by", "created_at", "released_at", "released_by",
        "release_reason",
    ),
}

SKIP_LEGAL_HOLD = "active_legal_hold"
SKIP_DISPUTE = "active_dispute"
SKIP_RETENTION = "retention_not_reached"
SKIP_REASONS = (SKIP_LEGAL_HOLD, SKIP_DISPUTE, SKIP_RETENTION)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class _RetentionCheckFailure(Exception):
    """批次完成前的哈希校验未通过。"""


def _replace_ref(value: Any, old: str, new: str) -> Any:
    """递归替换 JSON 结构中出现的旧标识字面量，不改变其余内容。"""
    if isinstance(value, str):
        return value.replace(old, new) if old in value else value
    if isinstance(value, dict):
        return {key: _replace_ref(item, old, new) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_ref(item, old, new) for item in value]
    return value


class PrivacyRetentionService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()

    # ------------------------------------------------------------------ 保全标记

    def add_legal_hold(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            existing = connection.execute(
                "SELECT id FROM privacy_legal_holds WHERE subscriber_hash=? AND state='active'",
                (payload["subscriber_hash"],),
            ).fetchone()
            if existing is not None:
                raise ConflictError("该标识已存在生效中的法律保全标记")
            cursor = connection.execute(
                "INSERT INTO privacy_legal_holds(subscriber_hash,reason,created_by,created_at) VALUES(?,?,?,?)",
                (payload["subscriber_hash"], payload["reason"], payload["actor"], now),
            )
            return self._hold(connection, cursor.lastrowid)

    def release_legal_hold(self, hold_id: int, actor: str, reason: str) -> dict[str, Any]:
        with transaction(immediate=True) as connection:
            row = connection.execute("SELECT * FROM privacy_legal_holds WHERE id=?", (hold_id,)).fetchone()
            if row is None:
                raise NotFoundError("法律保全标记不存在")
            if row["state"] != "active":
                return dict(row)
            now = to_storage(self.clock.now())
            connection.execute(
                "UPDATE privacy_legal_holds SET state='released',released_at=?,released_by=?,release_reason=? WHERE id=?",
                (now, actor, reason, hold_id),
            )
            return self._hold(connection, hold_id)

    def list_legal_holds(self, state: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM privacy_legal_holds"
        params: list[Any] = []
        if state:
            sql += " WHERE state=?"
            params.append(state)
        sql += " ORDER BY id"
        return [dict(row) for row in self.connection.execute(sql, params).fetchall()]

    @staticmethod
    def _hold(connection: sqlite3.Connection, hold_id: int) -> dict[str, Any]:
        return dict(connection.execute(
            "SELECT * FROM privacy_legal_holds WHERE id=?", (hold_id,)
        ).fetchone())

    # ------------------------------------------------------------------ 身份足迹

    def subject_footprint(self, subscriber_hash: str) -> dict[str, Any]:
        """按原始脱敏标识查询可关联足迹；去关联完成后应当查不到。"""
        samples = int(self.connection.execute(
            "SELECT COUNT(*) FROM experience_samples WHERE subscriber_hash=?",
            (subscriber_hash,),
        ).fetchone()[0])
        sessions = int(self.connection.execute(
            "SELECT COUNT(*) FROM acceleration_sessions WHERE subscriber_hash=?",
            (subscriber_hash,),
        ).fetchone()[0])
        entitlements = int(self.connection.execute(
            "SELECT COUNT(*) FROM subscriber_entitlements WHERE subscriber_hash=?",
            (subscriber_hash,),
        ).fetchone()[0])
        incidents = int(self.connection.execute(
            "SELECT COUNT(*) FROM quality_incidents i "
            "JOIN experience_samples x ON x.id=i.sample_id WHERE x.subscriber_hash=?",
            (subscriber_hash,),
        ).fetchone()[0])
        holds = int(self.connection.execute(
            "SELECT COUNT(*) FROM privacy_legal_holds WHERE subscriber_hash=? AND state='active'",
            (subscriber_hash,),
        ).fetchone()[0])
        return {
            "subscriber_hash": subscriber_hash,
            "found": any((samples, sessions, entitlements, incidents)),
            "samples": samples,
            "incidents": incidents,
            "sessions": sessions,
            "entitlements": entitlements,
            "active_legal_holds": holds,
        }

    # ------------------------------------------------------------------ 预演

    def preview(self, *, retention_days: int = DEFAULT_RETENTION_DAYS) -> dict[str, Any]:
        retention_days = self._validate_retention(retention_days)
        reference = to_storage(self.clock.now())
        subjects = self._scan_subjects()
        due: list[str] = []
        skipped: dict[str, list[str]] = {reason: [] for reason in SKIP_REASONS}
        skipped_detail: dict[str, dict[str, Any]] = {}
        tables = {table: {"scanned": 0, "updated": 0} for table in TRACKED_TABLES}
        for subject in sorted(subjects):
            eligible, reasons, scanned = self._eligibility(subject, subjects[subject], reference, retention_days)
            if eligible:
                due.append(subject)
                for table, count in scanned.items():
                    tables[table]["scanned"] += count
                    if table in IDENTITY_TABLES:
                        tables[table]["updated"] += count
                # 已解除的保全记录中的标识也会同步替换
                tables["privacy_legal_holds"]["updated"] += int(self.connection.execute(
                    "SELECT COUNT(*) FROM privacy_legal_holds WHERE subscriber_hash=? AND state='released'",
                    (subject,),
                ).fetchone()[0])
            else:
                for reason in reasons["codes"]:
                    skipped[reason].append(subject)
                skipped_detail[subject] = {
                    "retained_categories": reasons["retained_categories"],
                    "active_legal_holds": reasons["legal_holds"],
                    "active_disputes": reasons["disputes"],
                }
        batch_no = self._next_batch_no()
        return {
            "mode": "preview",
            "run_id": None,
            "state": "preview",
            "batch_no": batch_no,
            "reference_time": reference,
            "retention_days": retention_days,
            "subjects_total": len(subjects),
            "due_subjects": len(due),
            "skipped_subjects": len({subject for items in skipped.values() for subject in items}),
            "tables": tables,
            "skipped": [
                {"reason": reason, "count": len(items), "subjects": items[:20],
                 "details": [skipped_detail[subject] for subject in items[:20]]}
                for reason, items in skipped.items() if items
            ],
            "checksums": self._snapshot()["tables"],
            "generated_at": reference,
        }

    # ------------------------------------------------------------------ 执行

    def execute(
        self,
        *,
        actor: str = "retention-job",
        retention_days: int = DEFAULT_RETENTION_DAYS,
        run_id: int | None = None,
        _interrupt_after: int | None = None,
    ) -> dict[str, Any]:
        retention_days = self._validate_retention(retention_days)
        if run_id is None:
            run_id, secret, reference = self._start_run(actor, retention_days)
            resumed = False
        else:
            run_id, secret, reference, retention_days, resumed = self._resume_run(run_id)

        subjects = self._scan_subjects()
        processed_this_pass = 0
        interrupted = False
        try:
            for subject in sorted(subjects):
                if self._checkpoint_exists(run_id, subject, secret):
                    continue
                eligible, reasons, scanned = self._eligibility(subject, subjects[subject], reference, retention_days)
                if eligible:
                    self._deidentify_subject(run_id, subject, run_id, secret, reference, scanned)
                else:
                    self._record_checkpoint(run_id, subject, secret, "skipped", reasons["codes"], scanned, {})
                processed_this_pass += 1
                if _interrupt_after is not None and processed_this_pass >= _interrupt_after:
                    interrupted = True
                    break
        except Exception:
            self._mark_failed(run_id)
            raise
        if interrupted:
            self._mark_failed(run_id)
            raise ConflictError("保留批次在检查点处中断，可使用 run_id 继续", context={"run_id": run_id, "resumable": True})
        return self._finish_run(run_id, resumed=resumed)

    def resume(self, run_id: int) -> dict[str, Any]:
        return self.execute(run_id=run_id)

    def abort_run(self, run_id: int) -> dict[str, Any]:
        """将僵留的运行中批次标记为失败，以便续跑或另开批次。"""
        with transaction(immediate=True) as connection:
            row = connection.execute(
                "SELECT * FROM privacy_retention_runs WHERE id=?", (run_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("保留批次运行不存在")
            if row["state"] == "completed":
                raise ConflictError("已完成批次不能中止")
            connection.execute(
                "UPDATE privacy_retention_runs SET state='failed',failure_message='aborted',updated_at=? WHERE id=?",
                (to_storage(self.clock.now()), run_id),
            )
        return self.report(run_id)

    # ------------------------------------------------------------------ 报告

    def report(self, run_id: int) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM privacy_retention_runs WHERE id=?", (run_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("保留批次运行不存在")
        if row["state"] == "completed" and row["report_json"]:
            report = json.loads(row["report_json"])
            report["verification"] = self._verification_summary(report)
            return report
        checkpoints = int(self.connection.execute(
            "SELECT COUNT(*) FROM privacy_retention_checkpoints WHERE run_id=?", (run_id,)
        ).fetchone()[0])
        return {
            "mode": "execute",
            "run_id": run_id,
            "state": row["state"],
            "failure_message": row["failure_message"],
            "processed_checkpoints": checkpoints,
            "resumable": row["state"] in ("running", "failed"),
        }

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT id,state,started_by,started_at,completed_at,failure_message "
            "FROM privacy_retention_runs ORDER BY id DESC LIMIT ?",
            (min(max(limit, 1), 200),),
        ).fetchall()
        result = [dict(row) for row in rows]
        for item in result:
            item["resumable"] = item["state"] in ("running", "failed")
        return result

    # ------------------------------------------------------------------ 批次内部

    def _next_batch_no(self) -> int:
        return int(self.connection.execute(
            "SELECT COALESCE(MAX(id),0)+1 FROM privacy_retention_runs"
        ).fetchone()[0])

    def _start_run(self, actor: str, retention_days: int) -> tuple[int, bytes, str]:
        now = to_storage(self.clock.now())
        params = {"retention_days": retention_days, "reference_time": now}
        secret = secrets.token_bytes(32)
        with transaction(immediate=True) as connection:
            running = connection.execute(
                "SELECT id FROM privacy_retention_runs WHERE state='running' ORDER BY id LIMIT 1"
            ).fetchone()
            if running is not None:
                raise ConflictError("已有运行中的保留批次，请等待完成或查看检查点", context={"run_id": running["id"]})
            cursor = connection.execute(
                "INSERT INTO privacy_retention_runs(state,params_json,batch_secret,started_by,started_at,updated_at) "
                "VALUES('running',?,?,?,?,?)",
                (_canonical_json(params), secret.hex(), actor, now, now),
            )
            run_id = cursor.lastrowid
            baseline = self._snapshot(connection)
            connection.execute(
                "UPDATE privacy_retention_runs SET baseline_json=? WHERE id=?",
                (_canonical_json(baseline), run_id),
            )
        return run_id, secret, now

    def _resume_run(self, run_id: int) -> tuple[int, bytes, str, int, bool]:
        row = self.connection.execute(
            "SELECT * FROM privacy_retention_runs WHERE id=?", (run_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("保留批次运行不存在")
        if row["state"] not in ("running", "failed"):
            raise ConflictError("只有中断或运行中的批次可以继续")
        if not row["batch_secret"]:
            raise ConflictError("批次密钥不可用，无法继续")
        params = json.loads(row["params_json"])
        if not row["baseline_json"]:
            raise ConflictError("批次基线快照缺失，无法继续")
        return (
            run_id,
            bytes.fromhex(row["batch_secret"]),
            params["reference_time"],
            int(params["retention_days"]),
            True,
        )

    def _mark_failed(self, run_id: int) -> None:
        with transaction(immediate=True) as connection:
            connection.execute(
                "UPDATE privacy_retention_runs SET state='failed',failure_message='interrupted_at_checkpoint',"
                "updated_at=? WHERE id=? AND state<>'completed'",
                (to_storage(self.clock.now()), run_id),
            )

    def _finish_run(self, run_id: int, *, resumed: bool) -> dict[str, Any]:
        try:
            with transaction(immediate=True) as connection:
                row = connection.execute(
                    "SELECT * FROM privacy_retention_runs WHERE id=?", (run_id,)
                ).fetchone()
                params = json.loads(row["params_json"])
                baseline = json.loads(row["baseline_json"])
                after = self._snapshot(connection)

                # 校验一：去除标识列后的行投影哈希不变 -> 容量/质差/策略关联与数值均未被改动
                if baseline["projected"] != after["projected"]:
                    raise _RetentionCheckFailure("projected_checksum_mismatch")
                # 校验二：聚合报表数值不变
                if baseline["aggregates"] != after["aggregates"]:
                    raise _RetentionCheckFailure("aggregate_mismatch")

                tables, skipped, deidentified, skipped_subjects = self._aggregate_checkpoints(connection, run_id)
                completed_at = to_storage(self.clock.now())
                report = {
                    "mode": "execute",
                    "run_id": run_id,
                    "state": "completed",
                    "batch_no": run_id,
                    "reference_time": params["reference_time"],
                    "retention_days": int(params["retention_days"]),
                    "started_at": row["started_at"],
                    "completed_at": completed_at,
                    "resumed_from_checkpoint": bool(resumed and row["failure_message"]),
                    "processed_subjects": deidentified,
                    "skipped_subjects": skipped_subjects,
                    "skipped": skipped,
                    "tables": tables,
                    "checksums": {"before": baseline["tables"], "after": after["tables"]},
                    "projected_checksums": {"before": baseline["projected"], "after": after["projected"]},
                    "aggregates": {"before": baseline["aggregates"], "after": after["aggregates"]},
                    "stat_key_prefix": f"{STAT_PREFIX}{run_id:06d}-",
                }
                report["verification"] = self._verification_summary(report)
                connection.execute(
                    "UPDATE privacy_retention_runs SET state='completed',report_json=?,failure_message='',"
                    "batch_secret='',completed_at=?,updated_at=? WHERE id=?",
                    (_canonical_json(report), completed_at, completed_at, run_id),
                )
                # 检查点仅用于断点续跑；完成后清除，库内不再保留旧标识到统计键的任何线索
                connection.execute("DELETE FROM privacy_retention_checkpoints WHERE run_id=?", (run_id,))
                return report
        except _RetentionCheckFailure as failure:
            with transaction(immediate=True) as connection:
                connection.execute(
                    "UPDATE privacy_retention_runs SET state='failed',failure_message=?,updated_at=? WHERE id=?",
                    (str(failure), to_storage(self.clock.now()), run_id),
                )
            raise ConflictError(f"去关联校验失败：{failure}") from failure

    @staticmethod
    def _verification_summary(report: dict[str, Any]) -> dict[str, Any]:
        return {
            "projected_hashes_match": report["projected_checksums"]["before"] == report["projected_checksums"]["after"],
            "aggregates_match": report["aggregates"]["before"] == report["aggregates"]["after"],
            "identity_columns_replaced": all(
                report["tables"][table]["updated"] == report["tables"][table]["scanned"]
                for table in IDENTITY_TABLES
            ),
            "audit_links_preserved": (
                report["tables"]["quality_incidents"]["updated"] == 0
                and report["tables"]["capacity_reservations"]["updated"] == 0
            ),
        }

    def _aggregate_checkpoints(
        self, connection: sqlite3.Connection, run_id: int
    ) -> tuple[dict[str, dict[str, int]], list[dict[str, Any]], int, int]:
        tables = {table: {"scanned": 0, "updated": 0} for table in TRACKED_TABLES}
        skip_counts = {reason: 0 for reason in SKIP_REASONS}
        deidentified = 0
        skipped_subjects = 0
        rows = connection.execute(
            "SELECT decision,reasons_json,table_counts_json FROM privacy_retention_checkpoints WHERE run_id=?",
            (run_id,),
        ).fetchall()
        for row in rows:
            counts = json.loads(row["table_counts_json"] or "{}")
            if row["decision"] == "deidentified":
                deidentified += 1
                for table in TRACKED_TABLES:
                    tables[table]["scanned"] += int(counts.get("scanned", {}).get(table, 0))
                    tables[table]["updated"] += int(counts.get("updated", {}).get(table, 0))
            else:
                skipped_subjects += 1
                for reason in json.loads(row["reasons_json"] or "[]"):
                    if reason in skip_counts:
                        skip_counts[reason] += 1
        skipped = [{"reason": reason, "count": count} for reason, count in skip_counts.items() if count]
        return tables, skipped, deidentified, skipped_subjects

    # ------------------------------------------------------------------ 单主体处理

    def _deidentify_subject(
        self,
        run_id: int,
        subject: str,
        batch_no: int,
        batch_secret: bytes,
        reference: str,
        scanned: dict[str, int],
    ) -> None:
        stat_key = self.stat_key(subject, batch_no, batch_secret)
        digest = self.subject_digest(subject, batch_secret)
        with transaction(immediate=True) as connection:
            updated: dict[str, int] = {}
            for table in IDENTITY_TABLES:
                cursor = connection.execute(
                    f"UPDATE {table} SET subscriber_hash=? WHERE subscriber_hash=?",
                    (stat_key, subject),
                )
                updated[table] = cursor.rowcount
            # 已解除的保全记录仅作历史留存，同样去标识；生效中的保全在资格判定阶段即整体暂缓
            updated["privacy_legal_holds"] = connection.execute(
                "UPDATE privacy_legal_holds SET subscriber_hash=? WHERE subscriber_hash=? AND state='released'",
                (stat_key, subject),
            ).rowcount
            # 会话事件 JSON 中可能记录了标识字面量，同步替换；事件结构与其余字段不变
            events_updated = 0
            event_rows = connection.execute(
                "SELECT e.id,e.detail_json FROM session_events e "
                "JOIN acceleration_sessions s ON s.id=e.session_id WHERE s.subscriber_hash=?",
                (stat_key,),
            ).fetchall()
            for event in event_rows:
                detail = json.loads(event["detail_json"] or "{}")
                cleaned = _replace_ref(detail, subject, stat_key)
                if cleaned != detail:
                    connection.execute(
                        "UPDATE session_events SET detail_json=? WHERE id=?",
                        (json.dumps(cleaned, ensure_ascii=False, sort_keys=True), event["id"]),
                    )
                    events_updated += 1
            updated["session_events"] = events_updated
            updated["quality_incidents"] = 0
            updated["capacity_reservations"] = 0
            payload = {"scanned": scanned, "updated": updated}
            connection.execute(
                "INSERT INTO privacy_retention_checkpoints"
                "(run_id,subject_digest,decision,reasons_json,table_counts_json,processed_at) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(run_id,subject_digest) DO UPDATE SET "
                "decision=excluded.decision,reasons_json=excluded.reasons_json,"
                "table_counts_json=excluded.table_counts_json,processed_at=excluded.processed_at",
                (run_id, digest, "deidentified", "[]", _canonical_json(payload), reference),
            )

    def _record_checkpoint(
        self,
        run_id: int,
        subject: str,
        batch_secret: bytes,
        decision: str,
        reasons: list[str],
        scanned: dict[str, int],
        updated: dict[str, int],
    ) -> None:
        # 检查点只存批次密钥域下的不可逆摘要，不保存原始标识
        digest = self.subject_digest(subject, batch_secret)
        payload = {"scanned": scanned, "updated": updated}
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            connection.execute(
                "INSERT INTO privacy_retention_checkpoints"
                "(run_id,subject_digest,decision,reasons_json,table_counts_json,processed_at) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(run_id,subject_digest) DO UPDATE SET "
                "decision=excluded.decision,reasons_json=excluded.reasons_json,"
                "table_counts_json=excluded.table_counts_json,processed_at=excluded.processed_at",
                (run_id, digest, decision, _canonical_json(reasons), _canonical_json(payload), now),
            )

    def _checkpoint_exists(self, run_id: int, subject: str, batch_secret: bytes) -> bool:
        digest = self.subject_digest(subject, batch_secret)
        return self.connection.execute(
            "SELECT 1 FROM privacy_retention_checkpoints WHERE run_id=? AND subject_digest=?",
            (run_id, digest),
        ).fetchone() is not None

    @staticmethod
    def stat_key(subscriber_hash: str, batch_no: int, batch_secret: bytes) -> str:
        # HMAC 不可逆；每个批次独立随机密钥实现批次隔离，跨批次/跨库不可链接
        digest = hmac.new(
            batch_secret, b"stat-key\x00" + subscriber_hash.encode("utf-8"), hashlib.sha256
        ).hexdigest()[:32]
        return f"{STAT_PREFIX}{batch_no:06d}-{digest}"

    @staticmethod
    def subject_digest(subscriber_hash: str, batch_secret: bytes) -> str:
        return hmac.new(
            batch_secret, b"checkpoint\x00" + subscriber_hash.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    # ------------------------------------------------------------------ 扫描与判定

    def _scan_subjects(self) -> dict[str, dict[str, Any]]:
        """聚合样本、会话、权益中出现的全部原始标识；已是统计键的行不再处理（幂等）。"""
        subjects: dict[str, dict[str, Any]] = {}

        def ensure(ref: str) -> dict[str, Any]:
            info = subjects.setdefault(
                ref,
                {"samples": 0, "sessions": 0, "entitlements": 0,
                 "sample_latest": None, "session_latest": None, "entitlement_latest": None},
            )
            return info

        sample_rows = self.connection.execute(
            "SELECT subscriber_hash,COUNT(*),MAX(observed_at) FROM experience_samples "
            "WHERE subscriber_hash NOT LIKE ? GROUP BY subscriber_hash",
            (f"{STAT_PREFIX}%",),
        ).fetchall()
        for ref, count, latest in sample_rows:
            info = ensure(ref)
            info["samples"] = int(count)
            info["sample_latest"] = latest
        session_rows = self.connection.execute(
            "SELECT subscriber_hash,COUNT(*),MAX(started_at) FROM acceleration_sessions "
            "WHERE subscriber_hash NOT LIKE ? GROUP BY subscriber_hash",
            (f"{STAT_PREFIX}%",),
        ).fetchall()
        for ref, count, latest in session_rows:
            info = ensure(ref)
            info["sessions"] = int(count)
            info["session_latest"] = latest
        entitlement_rows = self.connection.execute(
            "SELECT subscriber_hash,COUNT(*),MAX(valid_until) FROM subscriber_entitlements "
            "WHERE subscriber_hash NOT LIKE ? GROUP BY subscriber_hash",
            (f"{STAT_PREFIX}%",),
        ).fetchall()
        for ref, count, latest in entitlement_rows:
            info = ensure(ref)
            info["entitlements"] = int(count)
            info["entitlement_latest"] = latest
        return subjects

    def _eligibility(
        self, subject: str, info: dict[str, Any], reference: str, retention_days: int
    ) -> tuple[bool, dict[str, Any], dict[str, int]]:
        codes: list[str] = []
        holds = int(self.connection.execute(
            "SELECT COUNT(*) FROM privacy_legal_holds WHERE subscriber_hash=? AND state='active'",
            (subject,),
        ).fetchone()[0])
        if holds:
            codes.append(SKIP_LEGAL_HOLD)
        dispute_rows = self.connection.execute(
            "SELECT i.state,COUNT(*) FROM quality_incidents i "
            "JOIN experience_samples x ON x.id=i.sample_id "
            "WHERE x.subscriber_hash=? AND i.state IN ('open','accelerating') GROUP BY i.state",
            (subject,),
        ).fetchall()
        if dispute_rows:
            codes.append(SKIP_DISPUTE)

        # 按数据类别分级计算到期：样本看观测时间、会话看发起时间、权益看有效期截止
        reference_dt = from_storage(reference)
        category_latest = {
            "samples": (info["samples"], info["sample_latest"]),
            "sessions": (info["sessions"], info["session_latest"]),
            "entitlements": (info["entitlements"], info["entitlement_latest"]),
        }
        not_due: list[str] = []
        for category, (count, latest) in category_latest.items():
            if count and (latest is None or from_storage(latest) + timedelta(days=retention_days) > reference_dt):
                not_due.append(category)
        if not_due:
            codes.append(SKIP_RETENTION)

        scanned = self._subject_row_counts(subject)
        reasons = {
            "codes": codes,
            "legal_holds": holds,
            "disputes": {row[0]: int(row[1]) for row in dispute_rows},
            "retained_categories": not_due,
        }
        return not codes, reasons, scanned

    def _subject_row_counts(self, subject: str) -> dict[str, int]:
        return {
            "experience_samples": int(self.connection.execute(
                "SELECT COUNT(*) FROM experience_samples WHERE subscriber_hash=?", (subject,)).fetchone()[0]),
            "acceleration_sessions": int(self.connection.execute(
                "SELECT COUNT(*) FROM acceleration_sessions WHERE subscriber_hash=?", (subject,)).fetchone()[0]),
            "subscriber_entitlements": int(self.connection.execute(
                "SELECT COUNT(*) FROM subscriber_entitlements WHERE subscriber_hash=?", (subject,)).fetchone()[0]),
            "quality_incidents": int(self.connection.execute(
                "SELECT COUNT(*) FROM quality_incidents i JOIN experience_samples x ON x.id=i.sample_id "
                "WHERE x.subscriber_hash=?", (subject,)).fetchone()[0]),
            "session_events": int(self.connection.execute(
                "SELECT COUNT(*) FROM session_events e JOIN acceleration_sessions s ON s.id=e.session_id "
                "WHERE s.subscriber_hash=?", (subject,)).fetchone()[0]),
            "capacity_reservations": int(self.connection.execute(
                "SELECT COUNT(*) FROM capacity_reservations r JOIN acceleration_sessions s ON s.id=r.session_id "
                "WHERE s.subscriber_hash=?", (subject,)).fetchone()[0]),
            "privacy_legal_holds": int(self.connection.execute(
                "SELECT COUNT(*) FROM privacy_legal_holds WHERE subscriber_hash=?",
                (subject,)).fetchone()[0]),
        }

    # ------------------------------------------------------------------ 校验快照

    def _snapshot(self, connection: sqlite3.Connection | None = None) -> dict[str, Any]:
        connection = connection or self.connection
        table_hashes: dict[str, str] = {}
        projected: dict[str, str] = {}
        for table in TRACKED_TABLES:
            rows = [dict(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()]
            table_hashes[table] = hashlib.sha256(_canonical_json(rows).encode()).hexdigest()
            columns = ", ".join(PROJECTED_COLUMNS[table])
            projected_rows = [dict(row) for row in connection.execute(
                f"SELECT {columns} FROM {table} ORDER BY id"
            ).fetchall()]
            projected[table] = hashlib.sha256(_canonical_json(projected_rows).encode()).hexdigest()
        analytics = NetworkAnalytics(connection)
        aggregates = {
            "quality_overview": analytics.quality_overview(),
            "scenario_breakdown": analytics.scenario_breakdown(),
            "application_breakdown": analytics.application_breakdown(),
            "severity_distribution": analytics.severity_distribution(),
            "capacity_snapshot": analytics.capacity_snapshot(),
            "acceleration_outcomes": analytics.acceleration_outcomes(),
        }
        return {"tables": table_hashes, "projected": projected, "aggregates": aggregates}

    @staticmethod
    def _validate_retention(retention_days: int) -> int:
        if not isinstance(retention_days, int) or not 1 <= retention_days <= 3650:
            raise ValidationError("排障保留天数必须在 1 到 3650 之间")
        return retention_days
