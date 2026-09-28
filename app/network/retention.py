"""分级保留与去关联服务。

合规要求：网络体验数据只在排障期限内保留可关联用户的标识；超过期限后数据仍可用于
场景与应用统计，但不能还原到单个旅客。

处理方式：
- 按数据类别配置保留天数，依据每行锚点时间（观测时间/会话结束时间/权益更新时间）计算到期批次；
- 到期且不在法律保全或活动争议状态的行，将 subscriber_hash 替换为不可逆、批次隔离的统计键；
- 只替换标识列，样本/事件/会话/权益/容量之间的外键与容量、质差、策略版本关联全部保留；
- 活动争议（未关闭质差事件、活动会话、未失效权益）与法律保全命中的行暂缓，留给后续任务；
- 执行过程按页提交检查点，中断后凭 run_id 从检查点继续；重复执行不会再次改动已去关联的行。
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable

from app.core.clock import Clock, SystemClock, from_storage, to_storage
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.database import transaction
from app.network.retention_keys import STAT_KEY_VERSION, derive_stat_key, generate_pepper, pepper_identifier
from app.network.schema import ensure_network_schema

PAGE_SIZE = 500
MIN_RETENTION_DAYS = 1
MAX_RETENTION_DAYS = 3650
KEYRING_NAME = f"stat-{STAT_KEY_VERSION}"
STAT_PREFIX = "stat:"


@dataclass(frozen=True, slots=True)
class CategoryPolicy:
    category: str
    label: str
    table: str
    retain_days: int
    anchor_column: str

    def cutoff(self, now: datetime) -> str:
        return to_storage(now - timedelta(days=self.retain_days))


CATEGORY_ORDER = ("experience_samples", "acceleration_sessions", "subscriber_entitlements")

CATEGORY_POLICIES = {
    "experience_samples": CategoryPolicy("experience_samples", "体验样本", "experience_samples", 30, "observed_at"),
    "acceleration_sessions": CategoryPolicy("acceleration_sessions", "加速会话", "acceleration_sessions", 90, "ended_at"),
    "subscriber_entitlements": CategoryPolicy("subscriber_entitlements", "用户权益", "subscriber_entitlements", 180, "updated_at"),
}

# 证明报告中参与哈希的稳定列。
TABLE_COLUMNS: dict[str, list[str]] = {
    "experience_samples": [
        "id", "sample_key", "scenario_id", "segment_id", "app_id", "subscriber_hash", "device_class",
        "train_speed_kmh", "latency_ms", "packet_loss", "downlink_mbps", "uplink_mbps",
        "observed_at", "received_at", "payload_digest",
    ],
    "acceleration_sessions": [
        "id", "incident_id", "subscriber_hash", "app_id", "scenario_id", "segment_id", "policy_version_id",
        "status", "allocated_downlink_mbps", "allocated_uplink_mbps", "priority",
        "started_at", "expires_at", "ended_at", "end_reason", "version",
    ],
    "subscriber_entitlements": [
        "id", "subscriber_hash", "scenario_id", "product_code", "valid_from", "valid_until",
        "state", "source_order_id", "created_at", "updated_at",
    ],
    "quality_incidents": [
        "id", "sample_id", "scenario_id", "segment_id", "app_id", "severity", "reasons_json",
        "state", "opened_at", "resolved_at", "version",
    ],
    "capacity_reservations": [
        "id", "session_id", "scenario_id", "segment_id", "downlink_mbps", "uplink_mbps",
        "state", "held_at", "released_at",
    ],
    "policy_versions": [
        "id", "scenario_id", "version_no", "state", "rules_json", "rules_digest",
        "created_by", "published_by", "effective_from", "retired_at", "created_at", "updated_at",
    ],
}
TRANSFORMED_TABLES = ("experience_samples", "acceleration_sessions", "subscriber_entitlements")
ASSOCIATION_TABLES = ("quality_incidents", "capacity_reservations", "policy_versions")


def batch_for(anchor_at: str, retain_days: int) -> str:
    """按锚点时间 + 保留天数得到到期月份批次（UTC）。"""
    anchor = from_storage(anchor_at)
    if anchor is None:
        raise ValidationError("锚点时间为空，无法计算到期批次")
    return (anchor + timedelta(days=retain_days)).strftime("%Y-%m")


def new_run_id() -> str:
    stamp = to_storage(SystemClock().now()).replace(":", "").replace("-", "").replace("+00:00", "Z")
    return f"rr-{stamp}-{secrets.token_hex(4)}"


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


class RetentionService:
    def __init__(
        self,
        connection: sqlite3.Connection,
        clock: Clock | None = None,
        *,
        pepper: str | None = None,
        page_size: int = PAGE_SIZE,
        derive_key: Callable[..., str] = derive_stat_key,
    ) -> None:
        self.connection = connection
        ensure_network_schema(self.connection)
        self.clock = clock or SystemClock()
        self.page_size = page_size
        self._pepper_override = pepper
        self._derive_key = derive_key

    # ------------------------------------------------------------------ 策略

    def _policies(self, overrides: dict[str, int] | None) -> dict[str, CategoryPolicy]:
        result: dict[str, CategoryPolicy] = {}
        for key in CATEGORY_ORDER:
            base = CATEGORY_POLICIES[key]
            days = base.retain_days
            if overrides and key in overrides:
                days = int(overrides[key])
                if not MIN_RETENTION_DAYS <= days <= MAX_RETENTION_DAYS:
                    raise ValidationError(f"{key} 保留天数必须在 {MIN_RETENTION_DAYS} 到 {MAX_RETENTION_DAYS} 之间")
            result[key] = CategoryPolicy(key, base.label, base.table, days, base.anchor_column)
        return result

    @staticmethod
    def _policy_view(policies: dict[str, CategoryPolicy], now: datetime) -> dict[str, Any]:
        return {
            key: {
                "label": policy.label,
                "table": policy.table,
                "retain_days": policy.retain_days,
                "anchor_column": policy.anchor_column,
                "cutoff_at": policy.cutoff(now),
            }
            for key, policy in policies.items()
        }

    # ------------------------------------------------------------------ 钥匙

    def resolve_pepper(self) -> str:
        """优先使用显式注入或 NETWORK_RETENTION_PEPPER；否则在库内初始化并持久化一个随机 pepper。"""
        if self._pepper_override:
            return self._pepper_override
        env_pepper = os.getenv("NETWORK_RETENTION_PEPPER")
        if env_pepper:
            return env_pepper
        row = self.connection.execute("SELECT pepper FROM retention_keyring WHERE name=?", (KEYRING_NAME,)).fetchone()
        if row is not None:
            return str(row["pepper"])
        pepper = generate_pepper()
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            connection.execute(
                "INSERT INTO retention_keyring(name,pepper,created_at) VALUES(?,?,?) ON CONFLICT(name) DO NOTHING",
                (KEYRING_NAME, pepper, now),
            )
            row = connection.execute("SELECT pepper FROM retention_keyring WHERE name=?", (KEYRING_NAME,)).fetchone()
        return str(row["pepper"])

    def stat_key(self, pepper: str, batch_key: str, subscriber_hash: str) -> str:
        return self._derive_key(pepper, batch_key=batch_key, subscriber_hash=subscriber_hash)

    # ------------------------------------------------------------------ 保全

    def add_legal_hold(self, payload: dict[str, Any]) -> dict[str, Any]:
        scope = payload.get("scope", "subscriber")
        if scope not in {"subscriber", "global"}:
            raise ValidationError("保全范围只能是 subscriber 或 global")
        subscriber_hash = (payload.get("subscriber_hash") or "").strip() or None
        if scope == "subscriber" and not subscriber_hash:
            raise ValidationError("旅客级保全必须提供脱敏用户标识")
        reason = (payload.get("reason") or "").strip()
        if len(reason) < 2:
            raise ValidationError("必须提供保全原因")
        expires_at = None
        if payload.get("expires_at"):
            try:
                expires_at = to_storage(from_storage(payload["expires_at"]))
            except (TypeError, ValueError) as exc:
                raise ValidationError("保全到期时间格式不正确") from exc
        actor = (payload.get("actor") or "compliance").strip() or "compliance"
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            if scope == "global":
                existing = connection.execute(
                    "SELECT id FROM retention_legal_holds WHERE state='active' AND scope='global'"
                ).fetchone()
            else:
                existing = connection.execute(
                    "SELECT id FROM retention_legal_holds WHERE state='active' AND scope='subscriber' AND subscriber_hash=?",
                    (subscriber_hash,),
                ).fetchone()
            if existing is not None:
                raise ConflictError("已存在生效中的相同法律保全")
            cursor = connection.execute(
                "INSERT INTO retention_legal_holds(scope,subscriber_hash,reason,state,created_by,created_at,expires_at) "
                "VALUES(?,?,?,'active',?,?,?)",
                (scope, subscriber_hash, reason, actor, now, expires_at),
            )
            return dict(connection.execute("SELECT * FROM retention_legal_holds WHERE id=?", (cursor.lastrowid,)).fetchone())

    def release_legal_hold(self, hold_id: int) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM retention_legal_holds WHERE id=?", (hold_id,)).fetchone()
        if row is None:
            raise NotFoundError("法律保全记录不存在")
        if row["state"] != "active":
            return dict(row)
        now = to_storage(self.clock.now())
        with transaction(immediate=True) as connection:
            connection.execute("UPDATE retention_legal_holds SET state='released',released_at=? WHERE id=?", (now, hold_id))
            return dict(connection.execute("SELECT * FROM retention_legal_holds WHERE id=?", (hold_id,)).fetchone())

    def list_legal_holds(self, *, active_only: bool = True) -> list[dict[str, Any]]:
        sql = "SELECT * FROM retention_legal_holds"
        if active_only:
            sql += " WHERE state='active'"
        return [dict(row) for row in self.connection.execute(sql + " ORDER BY id DESC").fetchall()]

    def _refresh_hold_table(self, now: str) -> bool:
        """在当前连接上重建旅客级保全临时表，返回是否存在生效的全局保全。"""
        self.connection.execute("DROP TABLE IF EXISTS temp._retention_holds")
        self.connection.execute("CREATE TEMP TABLE _retention_holds(subscriber_hash TEXT PRIMARY KEY)")
        rows = self.connection.execute(
            "SELECT DISTINCT subscriber_hash FROM retention_legal_holds "
            "WHERE state='active' AND scope='subscriber' AND subscriber_hash IS NOT NULL "
            "AND (expires_at IS NULL OR expires_at>?)",
            (now,),
        ).fetchall()
        self.connection.executemany(
            "INSERT OR IGNORE INTO _retention_holds(subscriber_hash) VALUES(?)",
            [(row["subscriber_hash"],) for row in rows],
        )
        global_hold = self.connection.execute(
            "SELECT 1 FROM retention_legal_holds WHERE state='active' AND scope='global' "
            "AND (expires_at IS NULL OR expires_at>?) LIMIT 1",
            (now,),
        ).fetchone()
        return global_hold is not None

    # ----------------------------------------------------------- 候选与分批

    @staticmethod
    def _conditions(policy: CategoryPolicy) -> tuple[str, str, str]:
        """返回 (锚点有效, 到期, 活动争议) SQL 片段，均引用别名 s 与参数 ?(cutoff)。"""
        if policy.table == "experience_samples":
            anchor_valid = "1=1"
            due = f"s.{policy.anchor_column}<=?"
            dispute = (
                "EXISTS (SELECT 1 FROM quality_incidents qi WHERE qi.sample_id=s.id "
                "AND qi.state IN ('open','accelerating'))"
            )
        elif policy.table == "acceleration_sessions":
            # 活动会话没有结束时间，但属于活动争议：到期评估包含它们，再由争议条件暂缓；
            # 取页时 NOT(争议) 会排除，所以活动行绝不会被去标识。
            anchor_valid = "1=1"
            due = "(s.ended_at IS NULL OR s.ended_at<=?)"
            dispute = (
                "s.status='active' OR EXISTS (SELECT 1 FROM quality_incidents qi WHERE qi.id=s.incident_id "
                "AND qi.state IN ('open','accelerating'))"
            )
        else:
            anchor_valid = "1=1"
            due = f"s.{policy.anchor_column}<=?"
            dispute = "s.state IN ('active','suspended')"
        return anchor_valid, due, dispute

    def _plan_category(self, policy: CategoryPolicy, cutoff: str, global_hold: bool) -> dict[str, Any]:
        anchor_valid, due, dispute = self._conditions(policy)
        held = "(?=1 OR h.subscriber_hash IS NOT NULL)"
        row = self.connection.execute(
            f"""
            SELECT
              COUNT(*) AS total,
              COALESCE(SUM(CASE WHEN ({anchor_valid}) AND ({due}) AND {held} THEN 1 ELSE 0 END),0) AS legal_hold,
              COALESCE(SUM(CASE WHEN ({anchor_valid}) AND ({due}) AND NOT {held} AND ({dispute}) THEN 1 ELSE 0 END),0) AS dispute,
              COALESCE(SUM(CASE WHEN ({anchor_valid}) AND ({due}) AND NOT {held} AND NOT ({dispute}) THEN 1 ELSE 0 END),0) AS due_rows,
              COALESCE(SUM(CASE WHEN NOT (({anchor_valid}) AND ({due})) THEN 1 ELSE 0 END),0) AS within_retention
            FROM {policy.table} s
            LEFT JOIN _retention_holds h ON h.subscriber_hash=s.subscriber_hash
            WHERE s.subscriber_hash NOT LIKE 'stat:%'
            """,
            (cutoff, 1 if global_hold else 0, cutoff, 1 if global_hold else 0,
             cutoff, 1 if global_hold else 0, cutoff),
        ).fetchone()
        return {
            "category": policy.category,
            "label": policy.label,
            "table": policy.table,
            "anchor_column": policy.anchor_column,
            "retain_days": policy.retain_days,
            "cutoff_at": cutoff,
            "candidate_rows": int(row["total"]),
            "within_retention": int(row["within_retention"]),
            "skipped_legal_hold": int(row["legal_hold"]),
            "skipped_active_dispute": int(row["dispute"]),
            "due": int(row["due_rows"]),
        }

    def _due_page(self, policy: CategoryPolicy, cutoff: str, after_id: int, limit: int, global_hold: bool) -> list[sqlite3.Row]:
        anchor_valid, due, dispute = self._conditions(policy)
        return self.connection.execute(
            f"""
            SELECT s.id,s.subscriber_hash,s.{policy.anchor_column} AS anchor_at
            FROM {policy.table} s
            LEFT JOIN _retention_holds h ON h.subscriber_hash=s.subscriber_hash
            WHERE s.subscriber_hash NOT LIKE 'stat:%' AND s.id>?
              AND ({anchor_valid}) AND ({due})
              AND ?=0 AND h.subscriber_hash IS NULL
              AND NOT ({dispute})
            ORDER BY s.id LIMIT ?
            """,
            (after_id, cutoff, 1 if global_hold else 0, limit),
        ).fetchall()

    # ------------------------------------------------------------- 哈希与校验

    def _table_digest(self, table: str) -> str:
        columns = TABLE_COLUMNS[table]
        hasher = hashlib.sha256()
        for row in self.connection.execute(f"SELECT {','.join(columns)} FROM {table} ORDER BY id"):
            hasher.update(_json(tuple(row)).encode())
            hasher.update(b"\n")
        return hasher.hexdigest()

    def _all_digests(self) -> dict[str, str]:
        return {table: self._table_digest(table) for table in TABLE_COLUMNS}

    def _mapping_digest(self, run_id: str, category: str) -> str:
        hasher = hashlib.sha256()
        rows = self.connection.execute(
            "SELECT table_name,row_id,batch_key,stat_key FROM retention_records WHERE run_id=? AND category=? ORDER BY id",
            (run_id, category),
        ).fetchall()
        for row in rows:
            hasher.update("|".join((row["table_name"], str(row["row_id"]), row["batch_key"], row["stat_key"])).encode())
            hasher.update(b"\n")
        return hasher.hexdigest()

    def aggregate_fingerprint(self) -> dict[str, Any]:
        """与用户标识无关的统计口径指纹：去关联前后必须完全一致。"""
        samples = self.connection.execute(
            "SELECT COUNT(*) AS amount,COALESCE(SUM(latency_ms),0) AS latency,"
            "COALESCE(SUM(packet_loss),0) AS loss,COALESCE(SUM(downlink_mbps),0) AS downlink,"
            "COALESCE(SUM(uplink_mbps),0) AS uplink FROM experience_samples"
        ).fetchone()
        incidents = [
            (row[0], row[1], int(row[2]))
            for row in self.connection.execute(
                "SELECT severity,state,COUNT(*) FROM quality_incidents GROUP BY severity,state ORDER BY 1,2"
            ).fetchall()
        ]
        sessions = [
            (row[0], int(row[1]), float(row[2]))
            for row in self.connection.execute(
                "SELECT status,COUNT(*),COALESCE(SUM(allocated_downlink_mbps),0) "
                "FROM acceleration_sessions GROUP BY status ORDER BY 1"
            ).fetchall()
        ]
        capacity = [
            (int(row[0]), row[1], row[2], float(row[3]), float(row[4]))
            for row in self.connection.execute(
                "SELECT scenario_id,segment_id,state,COALESCE(SUM(downlink_mbps),0),COALESCE(SUM(uplink_mbps),0) "
                "FROM capacity_reservations GROUP BY scenario_id,segment_id,state ORDER BY 1,2,3"
            ).fetchall()
        ]
        entitlements = [
            (row[0], int(row[1]))
            for row in self.connection.execute(
                "SELECT state,COUNT(*) FROM subscriber_entitlements GROUP BY state ORDER BY 1"
            ).fetchall()
        ]
        fingerprint = {
            "samples": {
                "amount": int(samples["amount"]),
                "latency_sum": float(samples["latency"]),
                "loss_sum": float(samples["loss"]),
                "downlink_sum": float(samples["downlink"]),
                "uplink_sum": float(samples["uplink"]),
            },
            "incidents": incidents,
            "sessions": sessions,
            "capacity": capacity,
            "entitlements": entitlements,
        }
        digest = hashlib.sha256(_json(fingerprint).encode()).hexdigest()
        return {"digest": digest, "metrics": fingerprint}

    # ------------------------------------------------------------- 任务存取

    def _get_run(self, run_id: str) -> sqlite3.Row:
        row = self.connection.execute("SELECT * FROM retention_runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise NotFoundError("去关联任务不存在")
        return row

    def _save_cursor(self, run_id: str, cursor: dict[str, int]) -> None:
        self.connection.execute("UPDATE retention_runs SET cursor_json=? WHERE run_id=?", (_json(cursor), run_id))

    # ------------------------------------------------------------------ 预演

    def preview(self, *, actor: str, run_id: str | None = None, retention_days: dict[str, int] | None = None) -> dict[str, Any]:
        run_id = run_id or new_run_id()
        existing = self.connection.execute("SELECT * FROM retention_runs WHERE run_id=?", (run_id,)).fetchone()
        if existing is not None:
            if existing["mode"] != "preview":
                raise ConflictError("相同 run_id 已用于其他模式的任务")
            if existing["state"] == "completed":
                return json.loads(existing["report_json"])
        now_value = self.clock.now()
        now = to_storage(now_value)
        policies = self._policies(retention_days)
        global_hold = self._refresh_hold_table(now)
        pepper = self.resolve_pepper()
        digests = self._all_digests()
        aggregate = self.aggregate_fingerprint()
        table_reports: list[dict[str, Any]] = []
        for key in CATEGORY_ORDER:
            policy = policies[key]
            cutoff = policy.cutoff(now_value)
            plan = self._plan_category(policy, cutoff, global_hold)
            batches: dict[str, int] = {}
            mapping_hasher = hashlib.sha256()
            after_id = 0
            while True:
                rows = self._due_page(policy, cutoff, after_id, self.page_size, global_hold)
                if not rows:
                    break
                for row in rows:
                    batch_key = batch_for(row["anchor_at"], policy.retain_days)
                    stat_key = self.stat_key(pepper, batch_key, row["subscriber_hash"])
                    batches[batch_key] = batches.get(batch_key, 0) + 1
                    mapping_hasher.update("|".join((policy.table, str(row["id"]), batch_key, stat_key)).encode())
                    mapping_hasher.update(b"\n")
                after_id = int(rows[-1]["id"])
            plan.update({"transformed": 0, "batches": dict(sorted(batches.items())), "mapping_digest": mapping_hasher.hexdigest()})
            table_reports.append(plan)
        return self._store_report(
            self._build_report(
                run_id=run_id, mode="preview", state="completed", actor=actor, policies=policies,
                now_value=now_value, pepper=pepper, table_reports=table_reports, digests=digests,
                aggregate_before=aggregate, aggregate_after=aggregate,
                cursor={key: 0 for key in CATEGORY_ORDER}, started_at=now, completed_at=now,
            )
        )

    # ------------------------------------------------------------------ 执行

    def apply(self, *, actor: str, run_id: str | None = None, retention_days: dict[str, int] | None = None) -> dict[str, Any]:
        run_id = run_id or new_run_id()
        now_value = self.clock.now()
        now = to_storage(now_value)
        policies = self._policies(retention_days)
        existing = self.connection.execute("SELECT * FROM retention_runs WHERE run_id=?", (run_id,)).fetchone()
        if existing is not None:
            if existing["mode"] != "apply":
                raise ConflictError("相同 run_id 已用于其他模式的任务")
            if existing["state"] == "completed":
                return json.loads(existing["report_json"])

        if existing is None:
            pepper = self.resolve_pepper()
            digests = self._all_digests()
            aggregate_before = self.aggregate_fingerprint()
            cursor = {key: 0 for key in CATEGORY_ORDER}
            with transaction(immediate=True) as connection:
                connection.execute(
                    "INSERT INTO retention_runs(run_id,mode,state,actor,cutoff_at,policy_json,cursor_json,"
                    "baseline_digests_json,aggregate_digest,started_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        run_id, "apply", "running", actor, now,
                        _json(self._policy_view(policies, now_value)), _json(cursor),
                        _json(digests), aggregate_before["digest"], now,
                    ),
                )
        else:
            pepper = self.resolve_pepper()
            digests = json.loads(existing["baseline_digests_json"])
            aggregate_before = {"digest": existing["aggregate_digest"]}
            cursor = {key: 0 for key in CATEGORY_ORDER}
            cursor.update(json.loads(existing["cursor_json"]))
            # 续跑沿用首次运行记录的保留天数，确保到期批次与统计键不因时间推移而变化。
            stored_policy = json.loads(existing["policy_json"])
            policies = self._policies({key: stored_policy[key]["retain_days"] for key in CATEGORY_ORDER})
            cutoffs = {key: stored_policy[key]["cutoff_at"] for key in CATEGORY_ORDER}
            with transaction(immediate=True) as connection:
                connection.execute("UPDATE retention_runs SET state='running',error_message='' WHERE run_id=?", (run_id,))

        if existing is None:
            cutoffs = {key: policies[key].cutoff(now_value) for key in CATEGORY_ORDER}

        global_hold = self._refresh_hold_table(now)
        # 各表候选/跳过/到期计数以“任务启动时刻”为准，续跑时复用首次计划，避免与累计转换数口径错位。
        if existing is not None and existing["plan_json"]:
            stored_plans = json.loads(existing["plan_json"])
        else:
            stored_plans = None
        plans: dict[str, dict[str, Any]] = {}
        for key in CATEGORY_ORDER:
            if stored_plans is not None:
                plans[key] = stored_plans[key]
            else:
                plans[key] = self._plan_category(policies[key], cutoffs[key], global_hold)
        if existing is None:
            with transaction(immediate=True) as connection:
                connection.execute("UPDATE retention_runs SET plan_json=? WHERE run_id=?", (_json(plans), run_id))

        table_reports: list[dict[str, Any]] = []
        try:
            for key in CATEGORY_ORDER:
                policy = policies[key]
                cutoff = cutoffs[key]
                plan = dict(plans[key])
                while True:
                    # 每页一个即时事务并推进检查点，中断后下一页从 cursor 继续。
                    with transaction(immediate=True) as connection:
                        rows = self._due_page(policy, cutoff, cursor[key], self.page_size, global_hold)
                        if not rows:
                            break
                        for row in rows:
                            batch_key = batch_for(row["anchor_at"], policy.retain_days)
                            stat_key = self.stat_key(pepper, batch_key, row["subscriber_hash"])
                            updated = connection.execute(
                                f"UPDATE {policy.table} SET subscriber_hash=? WHERE id=? AND subscriber_hash=?",
                                (stat_key, row["id"], row["subscriber_hash"]),
                            )
                            if updated.rowcount != 1:
                                raise ConflictError(f"{policy.table}#{row['id']} 在处理期间被改动，任务中止")
                            connection.execute(
                                "INSERT INTO retention_records(run_id,category,table_name,row_id,batch_key,stat_key,created_at) "
                                "VALUES(?,?,?,?,?,?,?)",
                                (run_id, key, policy.table, row["id"], batch_key, stat_key, now),
                            )
                        cursor[key] = int(rows[-1]["id"])
                        self._save_cursor(run_id, cursor)
                # 累计值（含续跑前已处理的页）从去关联记录汇总。
                batch_rows = self.connection.execute(
                    "SELECT batch_key,COUNT(*) AS amount FROM retention_records WHERE run_id=? AND category=? GROUP BY batch_key",
                    (run_id, key),
                ).fetchall()
                plan.update({
                    "transformed": sum(int(row["amount"]) for row in batch_rows),
                    "batches": {row["batch_key"]: int(row["amount"]) for row in sorted(batch_rows, key=lambda item: item["batch_key"])},
                })
                table_reports.append(plan)
        except BaseException as exc:
            with transaction(immediate=True) as connection:
                connection.execute(
                    "UPDATE retention_runs SET state='failed',error_message=?,completed_at=? WHERE run_id=? AND state='running'",
                    (str(exc)[:500], to_storage(self.clock.now()), run_id),
                )
            raise

        with transaction(immediate=True) as connection:
            final_digests = {table: self._table_digest(table) for table in TABLE_COLUMNS}
            aggregate_after = self.aggregate_fingerprint()
            # 结束时重算各表剩余到期行：首次执行或断点续跑完成后都应为 0。
            residual_due = 0
            for key in CATEGORY_ORDER:
                policy = policies[key]
                residual_due += self._plan_category(policy, cutoffs[key], global_hold)["due"]
            for report in table_reports:
                report["mapping_digest"] = self._mapping_digest(run_id, report["category"])
            report = self._build_report(
                run_id=run_id, mode="apply", state="completed", actor=actor, policies=policies,
                now_value=now_value, pepper=pepper, table_reports=table_reports, digests=final_digests,
                aggregate_before=aggregate_before, aggregate_after=aggregate_after,
                cursor=cursor, started_at=(existing["started_at"] if existing is not None else now),
                completed_at=to_storage(self.clock.now()),
                baseline_digests=digests, residual_due_rows=residual_due, cutoffs=cutoffs,
            )
            connection.execute(
                "INSERT INTO operation_events(resource_type,resource_id,event_type,actor,detail_json,created_at) "
                "VALUES('retention',0,?,?,?,?)",
                (
                    "deidentified",
                    actor,
                    _json({"run_id": run_id, "totals": report["totals"], "aggregate_digest": aggregate_after["digest"]}),
                    to_storage(self.clock.now()),
                ),
            )
            connection.execute(
                "UPDATE retention_runs SET state='completed',completed_at=?,report_json=?,aggregate_digest=? WHERE run_id=?",
                (to_storage(self.clock.now()), json.dumps(report, ensure_ascii=False, sort_keys=True), aggregate_after["digest"], run_id),
            )
        return report

    # ------------------------------------------------------------- 证明报告

    def attestation(self, run_id: str) -> dict[str, Any]:
        row = self._get_run(run_id)
        if row["state"] == "completed" and row["report_json"]:
            return json.loads(row["report_json"])
        return {
            "run_id": row["run_id"],
            "mode": row["mode"],
            "state": row["state"],
            "actor": row["actor"],
            "cutoff_at": row["cutoff_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "error_message": row["error_message"],
            "checkpoint": json.loads(row["cursor_json"]),
        }

    def list_runs(self, *, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT run_id,mode,state,actor,started_at,completed_at,aggregate_digest FROM retention_runs "
            "ORDER BY started_at DESC,rowid DESC LIMIT ?",
            (min(max(limit, 1), 200),),
        ).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------- 身份查询

    def locate_identity(self, subscriber_hash: str) -> dict[str, Any]:
        """按原始脱敏标识查询仍可关联到该旅客的行数；去关联后到期数据应全部为 0。"""
        located: dict[str, int] = {}
        for table in TRANSFORMED_TABLES:
            located[table] = int(self.connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE subscriber_hash=?",
                (subscriber_hash,),
            ).fetchone()[0])
        active_holds = [
            dict(row) for row in self.connection.execute(
                "SELECT id,scope,subscriber_hash,reason,expires_at FROM retention_legal_holds "
                "WHERE state='active' AND (scope='global' OR subscriber_hash=?)",
                (subscriber_hash,),
            ).fetchall()
        ]
        return {
            "subscriber_hash": subscriber_hash,
            "is_statistical_key": subscriber_hash.startswith(STAT_PREFIX),
            "remaining_rows": located,
            "total_remaining": sum(located.values()),
            "active_legal_holds": active_holds,
            "queried_at": to_storage(self.clock.now()),
        }

    # ------------------------------------------------------------- 报告组装

    def _store_report(self, report: dict[str, Any]) -> dict[str, Any]:
        with transaction(immediate=True) as connection:
            connection.execute(
                "INSERT INTO retention_runs(run_id,mode,state,actor,cutoff_at,policy_json,totals_json,"
                "baseline_digests_json,aggregate_digest,report_json,started_at,completed_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(run_id) DO UPDATE SET report_json=excluded.report_json,state='completed',completed_at=excluded.completed_at",
                (
                    report["run_id"], report["mode"], "completed", report["actor"], report["cutoff_at"],
                    _json(report["policy"]), _json(report["totals"]),
                    _json({t["table"]: t["baseline_digest"] for t in report["tables"]}),
                    report["checks"]["final_aggregate_digest"],
                    json.dumps(report, ensure_ascii=False, sort_keys=True),
                    report["started_at"], report["completed_at"],
                ),
            )
        return report

    def _build_report(
        self,
        *,
        run_id: str,
        mode: str,
        state: str,
        actor: str,
        policies: dict[str, CategoryPolicy],
        now_value: datetime,
        pepper: str,
        table_reports: list[dict[str, Any]],
        digests: dict[str, str],
        aggregate_before: dict[str, Any],
        aggregate_after: dict[str, Any],
        cursor: dict[str, int],
        started_at: str,
        completed_at: str | None,
        baseline_digests: dict[str, str] | None = None,
        residual_due_rows: int | None = None,
        cutoffs: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        baseline = baseline_digests or digests
        policy_view = self._policy_view(policies, now_value)
        if cutoffs:
            for key, cutoff in cutoffs.items():
                policy_view[key]["cutoff_at"] = cutoff
        totals = {
            "candidate_rows": sum(item["candidate_rows"] for item in table_reports),
            "within_retention": sum(item["within_retention"] for item in table_reports),
            "skipped_legal_hold": sum(item["skipped_legal_hold"] for item in table_reports),
            "skipped_active_dispute": sum(item["skipped_active_dispute"] for item in table_reports),
            "due": sum(item["due"] for item in table_reports),
            "transformed": sum(item["transformed"] for item in table_reports),
        }
        tables: list[dict[str, Any]] = []
        for item in table_reports:
            tables.append({
                **item,
                "baseline_digest": baseline[item["table"]],
                "final_digest": digests[item["table"]],
            })
        association = {
            table: {
                "digest": digests[table],
                "unchanged": digests[table] == baseline[table],
            }
            for table in ASSOCIATION_TABLES
        }
        transformed_total = totals["transformed"]
        report = {
            "run_id": run_id,
            "mode": mode,
            "state": state,
            "actor": actor,
            "policy": policy_view,
            "cutoff_at": to_storage(now_value),
            "pepper_id": pepper_identifier(pepper),
            "started_at": started_at,
            "completed_at": completed_at,
            "tables": tables,
            "totals": totals,
            "skipped_reasons": {
                "within_retention": totals["within_retention"],
                "legal_hold": totals["skipped_legal_hold"],
                "active_dispute": totals["skipped_active_dispute"],
            },
            "checks": {
                "baseline_aggregate_digest": aggregate_before["digest"],
                "final_aggregate_digest": aggregate_after["digest"],
                "aggregate_unchanged": aggregate_before["digest"] == aggregate_after["digest"],
                "association_tables": association,
                # apply 完成后到期未处理行数必须为 0（apply 显式重算）；preview 不做任何改动。
                "residual_due_rows": (
                    totals["due"] if residual_due_rows is None and mode == "preview"
                    else (totals["due"] - transformed_total if residual_due_rows is None else residual_due_rows)
                ),
            },
            "checkpoint": {"cursor": cursor, "resumable": state != "completed"},
        }
        report["report_digest"] = hashlib.sha256(
            json.dumps(
                {key: value for key, value in report.items() if key != "report_digest"},
                ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            ).encode()
        ).hexdigest()
        return report
