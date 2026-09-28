from __future__ import annotations

import argparse
import json

from fastapi.testclient import TestClient

from app.database import database_path, get_connection, init_db
from app.main import app
from app.network.retention import PrivacyRetentionService
from app.network.schema import ensure_network_schema


def command_init(_args=None) -> int:
    init_db()
    ensure_network_schema(get_connection())
    print(json.dumps({"database": str(database_path()), "status": "initialized"}, ensure_ascii=False))
    return 0


def command_check(_args=None) -> int:
    init_db()
    connection = get_connection()
    ensure_network_schema(connection)
    result = {
        "database": str(database_path()),
        "integrity": connection.execute("PRAGMA integrity_check").fetchone()[0],
        "foreign_keys": connection.execute("PRAGMA foreign_keys").fetchone()[0],
        "journal_mode": connection.execute("PRAGMA journal_mode").fetchone()[0],
        "tables": connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0],
    }
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["integrity"] == "ok" and result["foreign_keys"] == 1 else 1


def command_smoke(_args=None) -> int:
    with TestClient(app) as client:
        root = client.get("/")
        health = client.get("/api/system/health")
        summary = client.get("/api/network/summary")
    result = {
        "root": root.json(),
        "health": health.json(),
        "summary": summary.json(),
        "status_codes": [root.status_code, health.status_code, summary.status_code],
    }
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status_codes"] == [200, 200, 200] else 1


def command_network_demo(_args=None) -> int:
    with TestClient(app) as client:
        seeded = client.post("/api/network/demo/seed")
        if seeded.status_code != 200:
            print(seeded.text)
            return 1
        now = "2026-09-26T05:30:00Z"
        entitlement = client.post(
            "/api/network/entitlements",
            json={
                "subscriber_hash": "subscriber-demo-0000000001",
                "scenario_code": "gdh-rail",
                "product_code": "rail-boost-day",
                "valid_from": "2026-09-26T00:00:00Z",
                "valid_until": "2026-09-27T00:00:00Z",
                "source_order_id": "demo-order-000001",
            },
        )
        sample = client.post(
            "/api/network/samples",
            json={
                "sample_key": "demo-sample-000001",
                "scenario_code": "gdh-rail",
                "segment_code": "gz-sz-01",
                "app_code": "video-call",
                "subscriber_hash": "subscriber-demo-0000000001",
                "device_class": "phone",
                "train_speed_kmh": 300,
                "latency_ms": 380,
                "packet_loss": 0.08,
                "downlink_mbps": 1.5,
                "uplink_mbps": 0.5,
                "observed_at": now,
            },
        )
        incident_id = sample.json().get("incident_id")
        started = client.post(f"/api/network/incidents/{incident_id}/accelerate", json={"actor": "cli-demo"})
    result = {
        "seed": seeded.status_code,
        "entitlement": entitlement.status_code,
        "sample": sample.status_code,
        "incident_id": incident_id,
        "session": started.status_code,
        "session_id": started.json().get("id") if started.status_code == 200 else None,
    }
    print(json.dumps(result, ensure_ascii=False))
    return 0 if list(result.values())[:3] == [200, 201, 202] and started.status_code == 200 else 1


def command_retention_preview(args) -> int:
    init_db()
    ensure_network_schema(get_connection())
    report = PrivacyRetentionService(get_connection()).preview(retention_days=args.days)
    print(json.dumps(report, ensure_ascii=False))
    return 0


def command_retention_execute(args) -> int:
    init_db()
    ensure_network_schema(get_connection())
    report = PrivacyRetentionService(get_connection()).execute(actor=args.actor, retention_days=args.days)
    print(json.dumps(report, ensure_ascii=False))
    verification = report.get("verification", {})
    return 0 if all(verification.values()) else 1


def command_retention_resume(args) -> int:
    init_db()
    ensure_network_schema(get_connection())
    report = PrivacyRetentionService(get_connection()).resume(args.run_id)
    print(json.dumps(report, ensure_ascii=False))
    verification = report.get("verification", {})
    return 0 if all(verification.values()) else 1


def command_retention_report(args) -> int:
    init_db()
    ensure_network_schema(get_connection())
    print(json.dumps(PrivacyRetentionService(get_connection()).report(args.run_id), ensure_ascii=False))
    return 0


def command_retention_abort(args) -> int:
    init_db()
    ensure_network_schema(get_connection())
    print(json.dumps(PrivacyRetentionService(get_connection()).abort_run(args.run_id), ensure_ascii=False))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="network-acceleration", description="5G-A 场景加速运营服务维护入口")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init-db", help="初始化 SQLite 数据库")
    subparsers.add_parser("check-db", help="检查数据库完整性")
    subparsers.add_parser("smoke", help="执行本地 API 冒烟检查")
    subparsers.add_parser("network-demo", help="执行质差识别与加速演示")
    preview_parser = subparsers.add_parser("retention-preview", help="预演分级保留与去关联批次")
    preview_parser.add_argument("--days", type=int, default=180, help="排障保留天数")
    execute_parser = subparsers.add_parser("retention-execute", help="执行分级保留与去关联批次")
    execute_parser.add_argument("--days", type=int, default=180, help="排障保留天数")
    execute_parser.add_argument("--actor", default="retention-job", help="执行人/任务标识")
    resume_parser = subparsers.add_parser("retention-resume", help="从检查点继续中断的批次")
    resume_parser.add_argument("run_id", type=int)
    report_parser = subparsers.add_parser("retention-report", help="查看批次证明报告")
    report_parser.add_argument("run_id", type=int)
    abort_parser = subparsers.add_parser("retention-abort", help="将僵留的运行中批次标记为失败")
    abort_parser.add_argument("run_id", type=int)
    args = parser.parse_args()
    return {
        "init-db": command_init,
        "check-db": command_check,
        "smoke": command_smoke,
        "network-demo": command_network_demo,
        "retention-preview": command_retention_preview,
        "retention-execute": command_retention_execute,
        "retention-resume": command_retention_resume,
        "retention-report": command_retention_report,
        "retention-abort": command_retention_abort,
    }[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
