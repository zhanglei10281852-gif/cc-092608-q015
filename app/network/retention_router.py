from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import current_principal
from app.core.security import Principal
from app.database import get_connection
from app.network.retention import RetentionService
from app.network.retention_schemas import LegalHoldCreate, RetentionRunRequest

router = APIRouter(prefix="/api/network/retention", tags=["分级保留与去关联"])


def service() -> RetentionService:
    return RetentionService(get_connection())


@router.post("/preview")
def preview(payload: RetentionRunRequest, principal: Principal = Depends(current_principal)) -> dict:
    """预演：只计算到期批次、跳过原因与校验哈希，不改动任何标识。"""
    principal.require("network.write")
    return service().preview(
        actor=payload.actor,
        run_id=payload.run_id,
        retention_days=payload.retention_days.overrides() if payload.retention_days else None,
    )


@router.post("/apply", status_code=200)
def apply(payload: RetentionRunRequest, principal: Principal = Depends(current_principal)) -> dict:
    """执行：到期标识替换为不可逆批次隔离统计键，可凭 run_id 从检查点继续。"""
    principal.require("network.write")
    return service().apply(
        actor=payload.actor,
        run_id=payload.run_id,
        retention_days=payload.retention_days.overrides() if payload.retention_days else None,
    )


@router.get("/runs/{run_id}/attestation")
def attestation(run_id: str, principal: Principal = Depends(current_principal)) -> dict:
    """证明报告：各表处理数量、跳过原因与校验哈希。"""
    principal.require("audit.read")
    return service().attestation(run_id)


@router.get("/runs")
def list_runs(limit: int = Query(default=50, ge=1, le=200), principal: Principal = Depends(current_principal)) -> dict:
    principal.require("audit.read")
    return {"items": service().list_runs(limit=limit)}


@router.get("/identity")
def locate_identity(subscriber_hash: str = Query(min_length=1, max_length=128), principal: Principal = Depends(current_principal)) -> dict:
    """身份查询：执行后用原始标识应查不到任何到期数据。"""
    principal.require("audit.read")
    return service().locate_identity(subscriber_hash)


@router.post("/legal-holds", status_code=201)
def add_legal_hold(payload: LegalHoldCreate, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("network.write")
    return service().add_legal_hold(payload.model_dump())


@router.get("/legal-holds")
def list_legal_holds(active_only: bool = True, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("audit.read")
    return {"items": service().list_legal_holds(active_only=active_only)}


@router.post("/legal-holds/{hold_id}/release")
def release_legal_hold(hold_id: int, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("network.write")
    return service().release_legal_hold(hold_id)
