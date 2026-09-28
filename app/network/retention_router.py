from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.dependencies import current_principal
from app.core.errors import ValidationError
from app.core.security import Principal
from app.database import get_connection
from app.network.retention import DEFAULT_RETENTION_DAYS, PrivacyRetentionService
from app.network.retention_schemas import LegalHoldCreate, LegalHoldRelease, RetentionExecuteRequest, RetentionPreviewRequest

router = APIRouter(prefix="/api/network/privacy", tags=["隐私分级保留与去关联"])


def service() -> PrivacyRetentionService:
    return PrivacyRetentionService(get_connection())


@router.post("/retention/preview")
def preview_retention(payload: RetentionPreviewRequest, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("privacy.read")
    return service().preview(retention_days=payload.retention_days)


@router.post("/retention/execute", status_code=201)
def execute_retention(payload: RetentionExecuteRequest, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("privacy.execute")
    return service().execute(actor=payload.actor, retention_days=payload.retention_days)


@router.post("/retention/runs/{run_id}/resume", status_code=201)
def resume_retention(run_id: int, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("privacy.execute")
    return service().resume(run_id)


@router.post("/retention/runs/{run_id}/abort")
def abort_retention_run(run_id: int, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("privacy.execute")
    return service().abort_run(run_id)


@router.get("/retention/runs/{run_id}/report")
def retention_report(run_id: int, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("privacy.read")
    return service().report(run_id)


@router.get("/retention/runs")
def list_retention_runs(principal: Principal = Depends(current_principal), limit: int = Query(default=50, ge=1, le=200)) -> dict:
    principal.require("privacy.read")
    return {"items": service().list_runs(limit)}


@router.get("/subjects/footprint")
def subject_footprint(subscriber_hash: str = Query(min_length=1, max_length=128), principal: Principal = Depends(current_principal)) -> dict:
    principal.require("privacy.read")
    return service().subject_footprint(subscriber_hash)


@router.post("/legal-holds", status_code=201)
def add_legal_hold(payload: LegalHoldCreate, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("privacy.execute")
    return service().add_legal_hold(payload.model_dump())


@router.post("/legal-holds/{hold_id}/release")
def release_legal_hold(hold_id: int, payload: LegalHoldRelease, principal: Principal = Depends(current_principal)) -> dict:
    principal.require("privacy.execute")
    return service().release_legal_hold(hold_id, payload.actor, payload.reason)


@router.get("/legal-holds")
def list_legal_holds(state: str | None = Query(default=None), principal: Principal = Depends(current_principal)) -> dict:
    principal.require("privacy.read")
    if state not in (None, "active", "released"):
        raise ValidationError("保全状态只能是 active 或 released")
    return {"items": service().list_legal_holds(state)}
