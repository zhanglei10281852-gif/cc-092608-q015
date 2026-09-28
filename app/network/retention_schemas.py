from __future__ import annotations

from pydantic import BaseModel, Field


class RetentionPreviewRequest(BaseModel):
    retention_days: int = Field(default=180, ge=1, le=3650)


class RetentionExecuteRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=120)
    retention_days: int = Field(default=180, ge=1, le=3650)


class LegalHoldCreate(BaseModel):
    subscriber_hash: str = Field(min_length=16, max_length=128)
    reason: str = Field(min_length=2, max_length=500)
    actor: str = Field(min_length=1, max_length=120)


class LegalHoldRelease(BaseModel):
    actor: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=2, max_length=500)
