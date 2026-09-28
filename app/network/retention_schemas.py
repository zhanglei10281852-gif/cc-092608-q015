from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class RetentionDays(BaseModel):
    experience_samples: int = Field(default=30, ge=1, le=3650)
    acceleration_sessions: int = Field(default=90, ge=1, le=3650)
    subscriber_entitlements: int = Field(default=180, ge=1, le=3650)

    def overrides(self) -> dict[str, int]:
        return self.model_dump()


class RetentionRunRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=120)
    run_id: str | None = Field(default=None, min_length=4, max_length=120, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]+$")
    retention_days: RetentionDays | None = None


class LegalHoldCreate(BaseModel):
    scope: Literal["subscriber", "global"] = "subscriber"
    subscriber_hash: str | None = Field(default=None, min_length=1, max_length=128)
    reason: str = Field(min_length=2, max_length=500)
    expires_at: str | None = None
    actor: str = Field(default="compliance", min_length=1, max_length=120)

    @model_validator(mode="after")
    def validate_scope(self) -> "LegalHoldCreate":
        if self.scope == "subscriber" and not self.subscriber_hash:
            raise ValueError("旅客级保全必须提供脱敏用户标识")
        return self
