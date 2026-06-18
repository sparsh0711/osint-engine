from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class Provenance(BaseModel):
    connector: str
    source: str
    query: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_ref: Any
