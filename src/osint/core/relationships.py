from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from osint.core.ids import relationship_id
from osint.core.provenance import Provenance


class RelationType(StrEnum):
    HAS_SUBDOMAIN = "HAS_SUBDOMAIN"
    RESOLVES_TO = "RESOLVES_TO"
    SECURES = "SECURES"
    ANNOUNCES = "ANNOUNCES"
    CONTAINS = "CONTAINS"
    HOSTS = "HOSTS"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"


class Relationship(BaseModel):
    model_config = ConfigDict(use_enum_values=False)

    id: str | None = None
    type: RelationType
    src_id: str
    dst_id: str
    sources: list[Provenance] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @model_validator(mode="after")
    def normalize_envelope(self) -> "Relationship":
        self.id = self.id or relationship_id(self.type, self.src_id, self.dst_id)
        collected = [source.collected_at for source in self.sources]
        if self.first_seen is None:
            self.first_seen = min(collected)
        if self.last_seen is None:
            self.last_seen = max(collected)
        return self
