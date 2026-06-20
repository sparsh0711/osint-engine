from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from osint.core.ids import canonical_value, entity_id
from osint.core.provenance import Provenance


class EntityType(StrEnum):
    Domain = "Domain"
    IPAddress = "IPAddress"
    Certificate = "Certificate"
    Service = "Service"
    Vulnerability = "Vulnerability"
    ASN = "ASN"
    Netblock = "Netblock"
    Email = "Email"
    Username = "Username"
    URL = "URL"
    Person = "Person"
    Organization = "Organization"


class Entity(BaseModel):
    model_config = ConfigDict(use_enum_values=False)

    id: str | None = None
    type: EntityType
    value: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    sources: list[Provenance] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: set[str] = Field(default_factory=set)

    @model_validator(mode="after")
    def normalize_envelope(self) -> "Entity":
        if self.type == EntityType.Certificate:
            self.value = canonical_value(self.type, self.value)
            if "sha256" not in self.attributes:
                self.attributes["sha256"] = self.value
        else:
            self.value = canonical_value(self.type, self.value)

        self.id = self.id or entity_id(self.type, self.value)
        collected = [source.collected_at for source in self.sources]
        if self.first_seen is None:
            self.first_seen = min(collected)
        if self.last_seen is None:
            self.last_seen = max(collected)
        return self
