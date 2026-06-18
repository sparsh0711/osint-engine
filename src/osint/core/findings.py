from __future__ import annotations

from pydantic import BaseModel, Field

from osint.core.entities import Entity
from osint.core.relationships import Relationship


class Finding(BaseModel):
    entities: list[Entity] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
