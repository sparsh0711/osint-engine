from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Priority(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Check(BaseModel):
    entity_id: str
    attribute: str
    expected: Any


class Finding(BaseModel):
    id: str
    claim: str
    rationale: str
    priority: Priority
    supporting_entity_ids: list[str] = Field(default_factory=list)
    supporting_relationship_ids: list[str] = Field(default_factory=list)
    checks: list[Check] = Field(default_factory=list)


class RecommendedAction(BaseModel):
    action: str
    target: str
    target_entity_ids: list[str] = Field(default_factory=list)
    rationale: str
    authorization_required: str | None = None


class AgentOutput(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)


class RejectedFinding(BaseModel):
    finding: Finding
    reasons: list[str]


class ValidatedAction(BaseModel):
    action: RecommendedAction
    warnings: list[str] = Field(default_factory=list)


class ValidationResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    rejected_findings: list[RejectedFinding] = Field(default_factory=list)
    recommended_actions: list[ValidatedAction] = Field(default_factory=list)
