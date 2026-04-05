from pydantic import BaseModel, Field
from typing import Optional, List
from uuid import UUID
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingStatus(str, Enum):
    open = "open"
    in_remediation = "in_remediation"
    resolved = "resolved"
    accepted_risk = "accepted_risk"
    false_positive = "false_positive"


class FindingResponse(BaseModel):
    id: UUID
    org_id: UUID
    scan_id: Optional[UUID] = None
    asset_id: Optional[UUID] = None
    title: str
    description: Optional[str] = None
    severity: str
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    affected_component: Optional[str] = None
    affected_port: Optional[int] = None
    affected_service: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[List[str]] = []
    status: str
    assigned_to: Optional[UUID] = None
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: Optional[datetime] = None
    sla_due_date: Optional[datetime] = None
    is_known_exploited: bool = False
    exploit_available: bool = False
    mitre_technique: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class UpdateFindingRequest(BaseModel):
    status: Optional[FindingStatus] = None
    assigned_to: Optional[UUID] = None
    severity: Optional[Severity] = None
    remediation: Optional[str] = None
    sla_due_date: Optional[datetime] = None
    mitre_technique: Optional[str] = None
    notes: Optional[str] = None


class FindingStats(BaseModel):
    total: int
    by_severity: dict
    by_status: dict
    critical: int
    high: int
    medium: int
    low: int
    info: int
    open: int
    in_remediation: int
    resolved: int
    accepted_risk: int
    false_positive: int
    known_exploited: int
