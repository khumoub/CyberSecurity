from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from uuid import UUID
from datetime import datetime
from enum import Enum


class ScanType(str, Enum):
    nmap = "nmap"
    nuclei = "nuclei"
    nikto = "nikto"
    ssl = "ssl"
    subdomain = "subdomain"
    dns = "dns"
    headers = "headers"
    sqlmap = "sqlmap"
    gobuster = "gobuster"
    masscan = "masscan"
    whatweb = "whatweb"
    wpscan = "wpscan"


class ScanStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class CreateScanRequest(BaseModel):
    asset_id: Optional[UUID] = None
    scan_type: ScanType
    target: str = Field(..., min_length=1, max_length=500)
    options: Optional[Dict[str, Any]] = {}


class ScanJobResponse(BaseModel):
    id: UUID
    org_id: UUID
    asset_id: Optional[UUID] = None
    scan_type: str
    status: str
    celery_task_id: Optional[str] = None
    target: str
    options: Optional[Dict[str, Any]] = None
    initiated_by: Optional[UUID] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    findings_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScanOutputResponse(BaseModel):
    scan_id: UUID
    raw_output: Optional[str] = None
