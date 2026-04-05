from pydantic import BaseModel, Field
from typing import Optional, List, Any, Dict
from uuid import UUID
from datetime import datetime
from enum import Enum


class AssetType(str, Enum):
    host = "host"
    ip = "ip"
    domain = "domain"
    subnet = "subnet"
    url = "url"
    cidr = "cidr"


class CreateAssetRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    type: AssetType
    value: str = Field(..., min_length=1, max_length=500)
    os: Optional[str] = None
    os_version: Optional[str] = None
    tags: Optional[List[str]] = []
    metadata: Optional[Dict[str, Any]] = {}


class UpdateAssetRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    type: Optional[AssetType] = None
    value: Optional[str] = Field(None, min_length=1, max_length=500)
    os: Optional[str] = None
    os_version: Optional[str] = None
    tags: Optional[List[str]] = None
    is_active: Optional[bool] = None
    metadata: Optional[Dict[str, Any]] = None


class AssetResponse(BaseModel):
    id: UUID
    org_id: UUID
    name: str
    type: str
    value: str
    os: Optional[str] = None
    os_version: Optional[str] = None
    tags: Optional[List[str]] = []
    is_active: bool
    metadata_: Optional[Dict[str, Any]] = None
    last_scanned_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    findings_count: Optional[int] = None

    model_config = {"from_attributes": True}


class BulkImportRequest(BaseModel):
    type: AssetType
    targets: Optional[List[str]] = None  # list of IPs, domains, etc.
    cidr: Optional[str] = None  # e.g. 192.168.1.0/24
    csv_data: Optional[str] = None  # raw CSV content
    tags: Optional[List[str]] = []
