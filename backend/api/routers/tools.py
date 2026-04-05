import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from core.security import get_current_user
from models.user import User

router = APIRouter()


class NmapRequest(BaseModel):
    target: str
    asset_id: Optional[uuid.UUID] = None
    ports: Optional[str] = "1-65535"
    scan_type: Optional[str] = "tcp_syn"  # tcp_syn/udp/comprehensive
    os_detection: bool = False
    service_detection: bool = True
    scripts: Optional[List[str]] = None


class NucleiRequest(BaseModel):
    target: str
    asset_id: Optional[uuid.UUID] = None
    templates: Optional[List[str]] = ["cve", "misconfig", "exposure"]
    severity_filter: Optional[List[str]] = ["critical", "high", "medium"]
    rate_limit: int = Field(150, ge=1, le=500)
    tags: Optional[List[str]] = None


class NiktoRequest(BaseModel):
    target: str
    asset_id: Optional[uuid.UUID] = None
    options: Optional[Dict[str, Any]] = {}


class SslScanRequest(BaseModel):
    target: str
    asset_id: Optional[uuid.UUID] = None
    port: int = 443


class SubdomainEnumRequest(BaseModel):
    domain: str
    asset_id: Optional[uuid.UUID] = None
    sources: Optional[List[str]] = ["google", "bing", "crtsh", "dnsdumpster"]
    limit: int = Field(500, ge=1, le=5000)


class WhoisRequest(BaseModel):
    target: str


class HeadersRequest(BaseModel):
    url: str
    asset_id: Optional[uuid.UUID] = None
    follow_redirects: bool = True


class MasscanRequest(BaseModel):
    target: str
    asset_id: Optional[uuid.UUID] = None
    ports: str = "1-65535"
    rate: int = Field(1000, ge=100, le=100000)


class WhatWebRequest(BaseModel):
    target: str
    asset_id: Optional[uuid.UUID] = None
    aggression: int = Field(1, ge=1, le=4)


class WpScanRequest(BaseModel):
    target: str
    asset_id: Optional[uuid.UUID] = None
    enumerate: Optional[List[str]] = ["vp", "vt", "cb", "dbe", "u"]


class SqlmapRequest(BaseModel):
    target: str
    asset_id: Optional[uuid.UUID] = None
    authorized: bool = False
    level: int = Field(1, ge=1, le=5)
    risk: int = Field(1, ge=1, le=3)
    data: Optional[str] = None
    cookies: Optional[str] = None


class GobusterRequest(BaseModel):
    target: str
    asset_id: Optional[uuid.UUID] = None
    wordlist: Optional[str] = None
    extensions: Optional[List[str]] = ["php", "html", "js", "txt", "bak"]
    threads: int = Field(10, ge=1, le=50)


class WfuzzRequest(BaseModel):
    target: str
    asset_id: Optional[uuid.UUID] = None
    wordlist: Optional[str] = None
    fuzz_position: str = "FUZZ"
    filter_codes: Optional[List[int]] = [404]


def _dispatch_task(task_name: str, org_id: str, asset_id: Optional[str], target: str, options: dict) -> str:
    from worker.celery_app import celery_app

    scan_id = str(uuid.uuid4())
    celery_app.send_task(
        task_name,
        args=[scan_id, org_id, asset_id, target, options],
        queue="scans",
    )
    return scan_id


@router.post("/nmap", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_nmap(
    request: NmapRequest,
    current_user: User = Depends(get_current_user),
):
    scan_id = _dispatch_task(
        "worker.tasks.nmap_task.run_nmap",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.target,
        {
            "ports": request.ports,
            "scan_type": request.scan_type,
            "os_detection": request.os_detection,
            "service_detection": request.service_detection,
            "scripts": request.scripts or [],
        },
    )
    return {"scan_id": scan_id, "status": "queued", "message": "Nmap scan queued"}


@router.post("/nuclei", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_nuclei(
    request: NucleiRequest,
    current_user: User = Depends(get_current_user),
):
    scan_id = _dispatch_task(
        "worker.tasks.nuclei_task.run_nuclei",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.target,
        {
            "templates": request.templates,
            "severity_filter": request.severity_filter,
            "rate_limit": request.rate_limit,
            "tags": request.tags or [],
        },
    )
    return {"scan_id": scan_id, "status": "queued", "message": "Nuclei scan queued"}


@router.post("/nikto", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_nikto(
    request: NiktoRequest,
    current_user: User = Depends(get_current_user),
):
    scan_id = _dispatch_task(
        "worker.tasks.nikto_task.run_nikto",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.target,
        request.options or {},
    )
    return {"scan_id": scan_id, "status": "queued", "message": "Nikto scan queued"}


@router.post("/sslscan", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_sslscan(
    request: SslScanRequest,
    current_user: User = Depends(get_current_user),
):
    scan_id = _dispatch_task(
        "worker.tasks.ssl_task.run_sslscan",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.target,
        {"port": request.port},
    )
    return {"scan_id": scan_id, "status": "queued", "message": "SSL scan queued"}


@router.post("/subdomain-enum", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_subdomain_enum(
    request: SubdomainEnumRequest,
    current_user: User = Depends(get_current_user),
):
    scan_id = _dispatch_task(
        "worker.tasks.subdomain_task.run_subdomain_enum",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.domain,
        {"sources": request.sources, "limit": request.limit},
    )
    return {"scan_id": scan_id, "status": "queued", "message": "Subdomain enumeration queued"}


@router.post("/whois", response_model=dict)
async def run_whois(
    request: WhoisRequest,
    current_user: User = Depends(get_current_user),
):
    import subprocess

    try:
        result = subprocess.run(
            ["whois", request.target],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {
            "target": request.target,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None,
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Whois lookup timed out")
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="whois binary not found")


@router.post("/headers", response_model=dict)
async def check_headers(
    request: HeadersRequest,
    current_user: User = Depends(get_current_user),
):
    """Synchronous header check — returns results immediately."""
    import requests as req_lib

    try:
        response = req_lib.get(
            request.url,
            allow_redirects=request.follow_redirects,
            timeout=15,
            verify=False,
        )
        headers = dict(response.headers)

        security_headers = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "Referrer-Policy": headers.get("Referrer-Policy"),
            "Permissions-Policy": headers.get("Permissions-Policy"),
            "X-Powered-By": headers.get("X-Powered-By"),
            "Server": headers.get("Server"),
        }

        missing = [k for k, v in security_headers.items() if v is None and k not in ("X-Powered-By", "Server")]

        return {
            "url": request.url,
            "status_code": response.status_code,
            "security_headers": security_headers,
            "missing_headers": missing,
            "all_headers": headers,
        }
    except req_lib.exceptions.ConnectionError:
        raise HTTPException(status_code=502, detail="Could not connect to target URL")
    except req_lib.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="Request to target URL timed out")


@router.post("/masscan", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_masscan(
    request: MasscanRequest,
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Masscan requires admin or analyst role")

    scan_id = _dispatch_task(
        "worker.tasks.masscan_task.run_masscan",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.target,
        {"ports": request.ports, "rate": request.rate},
    )
    return {"scan_id": scan_id, "status": "queued", "message": "Masscan queued"}


@router.post("/whatweb", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_whatweb(
    request: WhatWebRequest,
    current_user: User = Depends(get_current_user),
):
    scan_id = _dispatch_task(
        "worker.tasks.whatweb_task.run_whatweb",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.target,
        {"aggression": request.aggression},
    )
    return {"scan_id": scan_id, "status": "queued", "message": "WhatWeb scan queued"}


@router.post("/wpscan", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_wpscan(
    request: WpScanRequest,
    current_user: User = Depends(get_current_user),
):
    scan_id = _dispatch_task(
        "worker.tasks.wpscan_task.run_wpscan",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.target,
        {"enumerate": request.enumerate},
    )
    return {"scan_id": scan_id, "status": "queued", "message": "WPScan queued"}


@router.post("/sqlmap", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_sqlmap(
    request: SqlmapRequest,
    current_user: User = Depends(get_current_user),
):
    if not request.authorized:
        raise HTTPException(
            status_code=403,
            detail="SQLMap requires explicit authorization. Set authorized=true to confirm you have permission to test this target.",
        )
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="SQLMap requires admin or analyst role")

    scan_id = _dispatch_task(
        "worker.tasks.sqlmap_task.run_sqlmap",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.target,
        {
            "authorized": True,
            "level": request.level,
            "risk": request.risk,
            "data": request.data,
            "cookies": request.cookies,
        },
    )
    return {"scan_id": scan_id, "status": "queued", "message": "SQLMap scan queued"}


@router.post("/gobuster", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_gobuster(
    request: GobusterRequest,
    current_user: User = Depends(get_current_user),
):
    scan_id = _dispatch_task(
        "worker.tasks.gobuster_task.run_gobuster",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.target,
        {
            "wordlist": request.wordlist,
            "extensions": request.extensions,
            "threads": request.threads,
        },
    )
    return {"scan_id": scan_id, "status": "queued", "message": "Gobuster scan queued"}


@router.post("/wfuzz", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_wfuzz(
    request: WfuzzRequest,
    current_user: User = Depends(get_current_user),
):
    from worker.celery_app import celery_app

    scan_id = str(uuid.uuid4())
    celery_app.send_task(
        "worker.tasks.gobuster_task.run_gobuster",  # reuse gobuster task structure
        args=[
            scan_id,
            str(current_user.org_id),
            str(request.asset_id) if request.asset_id else None,
            request.target,
            {
                "wordlist": request.wordlist,
                "mode": "wfuzz",
                "fuzz_position": request.fuzz_position,
                "filter_codes": request.filter_codes,
            },
        ],
        queue="scans",
    )
    return {"scan_id": scan_id, "status": "queued", "message": "Wfuzz scan queued"}
