import uuid, os, shutil
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from core.security import get_current_user
from core.config import settings
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
        "worker.tasks.wfuzz_task.run_wfuzz",
        args=[
            scan_id,
            str(current_user.org_id),
            str(request.asset_id) if request.asset_id else None,
            request.target,
            {
                "url": request.target,
                "wordlist": request.wordlist,
                "filter_code": request.filter_codes or "404",
                "threads": 10,
            },
        ],
        queue="scans",
    )
    return {"scan_id": scan_id, "status": "queued", "message": "Wfuzz scan queued"}


# ── Missing endpoints added below ─────────────────────────────────────────────

class DnsAnalysisRequest(BaseModel):
    domain: str
    asset_id: Optional[uuid.UUID] = None
    record_types: Optional[List[str]] = ["A", "MX", "SPF", "DMARC", "DNSSEC"]
    dns_server: Optional[str] = None


class ZapRequest(BaseModel):
    target: str
    asset_id: Optional[uuid.UUID] = None
    scan_type: str = "passive"   # passive | active
    spider_depth: int = Field(3, ge=1, le=10)


class HydraRequest(BaseModel):
    target: str
    asset_id: Optional[uuid.UUID] = None
    authorized: bool = False
    protocol: str = "ssh"
    username: Optional[str] = None
    username_file: Optional[str] = None
    password_file: Optional[str] = "/usr/share/wordlists/rockyou.txt"
    threads: int = Field(4, ge=1, le=16)
    delay_ms: int = Field(0, ge=0, le=5000)


class HashidRequest(BaseModel):
    hash_input: str   # single hash or newline-separated batch


class HashcatRequest(BaseModel):
    hash_input: str
    asset_id: Optional[uuid.UUID] = None
    authorized: bool = False
    hash_type: Optional[str] = None   # auto-detect if None
    attack_mode: int = Field(0, ge=0, le=3)   # 0=dict, 3=brute
    wordlist: Optional[str] = "/usr/share/wordlists/rockyou.txt"
    rules: Optional[str] = None
    runtime_secs: int = Field(60, ge=10, le=600)


class LynisRequest(BaseModel):
    asset_id: Optional[uuid.UUID] = None
    audit_type: str = "local"   # local | remote
    ssh_host: Optional[str] = None
    ssh_user: Optional[str] = None


class LanDiscoveryRequest(BaseModel):
    asset_id: Optional[uuid.UUID] = None
    interface: str = "eth0"
    ip_range: str = "192.168.1.0/24"
    passive: bool = False


class HttpRequestModel(BaseModel):
    url: str
    method: str = "GET"
    headers: Optional[Dict[str, str]] = {}
    body: Optional[str] = None
    follow_redirects: bool = True


class DefaultCredsRequest(BaseModel):
    target: str
    asset_id: Optional[uuid.UUID] = None
    vendor: str
    protocol: str = "http"
    port: Optional[int] = None


class ReconNgRequest(BaseModel):
    target: str
    asset_id: Optional[uuid.UUID] = None
    workspace: str = "default"
    modules: Optional[List[str]] = ["recon/domains-hosts/google_site_web"]


class PcapUploadResponse(BaseModel):
    scan_id: str
    status: str
    message: str


# Default credentials database
DEFAULT_CREDS: Dict[str, List[Dict]] = {
    "cisco": [{"username": "admin", "password": "admin"}, {"username": "cisco", "password": "cisco"}, {"username": "admin", "password": ""}],
    "linksys": [{"username": "admin", "password": "admin"}, {"username": "", "password": "admin"}],
    "dlink": [{"username": "admin", "password": ""}, {"username": "admin", "password": "admin"}],
    "asus": [{"username": "admin", "password": "admin"}],
    "mikrotik": [{"username": "admin", "password": ""}, {"username": "admin", "password": "admin"}],
    "fortinet": [{"username": "admin", "password": ""}, {"username": "admin", "password": "admin"}],
    "palo-alto": [{"username": "admin", "password": "admin"}],
    "juniper": [{"username": "root", "password": ""}, {"username": "admin", "password": "juniper1"}],
    "vmware": [{"username": "root", "password": "vmware"}, {"username": "admin", "password": "admin"}],
    "generic": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "root", "password": "root"},
        {"username": "admin", "password": "123456"},
        {"username": "user", "password": "user"},
    ],
}


@router.post("/dns-analysis", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_dns_analysis(
    request: DnsAnalysisRequest,
    current_user: User = Depends(get_current_user),
):
    scan_id = _dispatch_task(
        "worker.tasks.dns_task.run_dns_analysis",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.domain,
        {"record_types": request.record_types, "dns_server": request.dns_server},
    )
    return {"scan_id": scan_id, "status": "queued", "message": "DNS analysis queued"}


@router.post("/zaproxy", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_zaproxy(
    request: ZapRequest,
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="ZAP scanning requires admin or analyst role")
    scan_id = _dispatch_task(
        "worker.tasks.zaproxy_task.run_zaproxy",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.target,
        {"scan_type": request.scan_type, "spider_depth": request.spider_depth},
    )
    return {"scan_id": scan_id, "status": "queued", "message": "OWASP ZAP scan queued"}


@router.post("/hydra", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_hydra(
    request: HydraRequest,
    current_user: User = Depends(get_current_user),
):
    if not request.authorized:
        raise HTTPException(status_code=403, detail="Hydra requires explicit authorization. Set authorized=true.")
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Hydra requires admin or analyst role")
    scan_id = _dispatch_task(
        "worker.tasks.hydra_task.run_hydra",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.target,
        {
            "authorized": True,
            "protocol": request.protocol,
            "username": request.username,
            "username_file": request.username_file,
            "password_file": request.password_file,
            "threads": request.threads,
            "delay_ms": request.delay_ms,
        },
    )
    return {"scan_id": scan_id, "status": "queued", "message": "Hydra login test queued"}


@router.post("/hashid", response_model=dict)
async def run_hashid(
    request: HashidRequest,
    current_user: User = Depends(get_current_user),
):
    """Synchronous hash identification — returns results immediately."""
    import subprocess
    results = []
    for line in request.hash_input.strip().splitlines():
        h = line.strip()
        if not h:
            continue
        try:
            proc = subprocess.run(
                ["hashid", "-e", "-m", h],
                capture_output=True, text=True, timeout=10
            )
            types = []
            for out_line in proc.stdout.splitlines():
                out_line = out_line.strip()
                if out_line.startswith("[+]"):
                    name = out_line[3:].strip()
                    hashcat_mode = None
                    if "[Hashcat Mode:" in name:
                        parts = name.split("[Hashcat Mode:")
                        name = parts[0].strip()
                        hashcat_mode = parts[1].rstrip("]").strip()
                    types.append({"name": name, "hashcat_mode": hashcat_mode})
            results.append({"hash": h[:64] + ("..." if len(h) > 64 else ""), "types": types[:10]})
        except Exception as e:
            results.append({"hash": h[:64], "types": [], "error": str(e)})
    return {"results": results, "total": len(results)}


@router.post("/hashcat", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_hashcat(
    request: HashcatRequest,
    current_user: User = Depends(get_current_user),
):
    if not request.authorized:
        raise HTTPException(status_code=403, detail="Hash cracking requires explicit authorization. Set authorized=true.")
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Hashcat requires admin or analyst role")
    scan_id = _dispatch_task(
        "worker.tasks.hashcat_task.run_hashcat",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.hash_input,
        {
            "authorized": True,
            "hash_type": request.hash_type,
            "attack_mode": request.attack_mode,
            "wordlist": request.wordlist,
            "rules": request.rules,
            "runtime_secs": request.runtime_secs,
        },
    )
    return {"scan_id": scan_id, "status": "queued", "message": "Hashcat job queued"}


@router.post("/lynis", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_lynis(
    request: LynisRequest,
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Lynis audit requires admin or analyst role")
    scan_id = _dispatch_task(
        "worker.tasks.lynis_task.run_lynis",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.ssh_host or "localhost",
        {"audit_type": request.audit_type, "ssh_user": request.ssh_user},
    )
    return {"scan_id": scan_id, "status": "queued", "message": "Lynis audit queued"}


@router.post("/lan-discovery", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_lan_discovery(
    request: LanDiscoveryRequest,
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="LAN discovery requires admin or analyst role")
    scan_id = _dispatch_task(
        "worker.tasks.lan_discovery_task.run_lan_discovery",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.ip_range,
        {"interface": request.interface, "passive": request.passive},
    )
    return {"scan_id": scan_id, "status": "queued", "message": "LAN discovery queued"}


@router.post("/http-request", response_model=dict)
async def send_http_request(
    request: HttpRequestModel,
    current_user: User = Depends(get_current_user),
):
    """HTTP request inspector — sends a request and returns full request/response detail."""
    import requests as req_lib, time
    try:
        start = time.time()
        resp = req_lib.request(
            method=request.method.upper(),
            url=request.url,
            headers=request.headers or {},
            data=request.body,
            allow_redirects=request.follow_redirects,
            timeout=30,
            verify=False,
        )
        elapsed = round((time.time() - start) * 1000)
        body_text = resp.text[:10000]  # cap at 10KB
        return {
            "request": {
                "method": request.method.upper(),
                "url": request.url,
                "headers": dict(resp.request.headers),
                "body": request.body,
            },
            "response": {
                "status_code": resp.status_code,
                "status_text": resp.reason,
                "elapsed_ms": elapsed,
                "headers": dict(resp.headers),
                "body": body_text,
                "encoding": resp.encoding,
                "cookies": {k: v for k, v in resp.cookies.items()},
            },
        }
    except req_lib.exceptions.ConnectionError as e:
        raise HTTPException(status_code=502, detail=f"Connection error: {e}")
    except req_lib.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="Request timed out")


@router.get("/wordlists", response_model=dict)
async def list_wordlists(current_user: User = Depends(get_current_user)):
    """List available wordlists."""
    import os
    wordlists = [
        {"name": "RockYou", "path": "/usr/share/wordlists/rockyou.txt", "type": "password", "source": "built-in"},
        {"name": "SecLists — Common Passwords", "path": "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt", "type": "password", "source": "seclists"},
        {"name": "SecLists — Usernames", "path": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt", "type": "username", "source": "seclists"},
        {"name": "dirb — common", "path": "/usr/share/dirb/wordlists/common.txt", "type": "directory", "source": "built-in"},
        {"name": "dirb — big", "path": "/usr/share/dirb/wordlists/big.txt", "type": "directory", "source": "built-in"},
        {"name": "SecLists — raft-medium-directories", "path": "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt", "type": "directory", "source": "seclists"},
        {"name": "SecLists — DNS Subdomains", "path": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt", "type": "subdomain", "source": "seclists"},
    ]
    for w in wordlists:
        w["exists"] = os.path.exists(w["path"])
        if w["exists"]:
            w["size_bytes"] = os.path.getsize(w["path"])
            w["line_count"] = sum(1 for _ in open(w["path"], "rb"))
        else:
            w["size_bytes"] = 0
            w["line_count"] = 0
    return {"wordlists": wordlists}


@router.post("/default-creds-check", response_model=dict)
async def check_default_creds(
    request: DefaultCredsRequest,
    current_user: User = Depends(get_current_user),
):
    """Test default credentials against a target service."""
    import requests as req_lib, socket
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Credential testing requires admin or analyst role")

    creds = DEFAULT_CREDS.get(request.vendor.lower(), DEFAULT_CREDS["generic"])
    results = []
    port = request.port or (80 if request.protocol in ("http", "http-basic") else 443)

    for cred in creds[:10]:   # cap at 10 attempts
        success = False
        try:
            if request.protocol in ("http", "https", "http-basic"):
                url = f"{request.protocol}://{request.target}:{port}/"
                resp = req_lib.get(url, auth=(cred["username"], cred["password"]),
                                    timeout=5, verify=False)
                success = resp.status_code not in (401, 403)
            elif request.protocol == "ssh":
                import subprocess
                result = subprocess.run(
                    ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                     "-o", f"PasswordAuthentication=yes",
                     f"{cred['username']}@{request.target}", "exit"],
                    input=cred["password"] + "\n", capture_output=True, text=True, timeout=10
                )
                success = result.returncode == 0
        except Exception:
            pass
        results.append({**cred, "success": success, "protocol": request.protocol})
        if success:
            break   # stop on first success

    cracked = [r for r in results if r["success"]]
    return {
        "target": request.target,
        "vendor": request.vendor,
        "tested": len(results),
        "cracked": cracked,
        "vulnerable": len(cracked) > 0,
    }


@router.post("/recon-ng", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_recon_ng(
    request: ReconNgRequest,
    current_user: User = Depends(get_current_user),
):
    scan_id = _dispatch_task(
        "worker.tasks.recon_ng_task.run_recon_ng",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.target,
        {"workspace": request.workspace, "modules": request.modules},
    )
    return {"scan_id": scan_id, "status": "queued", "message": "Recon-ng scan queued"}


@router.post("/pcap-upload", response_model=dict, status_code=202)
async def upload_pcap(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
):
    """PCAP file upload — saves file to disk then dispatches tshark analysis task."""
    scan_id = str(uuid.uuid4())
    pcap_dir = os.path.join(getattr(settings, "SCAN_OUTPUT_DIR", "/tmp/scans"), "pcap")
    os.makedirs(pcap_dir, exist_ok=True)
    dest = os.path.join(pcap_dir, f"{scan_id}.pcap")
    with open(dest, "wb") as f:
        shutil.copyfileobj(file.file, f)
    _dispatch_task(
        "worker.tasks.pcap_task.run_pcap_analysis",
        str(current_user.org_id),
        None,
        scan_id,
        {"pcap_path": dest, "protocol_filter": "all"},
    )
    return {
        "scan_id": scan_id,
        "status": "queued",
        "filename": file.filename,
        "message": "PCAP uploaded and queued for analysis. Connect to /ws/scan/{scan_id} for live output.",
    }


# ── New Tool Endpoints ────────────────────────────────────────────────────────

class CredentialedScanRequest(BaseModel):
    target: str
    asset_id: Optional[uuid.UUID] = None
    username: str = "root"
    ssh_key_path: Optional[str] = None
    password: Optional[str] = None
    check_kernel: bool = True
    check_services: bool = True


class ExploitVerifyRequest(BaseModel):
    finding_id: str
    target: Optional[str] = None
    authorized: bool = False


class AdAttacksRequest(BaseModel):
    target: str
    asset_id: Optional[uuid.UUID] = None
    domain: str
    username: Optional[str] = None
    password: Optional[str] = None
    dc_ip: Optional[str] = None
    attacks: Optional[List[str]] = ["kerberoasting", "asrep", "enum"]
    hash: Optional[str] = None
    authorized: bool = False


class RemediationVerifyRequest(BaseModel):
    finding_id: str
    target: Optional[str] = None


class ContainerScanRequest(BaseModel):
    image: str
    asset_id: Optional[uuid.UUID] = None
    scan_type: str = "image"  # image, fs, repo, dockerfile
    dockerfile_path: Optional[str] = None


class CisAuditRequest(BaseModel):
    target: str
    asset_id: Optional[uuid.UUID] = None
    username: str = "root"
    ssh_key_path: Optional[str] = None
    password: Optional[str] = None
    checks: Optional[List[str]] = None
    benchmark: str = "generic"


class EasmRequest(BaseModel):
    domain: str
    asset_id: Optional[uuid.UUID] = None
    auto_add_assets: bool = True
    port_scan: bool = True
    alert_new: bool = True


@router.post("/credentialed-scan", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_credentialed_scan(
    request: CredentialedScanRequest,
    current_user: User = Depends(get_current_user),
):
    """SSH-based credentialed scan: software inventory + vuln matching + config checks."""
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Admin or analyst role required")
    scan_id = _dispatch_task(
        "worker.tasks.credentialed_scan_task.run_credentialed_scan",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.target,
        {
            "username": request.username,
            "ssh_key_path": request.ssh_key_path,
            "password": request.password,
            "check_kernel": request.check_kernel,
            "check_services": request.check_services,
        },
    )
    return {"scan_id": scan_id, "status": "queued", "message": "Credentialed scan queued"}


@router.post("/exploit-verify", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_exploit_verify(
    request: ExploitVerifyRequest,
    current_user: User = Depends(get_current_user),
):
    """Attempt to prove a finding is actually exploitable via nuclei/HTTP PoC/Metasploit."""
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Admin or analyst role required")
    if not request.authorized:
        raise HTTPException(status_code=400, detail="Set authorized=true to confirm you own/have permission to test this target")
    scan_id = _dispatch_task(
        "worker.tasks.exploit_verify_task.verify_exploitability",
        str(current_user.org_id),
        None,
        request.finding_id,
        {"authorized": True, "target": request.target},
    )
    return {"scan_id": scan_id, "status": "queued", "message": "Exploit verification queued"}


@router.post("/ad-attacks", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_ad_attacks(
    request: AdAttacksRequest,
    current_user: User = Depends(get_current_user),
):
    """Active Directory attack simulation: Kerberoasting, AS-REP Roasting, PtH."""
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Admin or analyst role required")
    if not request.authorized:
        raise HTTPException(status_code=400, detail="Set authorized=true to confirm you own/have permission to test this AD environment")
    scan_id = _dispatch_task(
        "worker.tasks.ad_attacks_task.run_ad_attacks",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.target,
        {
            "authorized": True,
            "domain": request.domain,
            "username": request.username,
            "password": request.password,
            "dc_ip": request.dc_ip or request.target,
            "attacks": request.attacks,
            "hash": request.hash,
        },
    )
    return {"scan_id": scan_id, "status": "queued", "message": "AD attack simulation queued"}


@router.post("/fix-verify", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_fix_verify(
    request: RemediationVerifyRequest,
    current_user: User = Depends(get_current_user),
):
    """Re-run check for a specific finding to verify if the fix was effective."""
    scan_id = _dispatch_task(
        "worker.tasks.remediation_verify_task.verify_fix",
        str(current_user.org_id),
        None,
        request.finding_id,
        {"target": request.target},
    )
    return {"scan_id": scan_id, "status": "queued", "message": "Fix verification queued"}


@router.post("/container-scan", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_container_scan(
    request: ContainerScanRequest,
    current_user: User = Depends(get_current_user),
):
    """Scan a container image for CVEs and misconfigurations (Trivy/Grype)."""
    scan_id = _dispatch_task(
        "worker.tasks.container_scan_task.run_container_scan",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.image,
        {
            "image": request.image,
            "scan_type": request.scan_type,
            "dockerfile_path": request.dockerfile_path,
        },
    )
    return {"scan_id": scan_id, "status": "queued", "message": f"Container scan queued for {request.image}"}


@router.post("/cis-audit", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_cis_audit(
    request: CisAuditRequest,
    current_user: User = Depends(get_current_user),
):
    """CIS Benchmark compliance audit via SSH (37 checks across filesystem, SSH, PAM, logging, network)."""
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Admin or analyst role required")
    scan_id = _dispatch_task(
        "worker.tasks.cis_audit_task.run_cis_audit",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.target,
        {
            "username": request.username,
            "ssh_key_path": request.ssh_key_path,
            "password": request.password,
            "checks": request.checks,
            "benchmark": request.benchmark,
        },
    )
    return {"scan_id": scan_id, "status": "queued", "message": "CIS audit queued"}


@router.post("/easm", response_model=dict, status_code=status.HTTP_202_ACCEPTED)
async def run_easm(
    request: EasmRequest,
    current_user: User = Depends(get_current_user),
):
    """External Attack Surface Management: enumerate subdomains, resolve, port scan, detect new assets."""
    scan_id = _dispatch_task(
        "worker.tasks.easm_task.run_easm",
        str(current_user.org_id),
        str(request.asset_id) if request.asset_id else None,
        request.domain,
        {
            "domain": request.domain,
            "auto_add_assets": request.auto_add_assets,
            "port_scan": request.port_scan,
            "alert_new": request.alert_new,
        },
    )
    return {"scan_id": scan_id, "status": "queued", "message": f"EASM scan queued for {request.domain}"}
