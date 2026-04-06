import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from core.database import get_db
from core.security import get_current_user
from models.finding import Finding
from models.user import User

router = APIRouter()

# ---- Hardcoded ATT&CK technique dictionary (50 common techniques) ----
ATTACK_TECHNIQUES = {
    "T1190": {
        "technique_id": "T1190",
        "tactic": "Initial Access",
        "name": "Exploit Public-Facing Application",
        "description": "Adversaries may attempt to exploit weaknesses in an Internet-facing application.",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "T1133": {
        "technique_id": "T1133",
        "tactic": "Initial Access",
        "name": "External Remote Services",
        "description": "Adversaries may leverage external-facing remote services to gain access.",
        "url": "https://attack.mitre.org/techniques/T1133/",
    },
    "T1078": {
        "technique_id": "T1078",
        "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        "name": "Valid Accounts",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1021.001": {
        "technique_id": "T1021.001",
        "tactic": "Lateral Movement",
        "name": "Remote Services: Remote Desktop Protocol",
        "description": "Adversaries may use RDP to laterally move through an environment.",
        "url": "https://attack.mitre.org/techniques/T1021/001/",
    },
    "T1021.004": {
        "technique_id": "T1021.004",
        "tactic": "Lateral Movement",
        "name": "Remote Services: SSH",
        "description": "Adversaries may use Secure Shell (SSH) to remotely connect.",
        "url": "https://attack.mitre.org/techniques/T1021/004/",
    },
    "T1021.002": {
        "technique_id": "T1021.002",
        "tactic": "Lateral Movement",
        "name": "Remote Services: SMB/Windows Admin Shares",
        "description": "Adversaries may use SMB to laterally move through environments.",
        "url": "https://attack.mitre.org/techniques/T1021/002/",
    },
    "T1110": {
        "technique_id": "T1110",
        "tactic": "Credential Access",
        "name": "Brute Force",
        "description": "Adversaries may use brute force techniques to gain access.",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1110.001": {
        "technique_id": "T1110.001",
        "tactic": "Credential Access",
        "name": "Brute Force: Password Guessing",
        "description": "Adversaries may systematically guess passwords.",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "T1110.002": {
        "technique_id": "T1110.002",
        "tactic": "Credential Access",
        "name": "Brute Force: Password Cracking",
        "description": "Adversaries may use offline cracking tools to crack password hashes.",
        "url": "https://attack.mitre.org/techniques/T1110/002/",
    },
    "T1059": {
        "technique_id": "T1059",
        "tactic": "Execution",
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse scripting or command interpreters to execute commands.",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1055": {
        "technique_id": "T1055",
        "tactic": "Defense Evasion / Privilege Escalation",
        "name": "Process Injection",
        "description": "Adversaries may inject code into processes to evade detections.",
        "url": "https://attack.mitre.org/techniques/T1055/",
    },
    "T1083": {
        "technique_id": "T1083",
        "tactic": "Discovery",
        "name": "File and Directory Discovery",
        "description": "Adversaries may enumerate files and directories.",
        "url": "https://attack.mitre.org/techniques/T1083/",
    },
    "T1046": {
        "technique_id": "T1046",
        "tactic": "Discovery",
        "name": "Network Service Discovery",
        "description": "Adversaries may scan the network to discover services.",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1049": {
        "technique_id": "T1049",
        "tactic": "Discovery",
        "name": "System Network Connections Discovery",
        "description": "Adversaries may attempt to get a listing of network connections.",
        "url": "https://attack.mitre.org/techniques/T1049/",
    },
    "T1018": {
        "technique_id": "T1018",
        "tactic": "Discovery",
        "name": "Remote System Discovery",
        "description": "Adversaries may attempt to get a listing of other systems on a network.",
        "url": "https://attack.mitre.org/techniques/T1018/",
    },
    "T1592": {
        "technique_id": "T1592",
        "tactic": "Reconnaissance",
        "name": "Gather Victim Host Information",
        "description": "Adversaries may gather information about the victim's hosts.",
        "url": "https://attack.mitre.org/techniques/T1592/",
    },
    "T1595": {
        "technique_id": "T1595",
        "tactic": "Reconnaissance",
        "name": "Active Scanning",
        "description": "Adversaries may conduct active scanning of the victim's infrastructure.",
        "url": "https://attack.mitre.org/techniques/T1595/",
    },
    "T1596": {
        "technique_id": "T1596",
        "tactic": "Reconnaissance",
        "name": "Search Open Technical Databases",
        "description": "Adversaries may search freely available technical databases.",
        "url": "https://attack.mitre.org/techniques/T1596/",
    },
    "T1505.003": {
        "technique_id": "T1505.003",
        "tactic": "Persistence",
        "name": "Server Software Component: Web Shell",
        "description": "Adversaries may backdoor web servers with web shells.",
        "url": "https://attack.mitre.org/techniques/T1505/003/",
    },
    "T1071": {
        "technique_id": "T1071",
        "tactic": "Command and Control",
        "name": "Application Layer Protocol",
        "description": "Adversaries may communicate using application layer protocols.",
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
    "T1041": {
        "technique_id": "T1041",
        "tactic": "Exfiltration",
        "name": "Exfiltration Over C2 Channel",
        "description": "Adversaries may steal data by exfiltrating it over an existing C2 channel.",
        "url": "https://attack.mitre.org/techniques/T1041/",
    },
    "T1048": {
        "technique_id": "T1048",
        "tactic": "Exfiltration",
        "name": "Exfiltration Over Alternative Protocol",
        "description": "Adversaries may steal data by exfiltrating it over a different protocol.",
        "url": "https://attack.mitre.org/techniques/T1048/",
    },
    "T1140": {
        "technique_id": "T1140",
        "tactic": "Defense Evasion",
        "name": "Deobfuscate/Decode Files or Information",
        "description": "Adversaries may use obfuscated files or information to hide artifacts.",
        "url": "https://attack.mitre.org/techniques/T1140/",
    },
    "T1562": {
        "technique_id": "T1562",
        "tactic": "Defense Evasion",
        "name": "Impair Defenses",
        "description": "Adversaries may maliciously modify components of a victim environment.",
        "url": "https://attack.mitre.org/techniques/T1562/",
    },
    "T1098": {
        "technique_id": "T1098",
        "tactic": "Persistence",
        "name": "Account Manipulation",
        "description": "Adversaries may manipulate accounts to maintain access.",
        "url": "https://attack.mitre.org/techniques/T1098/",
    },
    "T1136": {
        "technique_id": "T1136",
        "tactic": "Persistence",
        "name": "Create Account",
        "description": "Adversaries may create an account to maintain access.",
        "url": "https://attack.mitre.org/techniques/T1136/",
    },
    "T1574": {
        "technique_id": "T1574",
        "tactic": "Persistence / Privilege Escalation / Defense Evasion",
        "name": "Hijack Execution Flow",
        "description": "Adversaries may execute their own malicious payloads by hijacking the way OS loads code.",
        "url": "https://attack.mitre.org/techniques/T1574/",
    },
    "T1068": {
        "technique_id": "T1068",
        "tactic": "Privilege Escalation",
        "name": "Exploitation for Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities to elevate privileges.",
        "url": "https://attack.mitre.org/techniques/T1068/",
    },
    "T1548": {
        "technique_id": "T1548",
        "tactic": "Privilege Escalation / Defense Evasion",
        "name": "Abuse Elevation Control Mechanism",
        "description": "Adversaries may abuse elevation control mechanisms to obtain elevated access.",
        "url": "https://attack.mitre.org/techniques/T1548/",
    },
    "T1003": {
        "technique_id": "T1003",
        "tactic": "Credential Access",
        "name": "OS Credential Dumping",
        "description": "Adversaries may attempt to dump credentials to obtain account login information.",
        "url": "https://attack.mitre.org/techniques/T1003/",
    },
    "T1552": {
        "technique_id": "T1552",
        "tactic": "Credential Access",
        "name": "Unsecured Credentials",
        "description": "Adversaries may search compromised systems to find insecurely stored credentials.",
        "url": "https://attack.mitre.org/techniques/T1552/",
    },
    "T1539": {
        "technique_id": "T1539",
        "tactic": "Credential Access",
        "name": "Steal Web Session Cookie",
        "description": "Adversaries may steal web application session cookies.",
        "url": "https://attack.mitre.org/techniques/T1539/",
    },
    "T1059.007": {
        "technique_id": "T1059.007",
        "tactic": "Execution",
        "name": "Command and Scripting Interpreter: JavaScript",
        "description": "Adversaries may abuse JavaScript for execution (XSS).",
        "url": "https://attack.mitre.org/techniques/T1059/007/",
    },
    "T1203": {
        "technique_id": "T1203",
        "tactic": "Execution",
        "name": "Exploitation for Client Execution",
        "description": "Adversaries may exploit software vulnerabilities in client applications.",
        "url": "https://attack.mitre.org/techniques/T1203/",
    },
    "T1566": {
        "technique_id": "T1566",
        "tactic": "Initial Access",
        "name": "Phishing",
        "description": "Adversaries may send phishing messages to gain access to victim systems.",
        "url": "https://attack.mitre.org/techniques/T1566/",
    },
    "T1199": {
        "technique_id": "T1199",
        "tactic": "Initial Access",
        "name": "Trusted Relationship",
        "description": "Adversaries may breach trusted third-party providers to access victim systems.",
        "url": "https://attack.mitre.org/techniques/T1199/",
    },
    "T1195": {
        "technique_id": "T1195",
        "tactic": "Initial Access",
        "name": "Supply Chain Compromise",
        "description": "Adversaries may manipulate products or delivery mechanisms before receipt.",
        "url": "https://attack.mitre.org/techniques/T1195/",
    },
    "T1485": {
        "technique_id": "T1485",
        "tactic": "Impact",
        "name": "Data Destruction",
        "description": "Adversaries may destroy data and files on specific systems.",
        "url": "https://attack.mitre.org/techniques/T1485/",
    },
    "T1486": {
        "technique_id": "T1486",
        "tactic": "Impact",
        "name": "Data Encrypted for Impact",
        "description": "Adversaries may encrypt data on target systems or storage devices to interrupt availability.",
        "url": "https://attack.mitre.org/techniques/T1486/",
    },
    "T1490": {
        "technique_id": "T1490",
        "tactic": "Impact",
        "name": "Inhibit System Recovery",
        "description": "Adversaries may delete or remove built-in operating system data for recovery.",
        "url": "https://attack.mitre.org/techniques/T1490/",
    },
    "T1498": {
        "technique_id": "T1498",
        "tactic": "Impact",
        "name": "Network Denial of Service",
        "description": "Adversaries may perform Network DoS to degrade or block availability.",
        "url": "https://attack.mitre.org/techniques/T1498/",
    },
    "T1210": {
        "technique_id": "T1210",
        "tactic": "Lateral Movement",
        "name": "Exploitation of Remote Services",
        "description": "Adversaries may exploit remote services to gain unauthorized access.",
        "url": "https://attack.mitre.org/techniques/T1210/",
    },
    "T1557": {
        "technique_id": "T1557",
        "tactic": "Credential Access / Collection",
        "name": "Adversary-in-the-Middle",
        "description": "Adversaries may intercept network traffic between hosts.",
        "url": "https://attack.mitre.org/techniques/T1557/",
    },
    "T1040": {
        "technique_id": "T1040",
        "tactic": "Credential Access / Discovery",
        "name": "Network Sniffing",
        "description": "Adversaries may sniff network traffic to capture information.",
        "url": "https://attack.mitre.org/techniques/T1040/",
    },
    "T1119": {
        "technique_id": "T1119",
        "tactic": "Collection",
        "name": "Automated Collection",
        "description": "Adversaries may use automated techniques to collect internal data.",
        "url": "https://attack.mitre.org/techniques/T1119/",
    },
    "T1213": {
        "technique_id": "T1213",
        "tactic": "Collection",
        "name": "Data from Information Repositories",
        "description": "Adversaries may leverage information repositories to mine valuable information.",
        "url": "https://attack.mitre.org/techniques/T1213/",
    },
    "T1005": {
        "technique_id": "T1005",
        "tactic": "Collection",
        "name": "Data from Local System",
        "description": "Adversaries may search local system sources to find files of interest.",
        "url": "https://attack.mitre.org/techniques/T1005/",
    },
    "T1074": {
        "technique_id": "T1074",
        "tactic": "Collection",
        "name": "Data Staged",
        "description": "Adversaries may stage collected data in a central location prior to exfiltration.",
        "url": "https://attack.mitre.org/techniques/T1074/",
    },
    "T1087": {
        "technique_id": "T1087",
        "tactic": "Discovery",
        "name": "Account Discovery",
        "description": "Adversaries may attempt to get a listing of local and/or domain accounts.",
        "url": "https://attack.mitre.org/techniques/T1087/",
    },
    "T1082": {
        "technique_id": "T1082",
        "tactic": "Discovery",
        "name": "System Information Discovery",
        "description": "Adversaries may attempt to get detailed information about the operating system.",
        "url": "https://attack.mitre.org/techniques/T1082/",
    },
}

# ---- Keyword-based automatic mapping ----
# Maps lowercase substrings in finding title/description to technique IDs
KEYWORD_TECHNIQUE_MAP = [
    # Injection attacks
    (["sql injection", "sqli", "sql error", "blind sql"], "T1190"),
    (["xss", "cross-site scripting", "javascript injection", "reflected xss", "stored xss"], "T1059.007"),
    (["command injection", "os injection", "rce", "remote code execution", "code execution"], "T1059"),
    (["xxe", "xml injection", "xml external entity"], "T1190"),
    (["server-side template injection", "ssti"], "T1190"),
    # Auth/access
    (["default credential", "default password", "weak password", "weak credential"], "T1110.001"),
    (["brute force", "password spray", "credential stuffing"], "T1110"),
    (["missing mfa", "no mfa", "multi-factor", "two-factor disabled", "2fa"], "T1078"),
    (["valid account", "default account", "anonymous access"], "T1078"),
    (["hash crack", "password hash", "cracked password", "plaintext"], "T1110.002"),
    (["ldap injection", "ldap"], "T1190"),
    # Network/services
    (["open rdp", "rdp exposed", "rdp port"], "T1021.001"),
    (["open ssh", "ssh exposed", "ssh port 22"], "T1021.004"),
    (["smb", "netbios", "windows share"], "T1021.002"),
    (["telnet", "cleartext credential", "unencrypted protocol"], "T1040"),
    (["snmp", "community string"], "T1592"),
    (["dns zone transfer", "zone transfer"], "T1596"),
    (["open port", "network scan", "port scan"], "T1046"),
    (["arp", "arp scan", "lan discovery", "host discovery"], "T1018"),
    # Web
    (["directory listing", "directory traversal", "path traversal"], "T1083"),
    (["web shell", "webshell"], "T1505.003"),
    (["sensitive file", "backup file", ".bak", ".sql", ".env", "config file"], "T1552"),
    (["ssl", "tls", "certificate expired", "weak cipher", "ssl error", "https"], "T1557"),
    (["cors", "cross-origin", "access-control-allow-origin"], "T1190"),
    (["clickjacking", "x-frame-options"], "T1190"),
    (["csrf", "cross-site request forgery"], "T1190"),
    (["information disclosure", "server header", "version disclosure"], "T1592"),
    (["cookie", "session", "set-cookie", "httponly", "secure flag"], "T1539"),
    (["file upload", "unrestricted upload"], "T1190"),
    # Vulnerability / CVE based
    (["privilege escalation", "escalation of privilege"], "T1068"),
    (["outdated", "unpatched", "end of life", "eol", "vulnerable version"], "T1190"),
    (["open redirect", "redirect"], "T1190"),
    # WHOIS / recon
    (["whois", "domain expir", "registrar"], "T1596"),
    (["subdomain", "dns record", "name server"], "T1596"),
    # Audit / hardening
    (["lynis", "hardening", "system audit", "audit warning", "audit suggestion"], "T1082"),
    (["unencrypted", "plaintext", "cleartext"], "T1040"),
]


def _auto_map_technique(title: str, description: str) -> Optional[str]:
    """Return the best-matching technique ID for a finding based on keywords."""
    haystack = (title + " " + (description or "")).lower()
    for keywords, technique_id in KEYWORD_TECHNIQUE_MAP:
        if any(kw in haystack for kw in keywords):
            return technique_id
    return None


# ---- Pydantic models ----
class MapFindingRequest(BaseModel):
    finding_id: uuid.UUID
    technique_id: str
    auto_map: bool = False  # if True, auto-detect and override


@router.get("/techniques")
async def list_techniques(
    current_user: User = Depends(get_current_user),
):
    """Return the full ATT&CK technique list."""
    return {
        "total": len(ATTACK_TECHNIQUES),
        "techniques": sorted(ATTACK_TECHNIQUES.values(), key=lambda t: t["technique_id"]),
    }


@router.get("/coverage")
async def get_mitre_coverage(
    org_id: Optional[uuid.UUID] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return which ATT&CK techniques are covered by open findings for the org."""
    effective_org_id = org_id or current_user.org_id

    result = await db.execute(
        select(
            Finding.mitre_technique,
            func.count(Finding.id).label("finding_count"),
        )
        .where(
            and_(
                Finding.org_id == effective_org_id,
                Finding.mitre_technique.isnot(None),
                Finding.status.notin_(["false_positive", "resolved"]),
            )
        )
        .group_by(Finding.mitre_technique)
    )

    covered = {}
    for row in result.all():
        tid = row.mitre_technique
        technique = ATTACK_TECHNIQUES.get(tid, {
            "technique_id": tid,
            "tactic": "Unknown",
            "name": tid,
        })
        covered[tid] = {
            **technique,
            "finding_count": row.finding_count,
        }

    # Group by tactic
    by_tactic = {}
    for tid, tech in covered.items():
        tactic = tech["tactic"]
        if tactic not in by_tactic:
            by_tactic[tactic] = []
        by_tactic[tactic].append(tech)

    return {
        "org_id": str(effective_org_id),
        "covered_technique_count": len(covered),
        "total_technique_count": len(ATTACK_TECHNIQUES),
        "coverage_percent": round(len(covered) / len(ATTACK_TECHNIQUES) * 100, 1),
        "techniques": list(covered.values()),
        "by_tactic": by_tactic,
    }


@router.post("/map-finding")
async def map_finding_to_technique(
    request: MapFindingRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Assign a MITRE ATT&CK technique to a finding (manual or auto-detected)."""
    result = await db.execute(
        select(Finding).where(
            Finding.id == request.finding_id,
            Finding.org_id == current_user.org_id,
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if request.auto_map:
        technique_id = _auto_map_technique(finding.title, finding.description or "")
        if not technique_id:
            raise HTTPException(
                status_code=422,
                detail="Could not auto-map this finding to any ATT&CK technique. Provide technique_id manually.",
            )
    else:
        technique_id = request.technique_id

    if technique_id not in ATTACK_TECHNIQUES:
        # Allow unknown/custom technique IDs but warn
        technique_info = {
            "technique_id": technique_id,
            "name": "Custom/Unknown Technique",
            "tactic": "Unknown",
        }
    else:
        technique_info = ATTACK_TECHNIQUES[technique_id]

    finding.mitre_technique = technique_id
    await db.commit()
    await db.refresh(finding)

    return {
        "finding_id": str(finding.id),
        "technique": technique_info,
        "auto_mapped": request.auto_map,
    }


from pydantic import BaseModel as _BaseModel


class SimulateRequest(_BaseModel):
    technique_id: str


@router.post("/simulate")
async def simulate_technique(
    request: SimulateRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Simulate running an atomic test for a MITRE ATT&CK technique.
    Returns pass/fail outcome with detection notes.
    """
    tech = ATTACK_TECHNIQUES.get(request.technique_id)
    if not tech:
        raise HTTPException(status_code=404, detail=f"Technique {request.technique_id} not found")

    import random
    detected = random.random() > 0.45  # ~55% detection rate

    DETECTION_NOTES = {
        "T1110": "Brute force detected via failed login threshold alerts",
        "T1190": "Exploit attempt blocked by WAF / IDS signature",
        "T1059": "Command execution flagged by EDR process monitoring",
        "T1078": "Valid credential use from unusual geolocation detected",
        "T1046": "Port scan detected via network flow anomaly detection",
        "T1083": "File enumeration flagged by file integrity monitoring",
        "T1486": "Ransomware encryption pattern detected by honeypot files",
        "T1041": "Data exfiltration detected via DLP on egress traffic",
        "T1055": "Process injection flagged by EDR memory scanning",
        "T1548": "Privilege escalation attempt detected by UEBA",
    }

    note = DETECTION_NOTES.get(request.technique_id[:5], "Simulation complete — review SIEM alerts for detection status")

    return {
        "technique_id": request.technique_id,
        "technique_name": tech.get("name"),
        "tactic": tech.get("tactic"),
        "detected": detected,
        "result": "DETECTED" if detected else "NOT DETECTED",
        "detection_note": note if detected else "No detection triggered — consider tuning detection rules for this technique",
        "simulated": True,
    }
