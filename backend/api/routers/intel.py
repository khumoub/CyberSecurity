import uuid
from typing import Optional
import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, case
from core.database import get_db
from core.security import get_current_user
from core.config import settings
from models.finding import Finding
from models.asset import Asset
from models.user import User

router = APIRouter()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOIT_DB_BASE = "https://www.exploit-db.com/search"

# Severity weights for risk score calculation
SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 0.5,
    "info": 0.0,
}


@router.get("/cisa-kev")
async def get_cisa_kev(
    org_id: Optional[uuid.UUID] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return paginated CISA KEV (Known Exploited Vulnerabilities) findings for the org."""
    effective_org_id = org_id or current_user.org_id

    filters = [
        Finding.org_id == effective_org_id,
        Finding.is_known_exploited == True,
    ]

    count_result = await db.execute(
        select(func.count(Finding.id)).where(and_(*filters))
    )
    total = count_result.scalar_one()

    result = await db.execute(
        select(Finding)
        .where(and_(*filters))
        .order_by(Finding.created_at.desc())
        .offset((page - 1) * limit)
        .limit(limit)
    )
    findings = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "items": [
            {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "cve_id": f.cve_id,
                "cvss_score": f.cvss_score,
                "affected_component": f.affected_component,
                "status": f.status,
                "created_at": f.created_at.isoformat(),
            }
            for f in findings
        ],
    }


@router.get("/nvd/cve/{cve_id}")
async def get_nvd_cve(
    cve_id: str,
    current_user: User = Depends(get_current_user),
):
    """Fetch CVE detail from NVD API 2.0."""
    headers = {"Accept": "application/json"}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.get(
                NVD_API_BASE,
                params={"cveId": cve_id.upper()},
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=e.response.status_code,
                detail=f"NVD API error: {e.response.text[:500]}",
            )
        except httpx.RequestError as e:
            raise HTTPException(status_code=503, detail=f"NVD API unreachable: {str(e)}")

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found in NVD")

    cve_item = vulnerabilities[0].get("cve", {})
    cve_id_str = cve_item.get("id", cve_id)

    # Extract CVSS scores
    metrics = cve_item.get("metrics", {})
    cvss_v3 = None
    cvss_v2 = None

    for entry in metrics.get("cvssMetricV31", []) + metrics.get("cvssMetricV30", []):
        cvss_data = entry.get("cvssData", {})
        cvss_v3 = {
            "version": cvss_data.get("version"),
            "vector": cvss_data.get("vectorString"),
            "base_score": cvss_data.get("baseScore"),
            "base_severity": cvss_data.get("baseSeverity"),
            "exploitability_score": entry.get("exploitabilityScore"),
            "impact_score": entry.get("impactScore"),
        }
        break

    for entry in metrics.get("cvssMetricV2", []):
        cvss_data = entry.get("cvssData", {})
        cvss_v2 = {
            "version": "2.0",
            "vector": cvss_data.get("vectorString"),
            "base_score": cvss_data.get("baseScore"),
            "base_severity": entry.get("baseSeverity"),
        }
        break

    # Extract descriptions
    descriptions = {
        d["lang"]: d["value"]
        for d in cve_item.get("descriptions", [])
    }

    # Extract weaknesses (CWE)
    weaknesses = []
    for w in cve_item.get("weaknesses", []):
        for desc in w.get("description", []):
            if desc.get("lang") == "en":
                weaknesses.append(desc.get("value"))

    # Extract references
    references = [
        {"url": ref.get("url"), "tags": ref.get("tags", [])}
        for ref in cve_item.get("references", [])[:20]
    ]

    # Configurations / affected products
    configurations = cve_item.get("configurations", [])
    affected_products = []
    for config in configurations[:5]:
        for node in config.get("nodes", [])[:5]:
            for cpe_match in node.get("cpeMatch", [])[:5]:
                if cpe_match.get("vulnerable"):
                    affected_products.append(cpe_match.get("criteria", ""))

    return {
        "cve_id": cve_id_str,
        "description": descriptions.get("en", "No description available"),
        "published": cve_item.get("published"),
        "last_modified": cve_item.get("lastModified"),
        "vuln_status": cve_item.get("vulnStatus"),
        "cvss_v3": cvss_v3,
        "cvss_v2": cvss_v2,
        "weaknesses": weaknesses,
        "references": references,
        "affected_products": affected_products[:20],
    }


@router.get("/exploit-db/search")
async def search_exploitdb(
    query: str = Query(..., min_length=1),
    current_user: User = Depends(get_current_user),
):
    """Search ExploitDB for public exploits matching a CVE or keyword."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            params = {"json": "true"}
            # If looks like a CVE, search by CVE; otherwise text search
            if query.upper().startswith("CVE-"):
                params["cve"] = query.upper()
            else:
                params["description"] = query

            resp = await client.get(
                EXPLOIT_DB_BASE,
                params=params,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Leruo-Security-Platform/1.0",
                },
                follow_redirects=True,
            )
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=e.response.status_code,
                detail=f"ExploitDB API error: {e.response.text[:500]}",
            )
        except httpx.RequestError as e:
            raise HTTPException(status_code=503, detail=f"ExploitDB unreachable: {str(e)}")

    # ExploitDB returns {"data": [...], ...}
    exploits_raw = data.get("data", []) if isinstance(data, dict) else data
    exploits = []
    for item in exploits_raw[:50]:
        exploits.append({
            "id": item.get("id"),
            "title": item.get("description") or item.get("title"),
            "date": item.get("date_published") or item.get("date"),
            "author": item.get("author", {}).get("name") if isinstance(item.get("author"), dict) else item.get("author"),
            "type": item.get("type", {}).get("name") if isinstance(item.get("type"), dict) else item.get("type"),
            "platform": item.get("platform", {}).get("name") if isinstance(item.get("platform"), dict) else item.get("platform"),
            "url": f"https://www.exploit-db.com/exploits/{item.get('id')}",
            "cve": item.get("cve", {}).get("cve_id") if isinstance(item.get("cve"), dict) else item.get("cve"),
        })

    return {
        "query": query,
        "total": len(exploits),
        "results": exploits,
    }


@router.get("/risk-scores")
async def get_risk_scores(
    org_id: Optional[uuid.UUID] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return per-asset risk scores (0–100) for the organization."""
    effective_org_id = org_id or current_user.org_id

    # Aggregate finding counts per asset per severity
    result = await db.execute(
        select(
            Finding.asset_id,
            Asset.value.label("asset_value"),
            Asset.name.label("asset_name"),
            func.count(Finding.id).label("total"),
            func.sum(case((Finding.severity == "critical", 1), else_=0)).label("critical"),
            func.sum(case((Finding.severity == "high", 1), else_=0)).label("high"),
            func.sum(case((Finding.severity == "medium", 1), else_=0)).label("medium"),
            func.sum(case((Finding.severity == "low", 1), else_=0)).label("low"),
            func.sum(case((Finding.severity == "info", 1), else_=0)).label("info"),
            func.sum(case((Finding.is_known_exploited == True, 1), else_=0)).label("kev_count"),
        )
        .join(Asset, Asset.id == Finding.asset_id, isouter=True)
        .where(
            and_(
                Finding.org_id == effective_org_id,
                Finding.status.notin_(["false_positive", "resolved"]),
            )
        )
        .group_by(Finding.asset_id, Asset.value, Asset.name)
        .order_by(func.count(Finding.id).desc())
    )

    rows = result.all()
    asset_scores = []

    for row in rows:
        critical = row.critical or 0
        high = row.high or 0
        medium = row.medium or 0
        low = row.low or 0
        info = row.info or 0
        kev = row.kev_count or 0
        total = row.total or 1

        raw_score = (
            critical * SEVERITY_WEIGHTS["critical"]
            + high * SEVERITY_WEIGHTS["high"]
            + medium * SEVERITY_WEIGHTS["medium"]
            + low * SEVERITY_WEIGHTS["low"]
            + info * SEVERITY_WEIGHTS["info"]
        )

        # KEV bonus
        if kev > 0:
            raw_score *= 1 + (0.1 * min(kev, 5))

        # Normalize to 0-100 (cap at 100)
        normalized = min(100.0, (raw_score / (total * 10.0)) * 100)

        asset_scores.append({
            "asset_id": str(row.asset_id) if row.asset_id else None,
            "asset_value": row.asset_value or "Unknown",
            "asset_name": row.asset_name or "Unknown",
            "risk_score": round(normalized, 1),
            "findings": {
                "total": row.total or 0,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "info": info,
                "known_exploited": kev,
            },
        })

    return {
        "org_id": str(effective_org_id),
        "asset_scores": asset_scores,
    }


@router.post("/enrich-finding/{finding_id}")
async def enrich_finding(
    finding_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Enrich a finding with NVD CVE data and ExploitDB availability."""
    result = await db.execute(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.org_id == current_user.org_id,
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if not finding.cve_id:
        raise HTTPException(
            status_code=400,
            detail="Finding has no CVE ID. Cannot enrich without a CVE reference."
        )

    enrichment = {"cve_id": finding.cve_id, "nvd": None, "exploitdb": None}

    headers = {"Accept": "application/json"}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    async with httpx.AsyncClient(timeout=30.0) as client:
        # NVD enrichment
        try:
            nvd_resp = await client.get(
                NVD_API_BASE,
                params={"cveId": finding.cve_id.upper()},
                headers=headers,
            )
            if nvd_resp.status_code == 200:
                nvd_data = nvd_resp.json()
                vulns = nvd_data.get("vulnerabilities", [])
                if vulns:
                    cve_item = vulns[0].get("cve", {})
                    metrics = cve_item.get("metrics", {})
                    cvss_score = None
                    for entry in (
                        metrics.get("cvssMetricV31", [])
                        + metrics.get("cvssMetricV30", [])
                    ):
                        cvss_score = entry.get("cvssData", {}).get("baseScore")
                        break

                    descriptions = {
                        d["lang"]: d["value"]
                        for d in cve_item.get("descriptions", [])
                    }
                    enrichment["nvd"] = {
                        "cvss_score": cvss_score,
                        "description": descriptions.get("en"),
                        "published": cve_item.get("published"),
                        "vuln_status": cve_item.get("vulnStatus"),
                    }

                    # Update finding with CVSS score
                    if cvss_score and not finding.cvss_score:
                        finding.cvss_score = cvss_score
        except Exception as e:
            enrichment["nvd_error"] = str(e)

        # ExploitDB enrichment
        try:
            edb_resp = await client.get(
                EXPLOIT_DB_BASE,
                params={"cve": finding.cve_id.upper(), "json": "true"},
                headers={"Accept": "application/json", "User-Agent": "Leruo-Security-Platform/1.0"},
                follow_redirects=True,
            )
            if edb_resp.status_code == 200:
                edb_data = edb_resp.json()
                exploits = edb_data.get("data", []) if isinstance(edb_data, dict) else edb_data
                if exploits:
                    enrichment["exploitdb"] = {
                        "exploit_count": len(exploits),
                        "exploits": [
                            {
                                "id": e.get("id"),
                                "title": e.get("description") or e.get("title"),
                                "url": f"https://www.exploit-db.com/exploits/{e.get('id')}",
                            }
                            for e in exploits[:5]
                        ],
                    }
                    # Mark exploit_available
                    finding.exploit_available = True
        except Exception as e:
            enrichment["exploitdb_error"] = str(e)

    await db.commit()
    await db.refresh(finding)

    return {
        "finding_id": str(finding_id),
        "enrichment": enrichment,
        "updated": {
            "cvss_score": finding.cvss_score,
            "exploit_available": finding.exploit_available,
        },
    }


@router.get("/risk-heatmap")
async def get_risk_heatmap(
    org_id: Optional[uuid.UUID] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return asset risk heatmap data (likelihood x impact) for chart rendering."""
    from services.risk_scoring import RiskScoringService
    effective_org_id = str(org_id or current_user.org_id)
    svc = RiskScoringService()
    return {"heatmap": await svc.get_risk_heatmap_data(effective_org_id, db)}


@router.get("/patch-priority")
async def get_patch_priority(
    org_id: Optional[uuid.UUID] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return AI-ranked patch priority queue (top 25 findings)."""
    from services.risk_scoring import RiskScoringService
    effective_org_id = str(org_id or current_user.org_id)
    svc = RiskScoringService()
    priority = await svc.get_patch_priority(effective_org_id, db)
    return {"items": priority, "total": len(priority)}


@router.get("/patch-priority-ai")
async def get_patch_priority_ai(
    org_id: Optional[uuid.UUID] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """AI-ranked patch priority queue using Claude API for contextual recommendations."""
    from services.risk_scoring import RiskScoringService
    from services.claude_service import get_ai_patch_priority
    effective_org_id = str(org_id or current_user.org_id)
    svc = RiskScoringService()
    priority = await svc.get_patch_priority(effective_org_id, db)
    # Enrich with Claude AI recommendations
    enriched = await get_ai_patch_priority(priority)
    return {"items": enriched, "total": len(enriched), "ai_powered": bool(settings.CLAUDE_API_KEY)}


@router.get("/attack-paths")
async def get_attack_paths(
    org_id: Optional[uuid.UUID] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Compute attack paths between assets based on shared findings and lateral movement potential.
    Returns a graph of nodes (assets) and edges (potential attack vectors).
    """
    effective_org_id = org_id or current_user.org_id

    # Get assets with their critical/high finding counts
    result = await db.execute(
        select(
            Asset.id,
            Asset.value,
            Asset.name,
            Asset.asset_type,
            func.count(Finding.id).label("total_findings"),
            func.sum(case((Finding.severity == "critical", 1), else_=0)).label("critical"),
            func.sum(case((Finding.severity == "high", 1), else_=0)).label("high"),
            func.sum(case((Finding.is_known_exploited == True, 1), else_=0)).label("kev"),
        )
        .join(Finding, Finding.asset_id == Asset.id, isouter=True)
        .where(Asset.org_id == effective_org_id)
        .where(Finding.status.notin_(["resolved", "false_positive"]))
        .group_by(Asset.id, Asset.value, Asset.name, Asset.asset_type)
        .order_by(func.count(Finding.id).desc())
        .limit(20)
    )
    rows = result.all()

    nodes = []
    for row in rows:
        critical = row.critical or 0
        high     = row.high or 0
        kev      = row.kev or 0
        risk     = "critical" if critical > 0 or kev > 0 else "high" if high > 0 else "medium"
        nodes.append({
            "id":           str(row.id),
            "label":        row.value or row.name or str(row.id),
            "asset_type":   row.asset_type or "unknown",
            "risk":         risk,
            "critical":     critical,
            "high":         high,
            "kev":          kev,
            "total":        row.total_findings or 0,
        })

    # Build edges: connect nodes that share CVE IDs (lateral movement potential)
    edges = []
    if len(nodes) >= 2:
        shared_cve_result = await db.execute(
            select(Finding.asset_id, Finding.cve_id)
            .where(Finding.org_id == effective_org_id)
            .where(Finding.cve_id.isnot(None))
            .where(Finding.status.notin_(["resolved", "false_positive"]))
        )
        shared_rows = shared_cve_result.all()

        cve_to_assets: dict[str, set] = {}
        for asset_id, cve_id in shared_rows:
            if cve_id:
                cve_to_assets.setdefault(cve_id, set()).add(str(asset_id))

        edge_set: set[tuple] = set()
        for cve_id, asset_ids in cve_to_assets.items():
            asset_list = list(asset_ids)
            for i in range(len(asset_list)):
                for j in range(i + 1, len(asset_list)):
                    pair = (min(asset_list[i], asset_list[j]), max(asset_list[i], asset_list[j]))
                    if pair not in edge_set:
                        edge_set.add(pair)
                        edges.append({
                            "source":  asset_list[i],
                            "target":  asset_list[j],
                            "label":   cve_id,
                            "type":    "shared_cve",
                            "weight":  1,
                        })

    return {
        "nodes": nodes,
        "edges": edges[:50],
        "summary": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "critical_nodes": sum(1 for n in nodes if n["risk"] == "critical"),
        },
    }


# ── VPR: Vulnerability Priority Rating ──────────────────────────────────────

@router.get("/vpr")
async def get_vpr_scores(
    limit: int = Query(50, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Vulnerability Priority Rating: composite score combining:
    - CVSS base score
    - EPSS score (real-world exploit probability)
    - Asset business criticality (critical_weight from asset tags/type)
    - KEV status (2x multiplier)
    - Exploit availability (1.5x multiplier)
    Normalized to 0-10.
    """
    result = await db.execute(
        select(
            Finding.id,
            Finding.title,
            Finding.severity,
            Finding.cvss_score,
            Finding.epss_score,
            Finding.is_known_exploited,
            Finding.exploit_available,
            Finding.cve_id,
            Finding.affected_component,
            Finding.status,
            Asset.name.label("asset_name"),
            Asset.asset_type,
            Asset.criticality_score,
        )
        .outerjoin(Asset, Asset.id == Finding.asset_id)
        .where(Finding.org_id == current_user.org_id)
        .where(Finding.status.notin_(["resolved", "false_positive", "accepted_risk"]))
        .limit(500)
    )
    rows = result.all()

    SEV_BASE = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 1.0}
    ASSET_CRITICALITY = {"critical": 2.0, "high": 1.5, "medium": 1.0, "low": 0.75}

    scored = []
    for row in rows:
        base = SEV_BASE.get(row.severity or "info", 1.0)
        # CVSS factor
        cvss = float(row.cvss_score or 0)
        cvss_f = (cvss / 10.0) if cvss > 0 else 0.5
        # EPSS factor
        epss = float(row.epss_score or 0)
        epss_f = 1.0 + epss * 2.0  # EPSS 0.5 = 2x multiplier
        # KEV + exploit
        kev_f = 2.0 if row.is_known_exploited else 1.0
        exploit_f = 1.5 if row.exploit_available else 1.0
        # Asset criticality
        asset_crit = getattr(row, 'criticality_score', None)
        if asset_crit:
            asset_f = min(float(asset_crit) / 5.0 + 0.5, 2.0)
        else:
            asset_type = (row.asset_type or "").lower()
            asset_f = ASSET_CRITICALITY.get(
                "critical" if "prod" in asset_type or "db" in asset_type else
                "high" if "server" in asset_type else "medium",
                1.0
            )

        raw = base * cvss_f * epss_f * kev_f * exploit_f * asset_f
        vpr = round(min(raw / 8.0, 10.0), 2)

        scored.append({
            "finding_id": str(row.id),
            "title": row.title,
            "severity": row.severity,
            "cvss_score": cvss,
            "epss_score": epss,
            "is_known_exploited": row.is_known_exploited,
            "exploit_available": row.exploit_available,
            "cve_id": row.cve_id,
            "affected_component": row.affected_component,
            "status": row.status,
            "asset_name": row.asset_name,
            "asset_type": row.asset_type,
            "vpr_score": vpr,
            "vpr_factors": {
                "cvss_factor": round(cvss_f, 2),
                "epss_factor": round(epss_f, 2),
                "kev_factor": kev_f,
                "exploit_factor": exploit_f,
                "asset_criticality_factor": round(asset_f, 2),
            },
        })

    scored.sort(key=lambda x: x["vpr_score"], reverse=True)
    return {"findings": scored[:limit], "total": len(scored)}


# ── Attack Path Chaining (Multi-hop) ────────────────────────────────────────

@router.get("/attack-path-chains")
async def get_attack_path_chains(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Multi-hop attack path analysis:
    - Builds a graph of assets connected by shared CVEs
    - Finds chains: entry point → pivot → critical target
    - Calculates chain risk score and recommends highest-impact fix
    """
    # Get all assets with their findings
    findings_result = await db.execute(
        select(Finding.asset_id, Finding.cve_id, Finding.severity, Finding.is_known_exploited, Finding.exploit_available)
        .where(Finding.org_id == current_user.org_id)
        .where(Finding.cve_id.isnot(None))
        .where(Finding.status.notin_(["resolved", "false_positive"]))
    )
    finding_rows = findings_result.all()

    assets_result = await db.execute(
        select(Asset.id, Asset.name, Asset.asset_type, Asset.ip_address)
        .where(Asset.org_id == current_user.org_id)
        .where(Asset.is_active == True)
    )
    asset_rows = {str(r.id): {"name": r.name, "type": r.asset_type, "ip": r.ip_address} for r in assets_result.all()}

    # Build adjacency via shared CVEs
    import collections
    cve_assets = collections.defaultdict(set)
    asset_vulns = collections.defaultdict(list)

    for asset_id, cve_id, severity, is_kev, has_exploit in finding_rows:
        aid = str(asset_id)
        cve_assets[cve_id].add(aid)
        asset_vulns[aid].append({
            "cve_id": cve_id, "severity": severity,
            "is_kev": is_kev, "has_exploit": has_exploit
        })

    # Build adjacency list (edges between assets sharing CVEs)
    adjacency = collections.defaultdict(list)  # asset_id -> [(neighbor_id, shared_cve)]
    for cve_id, aids in cve_assets.items():
        aids_list = list(aids)
        for i in range(len(aids_list)):
            for j in range(i + 1, len(aids_list)):
                adjacency[aids_list[i]].append((aids_list[j], cve_id))
                adjacency[aids_list[j]].append((aids_list[i], cve_id))

    SEV_SCORE = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}

    def asset_risk(aid):
        vulns = asset_vulns.get(aid, [])
        if not vulns:
            return 0
        return max(SEV_SCORE.get(v["severity"], 0) for v in vulns)

    # Find chains using BFS (max depth 4 hops)
    chains = []
    visited_chains = set()

    def bfs_chains(start, max_depth=4):
        """Find all paths from start up to max_depth hops."""
        queue = [(start, [start], [], 0)]
        while queue:
            node, path, cves, depth = queue.pop(0)
            if depth >= max_depth:
                continue
            for neighbor, cve in adjacency.get(node, []):
                if neighbor not in path:
                    new_path = path + [neighbor]
                    new_cves = cves + [cve]
                    path_key = "->".join(sorted(new_path))
                    if path_key not in visited_chains and len(new_path) >= 2:
                        visited_chains.add(path_key)
                        chain_risk = sum(asset_risk(n) for n in new_path)
                        chains.append({
                            "path": new_path,
                            "path_labels": [asset_rows.get(n, {}).get("name", n) for n in new_path],
                            "shared_cves": new_cves,
                            "hop_count": len(new_path) - 1,
                            "chain_risk_score": chain_risk,
                            "entry_point": asset_rows.get(new_path[0], {}).get("name", new_path[0]),
                            "target": asset_rows.get(new_path[-1], {}).get("name", new_path[-1]),
                            "has_kev": any(
                                v["is_kev"] for aid in new_path
                                for v in asset_vulns.get(aid, [])
                                if v["cve_id"] in new_cves
                            ),
                        })
                    queue.append((neighbor, new_path, new_cves, depth + 1))

    # Start BFS from each asset (limit to top 15 by risk)
    sorted_assets = sorted(asset_vulns.keys(), key=asset_risk, reverse=True)[:15]
    for start_asset in sorted_assets:
        bfs_chains(start_asset)

    # Sort chains by risk score + hop count
    chains.sort(key=lambda c: (c["chain_risk_score"], c["hop_count"]), reverse=True)
    top_chains = chains[:20]

    # Identify the single most impactful CVE fix (breaks the most chains)
    cve_chain_count = collections.Counter()
    for chain in top_chains:
        for cve in chain["shared_cves"]:
            cve_chain_count[cve] += 1
    top_fix = cve_chain_count.most_common(1)
    recommended_fix = {
        "cve_id": top_fix[0][0],
        "chains_broken": top_fix[0][1],
        "message": f"Fixing {top_fix[0][0]} would break {top_fix[0][1]} attack path(s)"
    } if top_fix else None

    return {
        "chains": top_chains,
        "total_chains": len(chains),
        "max_hop_count": max((c["hop_count"] for c in chains), default=0),
        "recommended_fix": recommended_fix,
        "assets_analyzed": len(sorted_assets),
    }
