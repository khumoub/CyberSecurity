"""
Scheduled Scan Policies
- CRUD for scan policies with cron expressions
- Each policy defines: target assets/groups, tools, schedule, options
- Celery beat picks up active policies and fires scans
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, List
import uuid
import json
import psycopg2
from datetime import datetime, timezone
from core.security import get_current_user
from core.config import settings
from models.user import User

router = APIRouter()


# ── Pydantic Models ─────────────────────────────────────────────────────────

class ScanPolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    cron_expression: str = Field(..., description="Cron expression e.g. '0 2 * * *' (daily at 2am)")
    tools: List[str] = Field(..., description="List of tool names: nmap, nuclei, nikto, etc.")
    asset_ids: Optional[List[str]] = None
    asset_tags: Optional[List[str]] = None
    scan_all_assets: bool = False
    tool_options: Optional[dict] = None
    enabled: bool = True
    notify_email: Optional[str] = None


class ScanPolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    cron_expression: Optional[str] = None
    tools: Optional[List[str]] = None
    asset_ids: Optional[List[str]] = None
    asset_tags: Optional[List[str]] = None
    scan_all_assets: Optional[bool] = None
    tool_options: Optional[dict] = None
    enabled: Optional[bool] = None
    notify_email: Optional[str] = None


VALID_CRON_PRESETS = {
    "hourly": "0 * * * *",
    "daily": "0 2 * * *",
    "weekly": "0 2 * * 1",
    "monthly": "0 2 1 * *",
    "twice_daily": "0 6,18 * * *",
}

VALID_TOOLS = {
    "nmap", "nuclei", "nikto", "masscan", "gobuster", "wfuzz",
    "sslscan", "whatweb", "headers", "subdomain-enum", "dns-analysis",
    "whois", "wpscan", "credentialed-scan",
}


def _get_conn():
    return psycopg2.connect(settings.DATABASE_URL_SYNC)


def _ensure_table():
    """Create scan_policies table if not exists."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_policies (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL,
            created_by UUID NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            cron_expression TEXT NOT NULL,
            tools JSONB NOT NULL DEFAULT '[]',
            asset_ids JSONB,
            asset_tags JSONB,
            scan_all_assets BOOLEAN DEFAULT FALSE,
            tool_options JSONB,
            enabled BOOLEAN DEFAULT TRUE,
            notify_email TEXT,
            last_run_at TIMESTAMPTZ,
            next_run_at TIMESTAMPTZ,
            run_count INTEGER DEFAULT 0,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    conn.commit()
    cur.close()
    conn.close()


def _cron_to_next_run(cron_expr: str) -> Optional[str]:
    """Calculate next run time from cron expression using croniter if available."""
    try:
        from croniter import croniter
        from datetime import datetime
        base = datetime.now()
        cron = croniter(cron_expr, base)
        return cron.get_next(datetime).isoformat()
    except ImportError:
        return None
    except Exception:
        return None


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/", response_model=list)
async def list_policies(current_user: User = Depends(get_current_user)):
    _ensure_table()
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        """SELECT id, name, description, cron_expression, tools, asset_ids,
                  asset_tags, scan_all_assets, enabled, notify_email,
                  last_run_at, next_run_at, run_count, created_at
           FROM scan_policies WHERE org_id = %s ORDER BY created_at DESC""",
        (str(current_user.org_id),)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    cols = ["id", "name", "description", "cron_expression", "tools", "asset_ids",
            "asset_tags", "scan_all_assets", "enabled", "notify_email",
            "last_run_at", "next_run_at", "run_count", "created_at"]
    return [dict(zip(cols, r)) for r in rows]


@router.post("/", response_model=dict, status_code=status.HTTP_201_CREATED)
async def create_policy(
    body: ScanPolicyCreate,
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Admin or analyst role required")

    # Resolve cron preset
    cron = VALID_CRON_PRESETS.get(body.cron_expression, body.cron_expression)

    # Validate tools
    invalid = set(body.tools) - VALID_TOOLS
    if invalid:
        raise HTTPException(status_code=400, detail=f"Unknown tools: {invalid}. Valid: {VALID_TOOLS}")

    if not body.asset_ids and not body.asset_tags and not body.scan_all_assets:
        raise HTTPException(status_code=400, detail="Specify asset_ids, asset_tags, or set scan_all_assets=true")

    _ensure_table()
    next_run = _cron_to_next_run(cron)
    policy_id = str(uuid.uuid4())

    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO scan_policies
           (id, org_id, created_by, name, description, cron_expression,
            tools, asset_ids, asset_tags, scan_all_assets, tool_options,
            enabled, notify_email, next_run_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (
            policy_id,
            str(current_user.org_id),
            str(current_user.id),
            body.name,
            body.description,
            cron,
            json.dumps(body.tools),
            json.dumps(body.asset_ids) if body.asset_ids else None,
            json.dumps(body.asset_tags) if body.asset_tags else None,
            body.scan_all_assets,
            json.dumps(body.tool_options) if body.tool_options else None,
            body.enabled,
            body.notify_email,
            next_run,
        )
    )
    conn.commit()
    cur.close()
    conn.close()

    return {
        "id": policy_id,
        "name": body.name,
        "cron_expression": cron,
        "tools": body.tools,
        "enabled": body.enabled,
        "next_run_at": next_run,
        "message": "Scan policy created",
    }


@router.get("/{policy_id}", response_model=dict)
async def get_policy(policy_id: str, current_user: User = Depends(get_current_user)):
    _ensure_table()
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        """SELECT id, name, description, cron_expression, tools, asset_ids,
                  asset_tags, scan_all_assets, tool_options, enabled, notify_email,
                  last_run_at, next_run_at, run_count, created_at, updated_at
           FROM scan_policies WHERE id = %s AND org_id = %s""",
        (policy_id, str(current_user.org_id))
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found")
    cols = ["id", "name", "description", "cron_expression", "tools", "asset_ids",
            "asset_tags", "scan_all_assets", "tool_options", "enabled", "notify_email",
            "last_run_at", "next_run_at", "run_count", "created_at", "updated_at"]
    return dict(zip(cols, row))


@router.patch("/{policy_id}", response_model=dict)
async def update_policy(
    policy_id: str,
    body: ScanPolicyUpdate,
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Admin or analyst role required")

    _ensure_table()
    updates = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.description is not None:
        updates["description"] = body.description
    if body.cron_expression is not None:
        cron = VALID_CRON_PRESETS.get(body.cron_expression, body.cron_expression)
        updates["cron_expression"] = cron
        next_run = _cron_to_next_run(cron)
        if next_run:
            updates["next_run_at"] = next_run
    if body.tools is not None:
        updates["tools"] = json.dumps(body.tools)
    if body.asset_ids is not None:
        updates["asset_ids"] = json.dumps(body.asset_ids)
    if body.asset_tags is not None:
        updates["asset_tags"] = json.dumps(body.asset_tags)
    if body.scan_all_assets is not None:
        updates["scan_all_assets"] = body.scan_all_assets
    if body.tool_options is not None:
        updates["tool_options"] = json.dumps(body.tool_options)
    if body.enabled is not None:
        updates["enabled"] = body.enabled
    if body.notify_email is not None:
        updates["notify_email"] = body.notify_email

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    updates["updated_at"] = "NOW()"
    set_clause = ", ".join(
        f"{k} = %s" if v != "NOW()" else f"{k} = NOW()"
        for k, v in updates.items()
    )
    values = [v for v in updates.values() if v != "NOW()"]

    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        f"UPDATE scan_policies SET {set_clause} WHERE id = %s AND org_id = %s",
        values + [policy_id, str(current_user.org_id)]
    )
    conn.commit()
    cur.close()
    conn.close()
    return {"id": policy_id, "updated": True}


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(policy_id: str, current_user: User = Depends(get_current_user)):
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Admin or analyst role required")

    _ensure_table()
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM scan_policies WHERE id = %s AND org_id = %s",
        (policy_id, str(current_user.org_id))
    )
    conn.commit()
    cur.close()
    conn.close()


@router.post("/{policy_id}/run-now", response_model=dict)
async def run_policy_now(policy_id: str, current_user: User = Depends(get_current_user)):
    """Manually trigger a policy run immediately."""
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Admin or analyst role required")

    _ensure_table()
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        """SELECT tools, asset_ids, scan_all_assets, tool_options
           FROM scan_policies WHERE id = %s AND org_id = %s AND enabled = TRUE""",
        (policy_id, str(current_user.org_id))
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Policy not found or disabled")

    tools, asset_ids_json, scan_all, tool_options_json = row

    # Resolve asset targets
    if scan_all:
        cur.execute("SELECT id, value, name FROM assets WHERE org_id = %s AND is_active = TRUE", (str(current_user.org_id),))
        assets = cur.fetchall()
    elif asset_ids_json:
        asset_ids = json.loads(asset_ids_json) if isinstance(asset_ids_json, str) else asset_ids_json
        placeholders = ",".join(["%s"] * len(asset_ids))
        cur.execute(f"SELECT id, value, name FROM assets WHERE id IN ({placeholders})", asset_ids)
        assets = cur.fetchall()
    else:
        assets = []

    cur.close()
    conn.close()

    tool_options = json.loads(tool_options_json) if isinstance(tool_options_json, str) and tool_options_json else {}
    tool_list = json.loads(tools) if isinstance(tools, str) else tools

    scan_ids = []
    from api.routers.tools import _dispatch_task

    TOOL_TASK_MAP = {
        "nmap": "worker.tasks.nmap_task.run_nmap",
        "nuclei": "worker.tasks.nuclei_task.run_nuclei",
        "nikto": "worker.tasks.nikto_task.run_nikto",
        "masscan": "worker.tasks.masscan_task.run_masscan",
        "sslscan": "worker.tasks.ssl_task.run_sslscan",
        "whatweb": "worker.tasks.whatweb_task.run_whatweb",
        "headers": "worker.tasks.headers_task.check_headers",
        "gobuster": "worker.tasks.gobuster_task.run_gobuster",
        "wfuzz": "worker.tasks.wfuzz_task.run_wfuzz",
        "wpscan": "worker.tasks.wpscan_task.run_wpscan",
        "subdomain-enum": "worker.tasks.subdomain_task.run_subdomain_enum",
        "dns-analysis": "worker.tasks.dns_task.run_dns_analysis",
        "credentialed-scan": "worker.tasks.credentialed_scan_task.run_credentialed_scan",
    }

    for asset_id, ip, hostname in assets:
        target = ip or hostname
        if not target:
            continue
        for tool in tool_list:
            task_name = TOOL_TASK_MAP.get(tool)
            if task_name:
                sid = _dispatch_task(task_name, str(current_user.org_id), str(asset_id), target, tool_options)
                scan_ids.append(sid)

    # Update last_run_at
    conn2 = _get_conn()
    cur2 = conn2.cursor()
    cur2.execute(
        "UPDATE scan_policies SET last_run_at = NOW(), run_count = run_count + 1 WHERE id = %s",
        (policy_id,)
    )
    conn2.commit()
    cur2.close()
    conn2.close()

    return {
        "policy_id": policy_id,
        "scan_ids": scan_ids,
        "scans_launched": len(scan_ids),
        "message": f"Policy triggered: {len(scan_ids)} scans launched",
    }


@router.get("/presets/list", response_model=dict)
async def list_presets():
    """Return available cron presets and valid tool names."""
    return {
        "cron_presets": VALID_CRON_PRESETS,
        "valid_tools": sorted(VALID_TOOLS),
    }
