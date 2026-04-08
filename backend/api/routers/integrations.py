"""
Integrations Router
- Jira: create/sync issues from findings, OAuth token storage
- Slack: webhook-based finding alerts
- Splunk/Elastic: log forwarding (future)
"""
import json
import hashlib
import base64
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
import psycopg2
import httpx
from core.security import get_current_user
from core.config import settings
from models.user import User

router = APIRouter()


# ── DB helpers ────────────────────────────────────────────────────────────────

def _get_conn():
    return psycopg2.connect(settings.DATABASE_URL_SYNC)


def _ensure_integrations_table():
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS integrations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL,
            integration_type TEXT NOT NULL,
            config JSONB NOT NULL DEFAULT '{}',
            enabled BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE (org_id, integration_type)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS jira_issue_links (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL,
            finding_id UUID NOT NULL,
            jira_issue_key TEXT NOT NULL,
            jira_issue_url TEXT,
            jira_status TEXT,
            last_synced_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE (org_id, finding_id)
        )
    """)
    conn.commit()
    cur.close()
    conn.close()


def _get_integration_config(org_id: str, integration_type: str) -> Optional[dict]:
    _ensure_integrations_table()
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT config FROM integrations WHERE org_id = %s AND integration_type = %s AND enabled = TRUE",
        (org_id, integration_type)
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return None
    cfg = row[0]
    return cfg if isinstance(cfg, dict) else json.loads(cfg)


# ── Pydantic Models ───────────────────────────────────────────────────────────

class JiraConfig(BaseModel):
    base_url: str  # e.g. https://yourorg.atlassian.net
    email: str
    api_token: str
    project_key: str
    issue_type: str = "Bug"
    default_priority_map: Optional[dict] = None  # severity -> Jira priority name


class SlackConfig(BaseModel):
    webhook_url: str
    channel: Optional[str] = None
    severity_threshold: str = "high"  # only alert on this severity+
    mention_on_critical: Optional[str] = None  # Slack user ID to @mention


class JiraIssueCreate(BaseModel):
    finding_id: str
    summary_override: Optional[str] = None
    assignee: Optional[str] = None
    custom_fields: Optional[dict] = None


class JiraIssueBulk(BaseModel):
    finding_ids: List[str]
    assignee: Optional[str] = None


class SlackAlertRequest(BaseModel):
    finding_id: str


# ── Jira Endpoints ────────────────────────────────────────────────────────────

@router.get("/jira/config")
async def get_jira_config(current_user: User = Depends(get_current_user)):
    """Get current Jira configuration (token masked)."""
    cfg = _get_integration_config(str(current_user.org_id), "jira")
    if not cfg:
        return {"configured": False}
    safe_cfg = {k: v for k, v in cfg.items() if k != "api_token"}
    safe_cfg["api_token"] = "***" + cfg.get("api_token", "")[-4:]
    safe_cfg["configured"] = True
    return safe_cfg


@router.put("/jira/config")
async def save_jira_config(body: JiraConfig, current_user: User = Depends(get_current_user)):
    """Save or update Jira integration configuration."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    _ensure_integrations_table()
    config_data = body.dict()

    # Verify credentials before saving
    auth = base64.b64encode(f"{body.email}:{body.api_token}".encode()).decode()
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{body.base_url.rstrip('/')}/rest/api/3/myself",
                headers={"Authorization": f"Basic {auth}", "Accept": "application/json"}
            )
            if resp.status_code != 200:
                raise HTTPException(status_code=400, detail=f"Jira authentication failed: {resp.status_code}")
    except httpx.RequestError as e:
        raise HTTPException(status_code=400, detail=f"Could not connect to Jira: {e}")

    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO integrations (org_id, integration_type, config)
           VALUES (%s, 'jira', %s)
           ON CONFLICT (org_id, integration_type)
           DO UPDATE SET config = EXCLUDED.config, updated_at = NOW()""",
        (str(current_user.org_id), json.dumps(config_data))
    )
    conn.commit()
    cur.close()
    conn.close()
    return {"message": "Jira integration configured successfully"}


@router.post("/jira/issues", response_model=dict, status_code=status.HTTP_201_CREATED)
async def create_jira_issue(body: JiraIssueCreate, current_user: User = Depends(get_current_user)):
    """Create a Jira issue from a finding."""
    cfg = _get_integration_config(str(current_user.org_id), "jira")
    if not cfg:
        raise HTTPException(status_code=400, detail="Jira not configured. Go to Integrations → Jira to set up.")

    # Fetch finding
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        """SELECT f.id, f.title, f.description, f.severity, f.cve_id,
                  f.affected_component, f.affected_port, f.remediation,
                  a.name, a.value
           FROM findings f LEFT JOIN assets a ON a.id = f.asset_id
           WHERE f.id = %s AND f.org_id = %s""",
        (body.finding_id, str(current_user.org_id))
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    fid, ftitle, fdesc, fsev, fcve, fcomp, fport, frem, hostname, ip = row
    asset_label = hostname or ip or "unknown"

    PRIORITY_MAP = cfg.get("default_priority_map") or {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest",
    }
    priority = PRIORITY_MAP.get(fsev, "Medium")
    summary = body.summary_override or f"[{fsev.upper()}] {ftitle} on {asset_label}"
    cve_label = f"\n\n*CVE:* {fcve}" if fcve else ""
    port_label = f"\n*Port:* {fport}" if fport else ""
    description_body = {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": fdesc or ""}]},
            {"type": "paragraph", "content": [{"type": "text", "text": f"*Asset:* {asset_label}{port_label}{cve_label}"}]},
            {"type": "paragraph", "content": [{"type": "text", "text": f"*Remediation:* {frem or 'See finding details'}"}]},
            {"type": "paragraph", "content": [{"type": "text", "text": f"*Severity:* {fsev.upper()} | Created by Leruo Security Platform"}]},
        ]
    }

    payload = {
        "fields": {
            "project": {"key": cfg["project_key"]},
            "summary": summary[:255],
            "description": description_body,
            "issuetype": {"name": cfg.get("issue_type", "Bug")},
            "priority": {"name": priority},
            "labels": ["leruo-security", f"severity-{fsev}", "vulnerability"],
        }
    }
    if body.assignee:
        payload["fields"]["assignee"] = {"id": body.assignee}
    if body.custom_fields:
        payload["fields"].update(body.custom_fields)

    auth = base64.b64encode(f"{cfg['email']}:{cfg['api_token']}".encode()).decode()
    base_url = cfg["base_url"].rstrip("/")

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{base_url}/rest/api/3/issue",
                headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
                json=payload
            )
            if resp.status_code not in (200, 201):
                raise HTTPException(status_code=400, detail=f"Jira error: {resp.text[:300]}")

            issue_data = resp.json()
            issue_key = issue_data["key"]
            issue_url = f"{base_url}/browse/{issue_key}"

        # Store the link
        conn2 = _get_conn()
        cur2 = conn2.cursor()
        cur2.execute(
            """INSERT INTO jira_issue_links (org_id, finding_id, jira_issue_key, jira_issue_url, jira_status)
               VALUES (%s, %s, %s, %s, 'Open')
               ON CONFLICT (org_id, finding_id)
               DO UPDATE SET jira_issue_key = EXCLUDED.jira_issue_key,
                             jira_issue_url = EXCLUDED.jira_issue_url,
                             last_synced_at = NOW()""",
            (str(current_user.org_id), body.finding_id, issue_key, issue_url)
        )
        conn2.commit()
        cur2.close()
        conn2.close()

        return {"issue_key": issue_key, "issue_url": issue_url, "summary": summary}

    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Jira request failed: {e}")


@router.post("/jira/issues/bulk", response_model=dict)
async def create_jira_issues_bulk(body: JiraIssueBulk, current_user: User = Depends(get_current_user)):
    """Create Jira issues for multiple findings at once."""
    results = []
    errors = []
    for finding_id in body.finding_ids[:20]:  # cap at 20
        try:
            result = await create_jira_issue(
                JiraIssueCreate(finding_id=finding_id, assignee=body.assignee),
                current_user
            )
            results.append(result)
        except HTTPException as e:
            errors.append({"finding_id": finding_id, "error": e.detail})
    return {"created": results, "errors": errors, "total": len(results)}


@router.get("/jira/issues")
async def list_jira_issues(current_user: User = Depends(get_current_user)):
    """List all findings that have been linked to Jira issues."""
    _ensure_integrations_table()
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        """SELECT j.finding_id, j.jira_issue_key, j.jira_issue_url, j.jira_status, j.last_synced_at,
                  f.title, f.severity
           FROM jira_issue_links j
           JOIN findings f ON f.id = j.finding_id
           WHERE j.org_id = %s
           ORDER BY j.last_synced_at DESC""",
        (str(current_user.org_id),)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    cols = ["finding_id", "jira_issue_key", "jira_issue_url", "jira_status",
            "last_synced_at", "finding_title", "severity"]
    return [dict(zip(cols, r)) for r in rows]


@router.post("/jira/sync/{finding_id}", response_model=dict)
async def sync_jira_status(finding_id: str, current_user: User = Depends(get_current_user)):
    """Sync Jira issue status back to finding."""
    cfg = _get_integration_config(str(current_user.org_id), "jira")
    if not cfg:
        raise HTTPException(status_code=400, detail="Jira not configured")

    _ensure_integrations_table()
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT jira_issue_key FROM jira_issue_links WHERE finding_id = %s AND org_id = %s",
        (finding_id, str(current_user.org_id))
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="No Jira issue linked to this finding")

    issue_key = row[0]
    auth = base64.b64encode(f"{cfg['email']}:{cfg['api_token']}".encode()).decode()
    base_url = cfg["base_url"].rstrip("/")

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{base_url}/rest/api/3/issue/{issue_key}?fields=status,resolution",
                headers={"Authorization": f"Basic {auth}"}
            )
            if resp.status_code != 200:
                raise HTTPException(status_code=400, detail=f"Jira sync failed: {resp.status_code}")

            data = resp.json()
            jira_status = data["fields"]["status"]["name"]

        # Update the link
        conn2 = _get_conn()
        cur2 = conn2.cursor()
        cur2.execute(
            "UPDATE jira_issue_links SET jira_status = %s, last_synced_at = NOW() WHERE finding_id = %s",
            (jira_status, finding_id)
        )
        # If Jira is Done/Resolved, mark finding as resolved
        if jira_status.lower() in ("done", "resolved", "closed"):
            cur2.execute(
                "UPDATE findings SET status = 'resolved', resolved_at = NOW() WHERE id = %s",
                (finding_id,)
            )
        conn2.commit()
        cur2.close()
        conn2.close()

        return {"finding_id": finding_id, "jira_issue_key": issue_key, "jira_status": jira_status}

    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Jira request failed: {e}")


# ── Slack Endpoints ───────────────────────────────────────────────────────────

@router.put("/slack/config")
async def save_slack_config(body: SlackConfig, current_user: User = Depends(get_current_user)):
    """Save Slack webhook integration."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    # Verify webhook
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.post(body.webhook_url, json={"text": "Leruo Security Platform connected successfully."})
            if resp.status_code != 200:
                raise HTTPException(status_code=400, detail=f"Slack webhook test failed: {resp.text}")
    except httpx.RequestError as e:
        raise HTTPException(status_code=400, detail=f"Could not reach Slack webhook: {e}")

    _ensure_integrations_table()
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO integrations (org_id, integration_type, config)
           VALUES (%s, 'slack', %s)
           ON CONFLICT (org_id, integration_type)
           DO UPDATE SET config = EXCLUDED.config, updated_at = NOW()""",
        (str(current_user.org_id), json.dumps(body.dict()))
    )
    conn.commit()
    cur.close()
    conn.close()
    return {"message": "Slack integration configured successfully"}


@router.get("/slack/config")
async def get_slack_config(current_user: User = Depends(get_current_user)):
    """Get Slack config (webhook URL masked)."""
    cfg = _get_integration_config(str(current_user.org_id), "slack")
    if not cfg:
        return {"configured": False}
    return {
        "configured": True,
        "channel": cfg.get("channel"),
        "severity_threshold": cfg.get("severity_threshold", "high"),
        "webhook_url": "***" + cfg.get("webhook_url", "")[-8:],
    }


@router.post("/slack/alert", response_model=dict)
async def send_slack_alert(body: SlackAlertRequest, current_user: User = Depends(get_current_user)):
    """Manually send a Slack alert for a finding."""
    cfg = _get_integration_config(str(current_user.org_id), "slack")
    if not cfg:
        raise HTTPException(status_code=400, detail="Slack not configured")

    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        """SELECT f.title, f.severity, f.cve_id, f.affected_component, a.name, a.value
           FROM findings f LEFT JOIN assets a ON a.id = f.asset_id
           WHERE f.id = %s AND f.org_id = %s""",
        (body.finding_id, str(current_user.org_id))
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    title, severity, cve, component, hostname, ip = row
    asset = hostname or ip or "unknown"
    SEVERITY_EMOJI = {"critical": ":red_circle:", "high": ":orange_circle:", "medium": ":yellow_circle:", "low": ":blue_circle:", "info": ":white_circle:"}
    emoji = SEVERITY_EMOJI.get(severity, ":white_circle:")
    mention = f" <@{cfg['mention_on_critical']}>" if severity == "critical" and cfg.get("mention_on_critical") else ""

    message = {
        "text": f"{emoji} *{severity.upper()} Finding Alert*{mention}",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": f"{emoji} {severity.upper()}: {title}"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Asset:*\n{asset}"},
                {"type": "mrkdwn", "text": f"*CVE:*\n{cve or 'N/A'}"},
                {"type": "mrkdwn", "text": f"*Component:*\n{component or 'N/A'}"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
            ]},
        ]
    }

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.post(cfg["webhook_url"], json=message)
            if resp.status_code != 200:
                raise HTTPException(status_code=500, detail=f"Slack send failed: {resp.text}")
        return {"message": "Alert sent to Slack", "finding_id": body.finding_id}
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"Slack request failed: {e}")


@router.get("/status")
async def list_integrations(current_user: User = Depends(get_current_user)):
    """List all configured integrations and their status."""
    _ensure_integrations_table()
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT integration_type, enabled, updated_at FROM integrations WHERE org_id = %s",
        (str(current_user.org_id),)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    configured = {r[0]: {"enabled": r[1], "last_updated": r[2]} for r in rows}

    all_integrations = ["jira", "slack", "splunk", "elastic", "teams", "pagerduty"]
    return [
        {
            "type": i,
            "configured": i in configured,
            "enabled": configured.get(i, {}).get("enabled", False),
            "last_updated": configured.get(i, {}).get("last_updated"),
        }
        for i in all_integrations
    ]
