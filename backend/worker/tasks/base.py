import redis
import json
import uuid
import psycopg2
from datetime import datetime, timezone
from typing import Optional, List
from core.config import settings

r = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)


def publish_output(scan_id: str, line: str):
    """Publish a line of scan output to Redis pub/sub for WebSocket streaming."""
    r.publish(
        f"scan_output:{scan_id}",
        json.dumps({
            "type": "output",
            "line": line,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }),
    )


def update_scan_status(scan_id: str, status: str, error: Optional[str] = None):
    """Publish status update and persist to DB."""
    r.publish(
        f"scan_output:{scan_id}",
        json.dumps({
            "type": "status",
            "status": status,
            "error": error,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }),
    )
    _update_scan_in_db(scan_id, status, error)


def _update_scan_in_db(scan_id: str, status: str, error: Optional[str] = None):
    """Update scan_jobs row using synchronous psycopg2."""
    try:
        conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
        cur = conn.cursor()
        now = datetime.now(timezone.utc)
        if status in ("completed", "failed", "cancelled"):
            cur.execute(
                """
                UPDATE scan_jobs
                SET status = %s, error_message = %s, completed_at = %s, updated_at = %s
                WHERE id = %s
                """,
                (status, error, now, now, scan_id),
            )
        elif status == "running":
            cur.execute(
                """
                UPDATE scan_jobs
                SET status = %s, started_at = %s, updated_at = %s
                WHERE id = %s
                """,
                (status, now, now, scan_id),
            )
        else:
            cur.execute(
                """
                UPDATE scan_jobs
                SET status = %s, updated_at = %s
                WHERE id = %s
                """,
                (status, now, scan_id),
            )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[base] DB update error for scan {scan_id}: {e}")


def update_scan_raw_output(scan_id: str, raw_output: str):
    """Persist raw output text to scan_jobs."""
    try:
        conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
        cur = conn.cursor()
        cur.execute(
            "UPDATE scan_jobs SET raw_output = %s, updated_at = %s WHERE id = %s",
            (raw_output, datetime.now(timezone.utc), scan_id),
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[base] raw output DB error for scan {scan_id}: {e}")


def save_findings_to_db(
    scan_id: str,
    org_id: str,
    asset_id: Optional[str],
    findings: List[dict],
) -> int:
    """
    Bulk insert findings using psycopg2.
    Each finding dict should have: title, description, severity, cvss_score, cve_id, cwe_id,
    affected_component, affected_port, affected_service, remediation, references, raw_output,
    is_known_exploited, exploit_available, mitre_technique.
    Returns count of inserted rows.
    """
    if not findings:
        return 0

    try:
        conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
        cur = conn.cursor()
        now = datetime.now(timezone.utc)

        # Calculate SLA due date based on severity
        sla_days = {
            "critical": 7,
            "high": 30,
            "medium": 90,
            "low": 180,
            "info": None,
        }

        inserted = 0
        for f in findings:
            finding_id = str(uuid.uuid4())
            severity = f.get("severity", "info").lower()
            sla_delta = sla_days.get(severity)
            sla_due = None
            if sla_delta:
                from datetime import timedelta
                sla_due = now + timedelta(days=sla_delta)

            refs = f.get("references", [])
            if isinstance(refs, list):
                refs_pg = "{" + ",".join(f'"{r}"' for r in refs) + "}"
            else:
                refs_pg = "{}"

            cur.execute(
                """
                INSERT INTO findings (
                    id, org_id, scan_id, asset_id, title, description,
                    severity, cvss_score, cve_id, cwe_id, affected_component,
                    affected_port, affected_service, remediation, references,
                    raw_output, status, first_seen_at, last_seen_at, sla_due_date,
                    is_known_exploited, exploit_available, mitre_technique,
                    created_at, updated_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, 'open', %s, %s, %s,
                    %s, %s, %s,
                    %s, %s
                )
                ON CONFLICT DO NOTHING
                """,
                (
                    finding_id,
                    org_id,
                    scan_id,
                    asset_id,
                    f.get("title", "Unknown Finding"),
                    f.get("description", ""),
                    severity,
                    f.get("cvss_score"),
                    f.get("cve_id"),
                    f.get("cwe_id"),
                    f.get("affected_component"),
                    f.get("affected_port"),
                    f.get("affected_service"),
                    f.get("remediation"),
                    refs_pg,
                    f.get("raw_output"),
                    now,
                    now,
                    sla_due,
                    f.get("is_known_exploited", False),
                    f.get("exploit_available", False),
                    f.get("mitre_technique"),
                    now,
                    now,
                ),
            )
            inserted += 1

        # Update findings_count on scan_job
        cur.execute(
            """
            UPDATE scan_jobs
            SET findings_count = findings_count + %s, updated_at = %s
            WHERE id = %s
            """,
            (inserted, now, scan_id),
        )

        conn.commit()
        cur.close()
        conn.close()
        return inserted
    except Exception as e:
        print(f"[base] save_findings error for scan {scan_id}: {e}")
        return 0


def update_asset_last_scanned(asset_id: str):
    """Update last_scanned_at on the asset."""
    if not asset_id:
        return
    try:
        conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
        cur = conn.cursor()
        cur.execute(
            "UPDATE assets SET last_scanned_at = %s, updated_at = %s WHERE id = %s",
            (datetime.now(timezone.utc), datetime.now(timezone.utc), asset_id),
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[base] update_asset error: {e}")
