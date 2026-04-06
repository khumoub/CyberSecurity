"""SLA tasks: breach alerting, deadline assignment, MTTR calculation."""
import psycopg2, logging
from datetime import datetime, timezone, timedelta
from worker.celery_app import celery_app
from core.config import settings

logger = logging.getLogger(__name__)

SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}


@celery_app.task(name="worker.tasks.sla_task.check_sla_breaches")
def check_sla_breaches():
    """Hourly: find breached findings and send email alerts via Resend."""
    if not settings.RESEND_API_KEY:
        logger.warning("[sla] RESEND_API_KEY not set — skipping SLA alerts")
        return
    try:
        import resend
        resend.api_key = settings.RESEND_API_KEY

        conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
        cur  = conn.cursor()
        cur.execute("""
            SELECT f.id, f.title, f.severity, f.sla_due_date,
                   a.value AS asset, o.name AS org_name, u.email AS assigned_email
              FROM findings f
              JOIN assets        a ON f.asset_id = a.id
              JOIN organizations o ON f.org_id   = o.id
         LEFT JOIN users         u ON f.assigned_to = u.id
             WHERE f.sla_due_date < NOW()
               AND f.status NOT IN ('resolved','accepted_risk','false_positive')
          ORDER BY f.severity DESC, f.sla_due_date ASC
             LIMIT 100
        """)
        breaches = cur.fetchall()
        cur.close(); conn.close()

        if not breaches:
            logger.info("[sla] No SLA breaches.")
            return

        logger.info(f"[sla] {len(breaches)} SLA breaches.")
        now = datetime.now(timezone.utc)
        for finding_id, title, severity, due_date, asset, org_name, email in breaches:
            if not email:
                continue
            due_aware = due_date.replace(tzinfo=timezone.utc) if due_date.tzinfo is None else due_date
            days_over = max(0, (now - due_aware).days)
            try:
                resend.Emails.send({
                    "from": settings.EMAIL_FROM,
                    "to": [email],
                    "subject": f"[SLA BREACH] {severity.upper()}: {title}",
                    "html": f"""
                        <h2 style="color:#ff3b3b">SLA Breach — {org_name}</h2>
                        <p>This finding has breached its SLA by <strong>{days_over} day(s)</strong>:</p>
                        <table style="border-collapse:collapse">
                          <tr><td style="padding:6px;border:1px solid #ddd"><b>Finding</b></td>
                              <td style="padding:6px;border:1px solid #ddd">{title}</td></tr>
                          <tr><td style="padding:6px;border:1px solid #ddd"><b>Severity</b></td>
                              <td style="padding:6px;border:1px solid #ddd">{severity.upper()}</td></tr>
                          <tr><td style="padding:6px;border:1px solid #ddd"><b>Asset</b></td>
                              <td style="padding:6px;border:1px solid #ddd">{asset}</td></tr>
                          <tr><td style="padding:6px;border:1px solid #ddd"><b>Due Date</b></td>
                              <td style="padding:6px;border:1px solid #ddd">{due_date}</td></tr>
                          <tr><td style="padding:6px;border:1px solid #ddd"><b>Days Overdue</b></td>
                              <td style="padding:6px;border:1px solid #ddd;color:#ff3b3b"><b>{days_over}</b></td></tr>
                        </table>
                        <p>Please resolve or accept risk in the Leruo platform immediately.</p>
                    """,
                })
            except Exception as e:
                logger.error(f"[sla] Email to {email} failed: {e}")
    except Exception as exc:
        logger.error(f"[sla] check_sla_breaches error: {exc}")


@celery_app.task(name="worker.tasks.sla_task.assign_sla_deadlines")
def assign_sla_deadlines():
    """Daily: set sla_due_date on new findings that have none."""
    try:
        conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
        cur  = conn.cursor()
        now  = datetime.now(timezone.utc)
        total = 0
        for severity, days in SLA_DAYS.items():
            due = now + timedelta(days=days)
            cur.execute("""
                UPDATE findings SET sla_due_date = %s, updated_at = NOW()
                 WHERE severity = %s AND sla_due_date IS NULL
                   AND status NOT IN ('resolved','false_positive')
            """, (due, severity))
            total += cur.rowcount
        conn.commit(); cur.close(); conn.close()
        logger.info(f"[sla] Assigned SLA deadlines to {total} findings.")
    except Exception as exc:
        logger.error(f"[sla] assign_sla_deadlines error: {exc}")


@celery_app.task(name="worker.tasks.sla_task.calculate_mttr")
def calculate_mttr():
    """Weekly: calculate Mean Time To Remediate per org per severity."""
    try:
        conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
        cur  = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS mttr_metrics (
                id SERIAL PRIMARY KEY,
                org_id UUID NOT NULL,
                severity VARCHAR(20),
                avg_days FLOAT,
                median_days FLOAT,
                sample_count INT,
                calculated_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        cur.execute("SELECT id FROM organizations")
        org_ids = [row[0] for row in cur.fetchall()]

        for org_id in org_ids:
            for severity in ("critical", "high", "medium", "low"):
                cur.execute("""
                    SELECT
                        AVG(EXTRACT(EPOCH FROM (updated_at - created_at)) / 86400),
                        PERCENTILE_CONT(0.5) WITHIN GROUP (
                            ORDER BY EXTRACT(EPOCH FROM (updated_at - created_at)) / 86400
                        ),
                        COUNT(*)
                      FROM findings
                     WHERE org_id   = %s
                       AND severity = %s
                       AND status   = 'resolved'
                       AND updated_at > created_at
                       AND updated_at >= NOW() - INTERVAL '90 days'
                """, (org_id, severity))
                row = cur.fetchone()
                if row and row[2] and row[2] > 0:
                    cur.execute("""
                        INSERT INTO mttr_metrics (org_id, severity, avg_days, median_days, sample_count)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (org_id, severity, round(row[0] or 0, 1), round(row[1] or 0, 1), row[2]))

        conn.commit(); cur.close(); conn.close()
        logger.info("[sla] MTTR calculation complete.")
    except Exception as exc:
        logger.error(f"[sla] calculate_mttr error: {exc}")
