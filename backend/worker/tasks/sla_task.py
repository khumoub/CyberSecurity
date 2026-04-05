import psycopg2, logging
from datetime import datetime, timezone
from worker.celery_app import celery
from core.config import settings

logger = logging.getLogger(__name__)


@celery.task(name="worker.tasks.sla_task.check_sla_breaches")
def check_sla_breaches():
    """
    Hourly: find findings where sla_due_date < NOW() and status not resolved/accepted.
    Send email alerts via Resend API.
    """
    if not settings.RESEND_API_KEY:
        logger.warning("[sla_task] RESEND_API_KEY not set — skipping SLA alerts")
        return

    try:
        import resend
        resend.api_key = settings.RESEND_API_KEY

        conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
        cur = conn.cursor()
        cur.execute("""
            SELECT f.id, f.title, f.severity, f.sla_due_date,
                   a.value AS asset, o.name AS org_name,
                   u.email AS assigned_email
            FROM findings f
            JOIN assets a ON f.asset_id = a.id
            JOIN organizations o ON f.org_id = o.id
            LEFT JOIN users u ON f.assigned_to = u.id
            WHERE f.sla_due_date < NOW()
              AND f.status NOT IN ('resolved', 'accepted_risk', 'false_positive')
            ORDER BY f.severity DESC, f.sla_due_date ASC
            LIMIT 100
        """)
        breaches = cur.fetchall()
        cur.close()
        conn.close()

        if not breaches:
            logger.info("[sla_task] No SLA breaches found.")
            return

        logger.info(f"[sla_task] Found {len(breaches)} SLA breaches.")
        for breach in breaches:
            finding_id, title, severity, due_date, asset, org_name, assigned_email = breach
            if not assigned_email:
                continue
            try:
                resend.Emails.send({
                    "from": settings.EMAIL_FROM,
                    "to": [assigned_email],
                    "subject": f"[SLA BREACH] {severity.upper()}: {title}",
                    "html": f"""
                        <h2>SLA Breach Alert — {org_name}</h2>
                        <p>The following finding has breached its SLA deadline:</p>
                        <table>
                          <tr><td><b>Finding:</b></td><td>{title}</td></tr>
                          <tr><td><b>Severity:</b></td><td>{severity.upper()}</td></tr>
                          <tr><td><b>Asset:</b></td><td>{asset}</td></tr>
                          <tr><td><b>Due Date:</b></td><td>{due_date}</td></tr>
                        </table>
                        <p>Please resolve or accept this risk immediately.</p>
                    """,
                })
            except Exception as e:
                logger.error(f"[sla_task] Email send failed for {assigned_email}: {e}")

    except Exception as exc:
        logger.error(f"[sla_task] Error: {exc}")
