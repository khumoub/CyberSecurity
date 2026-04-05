import requests, psycopg2, logging
from worker.celery_app import celery
from core.config import settings

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@celery.task(name="worker.tasks.intel_task.fetch_cisa_kev")
def fetch_cisa_kev():
    """
    Daily: fetch CISA Known Exploited Vulnerabilities catalog.
    Cross-reference with org findings — mark is_known_exploited=True where matched.
    """
    try:
        logger.info("[intel_task] Fetching CISA KEV feed...")
        resp = requests.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        cve_ids = {v["cveID"] for v in vulnerabilities if "cveID" in v}
        logger.info(f"[intel_task] CISA KEV: {len(cve_ids)} CVEs in catalog")

        if not cve_ids:
            return

        conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
        cur = conn.cursor()

        # Update findings that match KEV CVEs
        cve_list = list(cve_ids)
        cur.execute("""
            UPDATE findings
            SET is_known_exploited = TRUE, updated_at = NOW()
            WHERE cve_id = ANY(%s)
              AND is_known_exploited = FALSE
        """, (cve_list,))
        updated = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()

        logger.info(f"[intel_task] Marked {updated} findings as known-exploited from CISA KEV.")

    except Exception as exc:
        logger.error(f"[intel_task] CISA KEV fetch failed: {exc}")
