"""Intel tasks: CISA KEV sync, EPSS enrichment, risk score calculation."""
import requests, psycopg2, logging
from worker.celery_app import celery_app
from core.config import settings

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL  = "https://api.first.org/data/v1/epss"

SEVERITY_WEIGHTS = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.5, "info": 0.3}
KEV_MULTIPLIER    = 2.0
EXPLOIT_MULT      = 1.5


@celery_app.task(name="worker.tasks.intel_task.fetch_cisa_kev")
def fetch_cisa_kev():
    """Daily: fetch CISA KEV catalog and mark matched findings as known-exploited."""
    try:
        logger.info("[intel] Fetching CISA KEV feed…")
        resp = requests.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        cve_ids = {v["cveID"] for v in resp.json().get("vulnerabilities", []) if "cveID" in v}
        logger.info(f"[intel] CISA KEV: {len(cve_ids)} CVEs in catalog")
        if not cve_ids:
            return

        conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
        cur  = conn.cursor()
        cur.execute("""
            UPDATE findings
               SET is_known_exploited = TRUE, updated_at = NOW()
             WHERE cve_id = ANY(%s) AND is_known_exploited = FALSE
        """, (list(cve_ids),))
        updated = cur.rowcount
        conn.commit(); cur.close(); conn.close()
        logger.info(f"[intel] Marked {updated} findings as known-exploited.")
    except Exception as exc:
        logger.error(f"[intel] CISA KEV fetch failed: {exc}")


@celery_app.task(name="worker.tasks.intel_task.enrich_epss_scores")
def enrich_epss_scores():
    """Daily: fetch EPSS scores for all findings that have CVE IDs."""
    try:
        conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
        cur  = conn.cursor()
        cur.execute("SELECT DISTINCT cve_id FROM findings WHERE cve_id IS NOT NULL AND cve_id != ''")
        cve_ids = [row[0] for row in cur.fetchall()]

        if not cve_ids:
            logger.info("[intel] No CVE IDs to enrich.")
            cur.close(); conn.close()
            return

        logger.info(f"[intel] Fetching EPSS scores for {len(cve_ids)} CVEs…")
        epss_map: dict[str, float] = {}
        batch_size = 100
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            try:
                r = requests.get(
                    EPSS_API_URL,
                    params={"cve": ",".join(batch), "limit": batch_size},
                    timeout=20,
                )
                if r.status_code == 200:
                    for item in r.json().get("data", []):
                        epss_map[item["cve"]] = float(item.get("epss", 0))
            except Exception as e:
                logger.warning(f"[intel] EPSS batch fetch failed: {e}")

        for cve_id, score in epss_map.items():
            cur.execute(
                "UPDATE findings SET epss_score = %s, updated_at = NOW() WHERE cve_id = %s",
                (score, cve_id),
            )
        conn.commit(); cur.close(); conn.close()
        logger.info(f"[intel] Updated EPSS scores for {len(epss_map)} CVEs.")
    except Exception as exc:
        logger.error(f"[intel] EPSS enrichment failed: {exc}")


@celery_app.task(name="worker.tasks.intel_task.calculate_risk_scores")
def calculate_risk_scores():
    """Daily: recalculate composite risk scores for all assets."""
    try:
        conn = psycopg2.connect(settings.DATABASE_URL_SYNC)
        cur  = conn.cursor()
        cur.execute("""
            SELECT DISTINCT asset_id FROM findings
             WHERE status NOT IN ('resolved', 'false_positive', 'accepted_risk')
               AND asset_id IS NOT NULL
        """)
        asset_ids = [row[0] for row in cur.fetchall()]

        for asset_id in asset_ids:
            cur.execute("""
                SELECT severity, cvss_score, is_known_exploited, exploit_available, epss_score
                  FROM findings
                 WHERE asset_id = %s
                   AND status NOT IN ('resolved', 'false_positive', 'accepted_risk')
            """, (asset_id,))
            raw = 0.0
            for sev, cvss, kev, exploit, epss in cur.fetchall():
                base       = SEVERITY_WEIGHTS.get(sev, 1.0)
                cvss_f     = (float(cvss) / 10.0) if cvss else 0.5
                kev_f      = KEV_MULTIPLIER if kev else 1.0
                exploit_f  = EXPLOIT_MULT   if exploit else 1.0
                epss_f     = 1.0 + float(epss or 0)
                raw       += base * cvss_f * kev_f * exploit_f * epss_f
            normalized = round(min(raw / 10.0, 10.0), 2)
            cur.execute(
                "UPDATE assets SET risk_score = %s, updated_at = NOW() WHERE id = %s",
                (normalized, asset_id),
            )

        conn.commit(); cur.close(); conn.close()
        logger.info(f"[intel] Updated risk scores for {len(asset_ids)} assets.")
    except Exception as exc:
        logger.error(f"[intel] Risk score calculation failed: {exc}")
