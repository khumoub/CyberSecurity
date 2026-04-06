from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text

SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 0.5,
    "info": 0.1,
}
EXPLOIT_MULTIPLIER = 1.5
KEV_MULTIPLIER = 2.0
MAX_RAW_SCORE = 100.0


class RiskScoringService:
    """Calculates weighted risk scores for assets and organisations."""

    async def calculate_asset_score(self, asset_id: str, db: AsyncSession) -> float:
        result = await db.execute(
            text("""
                SELECT severity,
                       COUNT(*) AS cnt,
                       SUM(CASE WHEN is_known_exploited THEN 1 ELSE 0 END) AS kev_count,
                       SUM(CASE WHEN exploit_available THEN 1 ELSE 0 END) AS exploit_count
                FROM findings
                WHERE asset_id = :asset_id
                  AND status NOT IN ('resolved', 'accepted_risk', 'false_positive')
                GROUP BY severity
            """),
            {"asset_id": asset_id},
        )
        rows = result.fetchall()
        if not rows:
            return 0.0

        raw = 0.0
        for row in rows:
            sev, cnt, kev, expl = row
            base = SEVERITY_WEIGHTS.get(sev, 0.1) * cnt
            if kev and kev > 0:
                base *= KEV_MULTIPLIER
            elif expl and expl > 0:
                base *= EXPLOIT_MULTIPLIER
            raw += base

        # Normalise: sigmoid-like clamp to 0-100
        score = min((raw / (raw + 20.0)) * 100.0, 100.0)
        return round(score, 1)

    async def calculate_org_score(self, org_id: str, db: AsyncSession) -> float:
        result = await db.execute(
            text("""
                SELECT severity,
                       COUNT(*) AS cnt,
                       SUM(CASE WHEN is_known_exploited THEN 1 ELSE 0 END) AS kev_count,
                       SUM(CASE WHEN exploit_available THEN 1 ELSE 0 END) AS exploit_count
                FROM findings
                WHERE org_id = :org_id
                  AND status NOT IN ('resolved', 'accepted_risk', 'false_positive')
                GROUP BY severity
            """),
            {"org_id": org_id},
        )
        rows = result.fetchall()
        if not rows:
            return 0.0

        raw = 0.0
        for row in rows:
            sev, cnt, kev, expl = row
            base = SEVERITY_WEIGHTS.get(sev, 0.1) * cnt
            if kev and kev > 0:
                base *= KEV_MULTIPLIER
            elif expl and expl > 0:
                base *= EXPLOIT_MULTIPLIER
            raw += base

        score = min((raw / (raw + 50.0)) * 100.0, 100.0)
        return round(score, 1)

    async def get_risk_heatmap_data(self, org_id: str, db: AsyncSession) -> list[dict]:
        """
        Returns list of {asset_id, asset_value, likelihood, impact, score, severity}
        for rendering as a scatter/heat-map chart.

        Likelihood  (1-5): based on exploit_available + is_known_exploited
        Impact      (1-5): based on max severity of open findings
        """
        result = await db.execute(
            text("""
                SELECT
                    a.id,
                    a.value,
                    MAX(CASE f.severity
                        WHEN 'critical' THEN 5
                        WHEN 'high'     THEN 4
                        WHEN 'medium'   THEN 3
                        WHEN 'low'      THEN 2
                        ELSE 1
                    END) AS impact,
                    GREATEST(1,
                        SUM(CASE WHEN f.is_known_exploited THEN 2
                                 WHEN f.exploit_available  THEN 1 ELSE 0 END)
                    ) AS raw_likelihood,
                    COUNT(f.id) AS finding_count,
                    MAX(f.severity) AS max_severity
                FROM assets a
                LEFT JOIN findings f
                    ON f.asset_id = a.id
                   AND f.status NOT IN ('resolved', 'accepted_risk', 'false_positive')
                WHERE a.org_id = :org_id
                  AND a.is_active = TRUE
                GROUP BY a.id, a.value
                HAVING COUNT(f.id) > 0
                ORDER BY impact DESC, raw_likelihood DESC
                LIMIT 50
            """),
            {"org_id": org_id},
        )
        rows = result.fetchall()

        heat_data = []
        for row in rows:
            asset_id, value, impact, raw_like, count, max_sev = row
            likelihood = min(int(raw_like), 5)
            score = round((impact * likelihood) / 25.0 * 100.0, 1)
            heat_data.append({
                "asset_id": str(asset_id),
                "asset_value": value,
                "likelihood": likelihood,
                "impact": int(impact),
                "score": score,
                "finding_count": int(count),
                "max_severity": max_sev,
            })

        return heat_data

    async def get_patch_priority(self, org_id: str, db: AsyncSession) -> list[dict]:
        """
        Returns top 25 findings ranked by patch priority:
        1. Known exploited (CISA KEV)
        2. Exploit available
        3. CVSS score
        4. Severity weight
        """
        result = await db.execute(
            text("""
                SELECT
                    f.id, f.title, f.severity, f.cvss_score,
                    f.cve_id, f.is_known_exploited, f.exploit_available,
                    f.affected_component, f.remediation,
                    a.value AS asset_value,
                    (
                        CASE WHEN f.is_known_exploited THEN 100 ELSE 0 END +
                        CASE WHEN f.exploit_available  THEN 50  ELSE 0 END +
                        COALESCE(f.cvss_score, 0) * 5 +
                        CASE f.severity
                            WHEN 'critical' THEN 40
                            WHEN 'high'     THEN 20
                            WHEN 'medium'   THEN 10
                            WHEN 'low'      THEN 5
                            ELSE 1
                        END
                    ) AS priority_score
                FROM findings f
                JOIN assets a ON f.asset_id = a.id
                WHERE f.org_id = :org_id
                  AND f.status NOT IN ('resolved', 'accepted_risk', 'false_positive')
                ORDER BY priority_score DESC
                LIMIT 25
            """),
            {"org_id": org_id},
        )
        rows = result.fetchall()

        return [
            {
                "rank": i + 1,
                "id": str(r[0]),
                "title": r[1],
                "severity": r[2],
                "cvss_score": float(r[3]) if r[3] else None,
                "cve_id": r[4],
                "is_known_exploited": bool(r[5]),
                "exploit_available": bool(r[6]),
                "affected_component": r[7],
                "remediation": r[8],
                "asset_value": r[9],
                "priority_score": float(r[10]),
            }
            for i, r in enumerate(rows)
        ]
