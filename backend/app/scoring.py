from pydantic import BaseModel
from app.join import JoinedRisk
from app.kev import KevMatch
from app.models import ThreatIntel


class ScoreResult(BaseModel):
    score: float
    breakdown: dict[str, float]


_REVENUE = {"Critical": 10, "High": 6, "Medium": 3, "Low": 0}


def score_risk(joined: JoinedRisk, kev: KevMatch, threat: ThreatIntel | None) -> ScoreResult:
    v, a, s = joined.vulnerability, joined.asset, joined.service
    b: dict[str, float] = {}
    b["cvss_base"] = round((v.cvss / 10.0) * 25, 2)
    if a.internet_exposed:
        b["internet_exposed"] = 20
    if v.exploit_available or kev.in_kev:
        b["exploit_available"] = 15
    if kev.ransomware:
        b["kev_ransomware"] = 15
    if threat is not None:
        b["threat_campaign"] = 15
    if s is not None:
        rev = _REVENUE.get(s.revenue_impact, 0)
        if rev:
            b["business_criticality"] = rev
        if any(k in s.compliance_scope for k in ("PCI", "GDPR")):
            b["compliance_scope"] = 5
    if not a.edr_installed:
        b["missing_edr"] = 5
    if not v.auth_required:
        b["no_auth_required"] = 3
    if v.days_open > 30:
        b["long_open"] = 2
    # Raw weighted sum, intentionally NOT clamped: clamping to 100 saturates the
    # highest risks and destroys differentiation in the ranking. The score may
    # exceed 100 for a risk that trips every factor.
    total = sum(b.values())
    return ScoreResult(score=round(total, 2), breakdown=b)
