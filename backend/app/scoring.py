from pydantic import BaseModel
from app.join import JoinedRisk
from app.kev import KevMatch
from app.models import ThreatIntel


class ScoreResult(BaseModel):
    score: float
    breakdown: dict[str, float]


_REVENUE = {"Critical": 10, "High": 6, "Medium": 3, "Low": 0}

# Compliance scope amplifies breach impact, but not all frameworks carry the same
# weight. Statutory data-protection and payment regimes (GDPR, PCI DSS, UAE PDPL)
# carry direct regulatory penalties and mandatory breach obligations, so they
# score highest. Certification/attestation frameworks (ISO 27001, SOC 2, IFRS)
# still raise the stakes, a breach risks certification and customer contracts -
# but at a lower tier. A service may list several scopes; the highest applicable
# tier is used.
_COMPLIANCE_STATUTORY = ("PCI", "GDPR", "PDPL")
_COMPLIANCE_ATTESTATION = ("ISO", "SOC", "IFRS")

# Some findings *are* the missing-EDR gap rather than a software flaw on a host
# that happens to lack EDR (the scanner reports the control gap itself, with
# ``affected_component`` "Endpoint Control"). Scoring those rows for missing EDR
# as well would charge the same fact twice, once as the finding and once as the
# asset's weakness.
_EDR_CONTROL_COMPONENT = "Endpoint Control"


def _compliance_points(scope: str) -> int:
    if any(k in scope for k in _COMPLIANCE_STATUTORY):
        return 5
    if any(k in scope for k in _COMPLIANCE_ATTESTATION):
        return 3
    return 0


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
        comp = _compliance_points(s.compliance_scope)
        if comp:
            b["compliance_scope"] = comp
    if not a.edr_installed and v.affected_component != _EDR_CONTROL_COMPONENT:
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
