from app.models import Asset, Vulnerability, BusinessService, ThreatIntel
from app.join import JoinedRisk
from app.kev import KevMatch
from app.scoring import score_risk


def mk(asset_kw, vuln_kw, svc_kw):
    asset_defaults = dict(asset_id="A", asset_name="n", asset_type="t", environment="Production", owner_team="X",
        business_service="S", internet_exposed=True, criticality="Critical", data_classification="PII",
        edr_installed=True, last_seen_days=1, location="UAE", vendor_product="v")
    asset_defaults.update(asset_kw)
    a = Asset(**asset_defaults)
    vuln_defaults = dict(vuln_id="V", asset_id="A", vulnerability_name="x", cve="CVE-1", severity="High", cvss=8.0,
        exploit_available=True, patch_available=True, days_open=10, asset_exposure="Internet", auth_required=True,
        status="Open", affected_component="c")
    vuln_defaults.update(vuln_kw)
    v = Vulnerability(**vuln_defaults)
    svc_defaults = dict(business_service="S", business_owner="o", business_impact="i", customer_facing=True,
        compliance_scope="PCI DSS", revenue_impact="Critical", rto_hours=1, depends_on="", risk_appetite="Very Low")
    svc_defaults.update(svc_kw)
    s = BusinessService(**svc_defaults)
    return JoinedRisk(vulnerability=v, asset=a, service=s)


def test_internal_cvss10_ranks_below_exposed_cvss8_ransomware():
    internal = mk({"internet_exposed": False, "criticality": "Low"},
                  {"cvss": 10.0, "exploit_available": False},
                  {"revenue_impact": "Low", "compliance_scope": "None"})
    internal_score = score_risk(internal, KevMatch(in_kev=False, ransomware=False), None).score

    exposed = mk({"internet_exposed": True}, {"cvss": 8.0, "exploit_available": True},
                 {"revenue_impact": "Critical", "compliance_scope": "PCI DSS"})
    ti = ThreatIntel(intel_id="T", threat_actor="a", campaign_name="c", target_sector="Financial Services",
        target_region="Middle East", matched_cve_or_control="CVE-1", exploit_maturity="Weaponized",
        active_last_seen="2026-04-22", ransomware_association=True, confidence="High", summary="s")
    exposed_score = score_risk(exposed, KevMatch(in_kev=True, ransomware=True), ti).score

    assert exposed_score > internal_score


def test_breakdown_records_factors():
    r = mk({"internet_exposed": True}, {}, {})
    res = score_risk(r, KevMatch(in_kev=True, ransomware=True), None)
    assert res.breakdown["internet_exposed"] == 20
    assert res.breakdown["kev_ransomware"] == 15
