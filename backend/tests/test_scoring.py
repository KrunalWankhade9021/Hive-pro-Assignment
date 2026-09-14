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

    # Exact expected values (the clamp was removed; these cases still land here):
    # internal = cvss_base only = (10/10)*25 = 25.0
    # exposed  = 20(base 8) +20 +15 +15 +15 +10 +5 = 100.0
    assert internal_score == 25.0
    assert exposed_score == 100.0
    assert exposed_score > internal_score


def test_breakdown_records_factors():
    r = mk({"internet_exposed": True}, {}, {})
    res = score_risk(r, KevMatch(in_kev=True, ransomware=True), None)
    assert res.breakdown["internet_exposed"] == 20
    assert res.breakdown["kev_ransomware"] == 15


def test_statutory_compliance_scores_higher_than_attestation():
    """Statutory regimes (GDPR/PCI/PDPL) weigh 5; certifications (ISO/SOC/IFRS) weigh 3."""
    statutory = mk({}, {}, {"compliance_scope": "GDPR"})
    attestation = mk({}, {}, {"compliance_scope": "ISO 27001"})
    none = mk({}, {}, {"compliance_scope": "None"})

    kev = KevMatch(in_kev=False, ransomware=False)
    assert score_risk(statutory, kev, None).breakdown["compliance_scope"] == 5
    assert score_risk(attestation, kev, None).breakdown["compliance_scope"] == 3
    assert "compliance_scope" not in score_risk(none, kev, None).breakdown


def test_mixed_compliance_scope_takes_highest_tier():
    """A service listing both a certification and a statutory regime scores the top tier."""
    mixed = mk({}, {}, {"compliance_scope": "SOC 2, UAE PDPL"})
    res = score_risk(mixed, KevMatch(in_kev=False, ransomware=False), None)
    assert res.breakdown["compliance_scope"] == 5
