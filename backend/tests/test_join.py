from app.models import Asset, Vulnerability, BusinessService
from app.join import join


def _asset(**k):
    defaults = dict(asset_id="A-1", asset_name="n", asset_type="t", environment="Production",
        owner_team="X", business_service="Payment Processing", internet_exposed=True, criticality="Critical",
        data_classification="PII", edr_installed=False, last_seen_days=1, location="UAE", vendor_product="v")
    defaults.update(k)
    return Asset(**defaults)


def _vuln(**k):
    defaults = dict(vuln_id="V-1", asset_id="A-1", vulnerability_name="RCE", cve="CVE-2024-21762",
        severity="Critical", cvss=9.8, exploit_available=True, patch_available=True, days_open=40, asset_exposure="Internet",
        auth_required=False, status="Open", affected_component="VPN")
    defaults.update(k)
    return Vulnerability(**defaults)


def _svc():
    return BusinessService(business_service="Payment Processing", business_owner="CFO", business_impact="x",
        customer_facing=True, compliance_scope="PCI DSS", revenue_impact="Critical", rto_hours=1, depends_on="", risk_appetite="Very Low")


def test_join_links_vuln_to_asset_and_service():
    joined = join([_vuln()], [_asset()], {"Payment Processing": _svc()})
    assert len(joined) == 1
    jr = joined[0]
    assert jr.asset.asset_id == "A-1"
    assert jr.service.revenue_impact == "Critical"


def test_join_orphan_vuln_without_asset_is_dropped_and_logged():
    joined = join([_vuln(asset_id="A-999")], [_asset()], {"Payment Processing": _svc()})
    assert joined == []
