from pathlib import Path
from app.loaders import load_assets, load_vulnerabilities, load_threat_intel, load_services

DATA = Path(__file__).resolve().parents[2] / "Dataset"


def test_load_assets_count_and_types():
    assets = load_assets(DATA / "assets.csv")
    assert len(assets) == 60
    a = {x.asset_id: x for x in assets}["A-1001"]
    assert a.internet_exposed is True
    assert a.criticality == "Critical"
    assert a.edr_installed is True


def test_load_vulnerabilities_count():
    vulns = load_vulnerabilities(DATA / "vulnerabilities.csv")
    assert len(vulns) == 114
    assert isinstance(vulns[0].cvss, float)


def test_load_services_keyed_by_name():
    svcs = load_services(DATA / "business_services.csv")
    assert "Payment Processing" in svcs
    assert svcs["Payment Processing"].revenue_impact == "Critical"


def test_load_threat_intel_count():
    ti = load_threat_intel(DATA / "threat_intelligence.csv")
    assert len(ti) == 40
