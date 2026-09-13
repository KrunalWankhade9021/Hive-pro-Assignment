from pathlib import Path
from app.loaders import load_assets, load_vulnerabilities, load_threat_intel, load_services
from app.engine import build_risks, NistControl

DATA = Path(__file__).resolve().parents[2] / "Dataset"


def _stub_retriever(joined):
    return NistControl(id="si-2", title="Flaw Remediation", text="Identify, report, correct flaws.", similarity=0.9)


def _stub_explainer(risk):
    return "Ranked high due to exposure and active ransomware."


def _data():
    return {
        "assets": load_assets(DATA / "assets.csv"),
        "vulns": load_vulnerabilities(DATA / "vulnerabilities.csv"),
        "intel": load_threat_intel(DATA / "threat_intelligence.csv"),
        "services": load_services(DATA / "business_services.csv"),
    }


def test_build_risks_returns_top5_sorted():
    risks = build_risks(_data(), kev={}, retriever=_stub_retriever, explainer=_stub_explainer, n=5)
    assert len(risks) == 5
    assert [r.rank for r in risks] == [1, 2, 3, 4, 5]
    scores = [r.risk_score for r in risks]
    assert scores == sorted(scores, reverse=True)
    assert risks[0].nist_control.id == "si-2"
    assert risks[0].explanation


def test_build_risks_wires_evidence_fields():
    risks = build_risks(_data(), kev={}, retriever=_stub_retriever, explainer=_stub_explainer, n=5)
    top = risks[0]
    # asset/vulnerability are serialized dicts carrying the joined records
    assert "asset_id" in top.asset
    assert "cve" in top.vulnerability
    # kev match object is present (empty kev dict => not in kev)
    assert top.kev.in_kev is False
    # explanation comes from the injected explainer
    assert top.explanation == "Ranked high due to exposure and active ransomware."


def test_build_risks_respects_n():
    risks = build_risks(_data(), kev={}, retriever=_stub_retriever, explainer=_stub_explainer, n=3)
    assert len(risks) == 3
    assert [r.rank for r in risks] == [1, 2, 3]
