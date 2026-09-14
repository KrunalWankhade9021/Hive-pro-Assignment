from pathlib import Path
from app.loaders import load_assets, load_vulnerabilities, load_threat_intel, load_services
from app.kev import load_kev
from app.engine import build_risks, NistControl

DATA = Path(__file__).resolve().parents[2] / "Dataset"
KEV_PATH = Path(__file__).resolve().parents[1] / "data" / "kev.parquet"


def _stub_retriever(joined):
    """Return a ranked list of controls; engine uses [0] as primary, rest as alternatives."""
    return [
        NistControl(id="si-2", title="Flaw Remediation", text="Identify, report, correct flaws.", similarity=0.9),
        NistControl(id="ra-5", title="Vulnerability Monitoring", text="Monitor and scan for vulnerabilities.", similarity=0.8),
        NistControl(id="ca-7", title="Continuous Monitoring", text="Monitor controls on an ongoing basis.", similarity=0.7),
    ]


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


def test_normalized_score_is_raw_over_max_and_preserves_order():
    """normalized_score = raw / 115 * 100, and normalising does not reorder risks."""
    risks = build_risks(_data(), kev={}, retriever=_stub_retriever, explainer=_stub_explainer, n=5)
    for r in risks:
        assert r.normalized_score == round(r.risk_score / 115.0 * 100, 1)
        assert 0.0 <= r.normalized_score <= 100.0
    raw_order = [r.risk_score for r in risks]
    norm_order = [r.normalized_score for r in risks]
    assert raw_order == sorted(raw_order, reverse=True)
    assert norm_order == sorted(norm_order, reverse=True)


def test_alternative_controls_are_distinct_from_primary():
    """The engine surfaces up to two alternative controls, none equal to the primary."""
    risks = build_risks(_data(), kev={}, retriever=_stub_retriever, explainer=_stub_explainer, n=5)
    top = risks[0]
    assert top.nist_control.id == "si-2"
    alt_ids = [c.id for c in top.alternative_controls]
    assert alt_ids == ["ra-5", "ca-7"]
    assert top.nist_control.id not in alt_ids


def test_cve_concentration_counts_shared_cves_in_top_n():
    """cve_concentration reports how many of the top-n share each risk's CVE."""
    # The real data pack has CVE-2023-4966 on two load balancers and
    # CVE-2024-21762 on three VPN assets, all in the top of the ranking.
    kev = load_kev(KEV_PATH) if KEV_PATH.exists() else {}
    risks = build_risks(_data(), kev=kev, retriever=_stub_retriever, explainer=_stub_explainer, n=5)
    by_cve = {}
    for r in risks:
        by_cve.setdefault(r.vulnerability["cve"], []).append(r.cve_concentration)
    # Every risk sharing a CVE reports the same count, equal to that CVE's frequency.
    for cve, counts in by_cve.items():
        assert len(set(counts)) == 1, f"{cve} concentration inconsistent: {counts}"
        assert counts[0] == len(counts)


def test_real_dataset_top5_prioritizes_exposed_ransomware_critical():
    """Over the real data pack, the top-5 must differentiate risks and surface the
    internet-exposed, ransomware-associated, business-critical ones.

    Regression guard for the clamp-saturation defect: before the raw-score +
    multi-key-tiebreak fix, every high risk scored exactly 100 and ordering fell
    to input order, so a Payment Processing / Customer Login CitrixBleed risk
    (CVE-2023-4966) could be pushed out of the top-5 by less-critical assets.
    """
    # Arrange: real data + real KEV so ransomware association is populated.
    kev = load_kev(KEV_PATH) if KEV_PATH.exists() else {}
    # Act
    risks = build_risks(_data(), kev=kev, retriever=_stub_retriever, explainer=_stub_explainer, n=5)
    # Assert: genuine differentiation — the top-5 are not all the same score.
    scores = [r.risk_score for r in risks]
    assert len(set(scores)) > 1, f"top-5 not differentiated: {scores}"
    assert scores == sorted(scores, reverse=True)
    # Assert: at least one internet-exposed, Critical-revenue risk on a
    # customer-facing money/identity service is in the top-5.
    assert any(
        r.asset["internet_exposed"] is True
        and r.business_service is not None
        and r.business_service["revenue_impact"] == "Critical"
        and r.business_service["business_service"] in ("Payment Processing", "Customer Login")
        for r in risks
    ), (
        "no exposed/Critical customer-facing risk in top-5: "
        f"{[(r.vulnerability['cve'], r.business_service and r.business_service['business_service']) for r in risks]}"
    )


def test_equal_score_ties_rank_production_above_staging():
    """On an exact score tie, a Production asset outranks a Staging one.

    The Fortinet CVE-2024-21762 risks on the two prod VPN edges and the staging
    VPN all tie at the same raw score; the environment tiebreak must place both
    Production edges ahead of vpn-staging.
    """
    # Arrange
    kev = load_kev(KEV_PATH) if KEV_PATH.exists() else {}
    # Act
    risks = build_risks(_data(), kev=kev, retriever=_stub_retriever, explainer=_stub_explainer, n=10)
    # Assert: within the group sharing the top VPN score, every Production-env
    # entry precedes every Staging-env entry.
    vpn = [r for r in risks if r.vulnerability["cve"] == "CVE-2024-21762"]
    assert vpn, "expected Fortinet CVE-2024-21762 risks present"
    tie_score = vpn[0].risk_score
    tie_group = [r for r in risks if r.risk_score == tie_score and r.vulnerability["cve"] == "CVE-2024-21762"]
    envs = [r.asset["environment"] for r in tie_group]
    last_prod = max((i for i, e in enumerate(envs) if e == "Production"), default=-1)
    first_staging = next((i for i, e in enumerate(envs) if e == "Staging"), len(envs))
    assert last_prod < first_staging, f"Production must precede Staging on ties, got {envs}"
