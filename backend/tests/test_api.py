"""API-level tests for the FastAPI service.

These exercise the HTTP surface with the retriever and explainer monkeypatched
to lightweight stubs, so the endpoints are tested without loading the embedding
model or the vector store. The engine, scoring, and ranking run for real against
the bundled data pack.
"""
import app.main as main
from app.engine import NistControl
from fastapi.testclient import TestClient


def _patch_pipeline(monkeypatch):
    """Replace the network/model-heavy seams with deterministic stubs."""
    monkeypatch.setattr(
        main, "_build_retriever",
        lambda: (lambda jr: NistControl(id="si-2", title="Flaw Remediation", text="fix flaws", similarity=0.9)),
    )
    monkeypatch.setattr(main, "_build_explainer", lambda: (lambda risk: "because reasons"))
    monkeypatch.setattr(main, "_load_kev_dict", lambda: {})
    main._risks.cache_clear()
    main._stats.cache_clear()


def test_health_reports_ok(monkeypatch):
    """GET /health returns a status of ok."""
    _patch_pipeline(monkeypatch)
    client = TestClient(main.app)

    body = client.get("/health").json()

    assert body["status"] == "ok"


def test_top_risks_returns_ranked_entries_with_control_and_explanation(monkeypatch):
    """GET /risks/top returns n ranked risks, each with a NIST control and explanation."""
    _patch_pipeline(monkeypatch)
    client = TestClient(main.app)

    data = client.get("/risks/top?n=5").json()

    assert len(data) == 5
    assert [r["rank"] for r in data] == [1, 2, 3, 4, 5]
    assert data[0]["nist_control"]["id"] == "si-2"
    assert data[0]["explanation"] == "because reasons"
    # scores are the raw weighted sums, sorted descending
    scores = [r["risk_score"] for r in data]
    assert scores == sorted(scores, reverse=True)


def test_top_risks_respects_n_parameter(monkeypatch):
    """The n query parameter controls how many risks are returned."""
    _patch_pipeline(monkeypatch)
    client = TestClient(main.app)

    data = client.get("/risks/top?n=3").json()

    assert len(data) == 3


def test_stats_returns_portfolio_counts(monkeypatch):
    """GET /stats returns integer portfolio counts matching the bundled data pack."""
    _patch_pipeline(monkeypatch)
    client = TestClient(main.app)

    body = client.get("/stats").json()

    expected_keys = {
        "total_assets", "internet_exposed_assets", "critical_assets",
        "total_vulnerabilities", "exploited_count", "kev_matches",
        "ransomware_vulns", "matched_campaigns", "noise_campaigns", "generated_at",
    }
    assert expected_keys <= body.keys()
    assert all(isinstance(body[k], int) for k in expected_keys - {"generated_at"})
    # Known counts for the bundled data pack (KEV stubbed empty, so kev_matches == 0).
    assert body["total_assets"] == 60
    assert body["internet_exposed_assets"] == 21
    assert body["critical_assets"] == 15
    assert body["total_vulnerabilities"] == 114
