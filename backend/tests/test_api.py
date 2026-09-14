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
