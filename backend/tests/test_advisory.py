"""Tests for ingesting the MDR threat advisory and serving it over the API."""
from pathlib import Path

import app.main as main
from app.advisory import Advisory, load_advisory
from fastapi.testclient import TestClient

_REPORT = Path(__file__).resolve().parents[2] / "Dataset" / "synthetic_threat_report.md"


def test_load_advisory_returns_raw_markdown_and_campaigns():
    """The real advisory loads with its markdown intact and all campaigns parsed."""
    advisory = load_advisory(_REPORT)

    assert "MDR Advisory" in advisory.raw_markdown
    assert len(advisory.campaigns) == 5
    names = {c.name for c in advisory.campaigns}
    assert {
        "Gateway Breaker",
        "Collaboration Breach",
        "Build Chain Theft",
        "CitrixBleed Exploitation",
        "API Gateway Takeover",
    } <= names


def test_campaign_fields_are_extracted():
    """A parsed campaign carries its actor, exploit chain, and ransomware note."""
    advisory = load_advisory(_REPORT)

    gateway = next(c for c in advisory.campaigns if c.name == "Gateway Breaker")

    assert gateway.threat_actor == "CrimsonJackal"
    assert "CVE-2024-21762" in (gateway.exploit_chain or "")
    assert gateway.ransomware and gateway.ransomware.lower().startswith("yes")
    assert gateway.summary


def test_advisory_endpoint_serves_ingested_report(monkeypatch):
    """GET /advisory returns the raw markdown and parsed campaigns."""
    stub = Advisory(
        raw_markdown="# TawasolPay, MDR Advisory\nRisk level: HIGH.",
        campaigns=load_advisory(_REPORT).campaigns,
    )
    monkeypatch.setattr(main, "_load_advisory", lambda: stub)
    main._advisory.cache_clear()
    client = TestClient(main.app)

    body = client.get("/advisory").json()

    assert "MDR Advisory" in body["raw_markdown"]
    assert len(body["campaigns"]) == 5
    assert body["campaigns"][0]["name"]
