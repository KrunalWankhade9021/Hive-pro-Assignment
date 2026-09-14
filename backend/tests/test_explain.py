"""Tests for risk explanations.

The explanation is the plain-English "why it ranks here" sentence a technical
manager reads. The deterministic template is the primary correctness path (the
live demo falls back to it whenever Groq is unavailable or rate-limited), so it
is tested directly; the Groq path is tested with a fake client so no network or
API key is required.
"""
from app.engine import NistControl, RankedRisk
from app.explain import Explainer, template_explanation
from app.kev import KevMatch


def _risk(**overrides) -> RankedRisk:
    """Build a representative top-risk (CitrixBleed-style) for explanation tests."""
    defaults = dict(
        rank=1,
        risk_score=113.5,
        score_breakdown={
            "cvss_base": 23.5,
            "internet_exposed": 20,
            "exploit_available": 15,
            "kev_ransomware": 15,
            "threat_campaign": 15,
            "business_criticality": 10,
            "compliance_scope": 5,
        },
        asset={"asset_name": "load-balancer-prod-01", "internet_exposed": True, "environment": "Production"},
        vulnerability={"cve": "CVE-2023-4966", "cvss": 9.4, "vulnerability_name": "Citrix ADC Session Token Leak"},
        matched_threat={"campaign_name": "IronVeil", "ransomware_association": True},
        kev=KevMatch(in_kev=True, ransomware=True, date_added="2023-10-18"),
        business_service={"business_service": "Payment Processing", "compliance_scope": "PCI DSS"},
        nist_control=NistControl(id="sc-23", title="Session Authenticity", text="Protect the authenticity of sessions.", similarity=0.67),
    )
    defaults.update(overrides)
    return RankedRisk(**defaults)


def test_template_names_vuln_asset_and_service():
    """The sentence identifies the vulnerability, CVE, asset, and business service."""
    sentence = template_explanation(_risk())

    assert "CVE-2023-4966" in sentence
    assert "load-balancer-prod-01" in sentence
    assert "Payment Processing" in sentence


def test_template_states_the_ranking_drivers_from_the_breakdown():
    """The sentence explains WHY it ranks: exposure, exploitation, ransomware, campaign."""
    sentence = template_explanation(_risk()).lower()

    assert "internet" in sentence
    assert "ransomware" in sentence
    assert "ironveil" in sentence  # the matched campaign is named


def test_template_handles_a_risk_with_no_service_or_threat():
    """A risk with no mapped service and no campaign still yields a clean sentence."""
    bare = _risk(
        score_breakdown={"cvss_base": 25.0},
        matched_threat=None,
        business_service=None,
        kev=KevMatch(in_kev=False, ransomware=False),
    )

    sentence = template_explanation(bare)

    assert "unmapped service" in sentence
    assert sentence.endswith(".")


def test_explainer_without_key_uses_the_template():
    """With no API key, Explainer returns exactly the deterministic template."""
    risk = _risk()

    assert Explainer(groq_api_key=None).explain(risk) == template_explanation(risk)


def test_explainer_uses_groq_response_when_the_client_succeeds():
    """When the Groq client returns text, that text is surfaced (not the template)."""
    risk = _risk()
    explainer = Explainer(groq_api_key=None)
    explainer._client = _FakeGroq("Ranks #1 because it is an internet-facing, ransomware-linked payment gateway flaw.")

    result = explainer.explain(risk)

    assert result == "Ranks #1 because it is an internet-facing, ransomware-linked payment gateway flaw."
    assert result != template_explanation(risk)


def test_explainer_falls_back_to_template_when_groq_raises():
    """Any Groq error (rate limit, network, bad key) degrades to the template."""
    risk = _risk()
    explainer = Explainer(groq_api_key=None)
    explainer._client = _FakeGroq(error=RuntimeError("rate limited"))

    assert explainer.explain(risk) == template_explanation(risk)


class _FakeGroq:
    """Minimal stand-in for the Groq client mirroring chat.completions.create."""

    def __init__(self, content: str = "", error: Exception | None = None):
        self._content = content
        self._error = error
        self.chat = self  # so .chat.completions.create resolves back here
        self.completions = self

    def create(self, **kwargs):
        if self._error:
            raise self._error
        message = type("M", (), {"content": self._content})
        choice = type("C", (), {"message": message})
        return type("R", (), {"choices": [choice]})
