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
        normalized_score=98.7,
        asset={
            "asset_name": "load-balancer-prod-01",
            "internet_exposed": True,
            "environment": "Production",
            "edr_installed": False,
        },
        vulnerability={
            "cve": "CVE-2023-4966",
            "cvss": 9.4,
            "vulnerability_name": "Citrix ADC Session Token Leak",
            "exploit_available": True,
            "days_open": 180,
            "auth_required": False,
        },
        matched_threat={
            "campaign_name": "IronVeil",
            "threat_actor": "IronVeil",
            "ransomware_association": True,
        },
        kev=KevMatch(in_kev=True, ransomware=True, date_added="2023-10-18"),
        business_service={
            "business_service": "Payment Processing",
            "compliance_scope": "PCI DSS",
            "revenue_impact": "Critical",
        },
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


def test_explainer_falls_back_when_the_response_is_truncated():
    """A reply cut off at the token cap is discarded, not shown as a half sentence."""
    risk = _risk()
    explainer = Explainer(groq_api_key=None)
    explainer._client = _FakeGroq(
        "Ranks #1 because the internet-facing load balancer is",
        finish_reason="length",
    )

    assert explainer.explain(risk) == template_explanation(risk)


def test_fact_payload_carries_no_scoring_weights():
    """Weights are passed as factor names only, so no weight can be read as a CVSS.

    ``score_breakdown`` holds values like ``cvss_base=23.5`` (CVSS scaled onto a
    25-point slot). Sending those alongside the real ``cvss`` invited the model to
    quote an impossible severity, so only the real CVSS appears as a number.
    """
    risk = _risk()

    facts = Explainer._facts(risk)

    assert facts["cvss"] == 9.4
    assert facts["ranking_factors_that_applied"] == sorted(risk.score_breakdown)
    numeric = {k: v for k, v in facts.items() if isinstance(v, (int, float)) and not isinstance(v, bool)}
    assert 23.5 not in numeric.values(), f"a scoring weight leaked into the payload: {numeric}"


def test_fact_payload_labels_each_ranking_factor():
    """The assignment's ranking factors are passed as explicit labelled evidence."""
    facts = Explainer._facts(_risk())

    for key in (
        "internet_exposed",
        "exploit_available",
        "kev_ransomware_associated",
        "matched_threat_campaign",
        "revenue_impact",
        "compliance_scope",
        "edr_installed",
    ):
        assert key in facts, f"missing labelled ranking factor: {key}"


class _FakeGroq:
    """Minimal stand-in for the Groq client mirroring chat.completions.create."""

    def __init__(
        self,
        content: str = "",
        error: Exception | None = None,
        finish_reason: str = "stop",
    ):
        self._content = content
        self._error = error
        self._finish_reason = finish_reason
        self.chat = self  # so .chat.completions.create resolves back here
        self.completions = self

    def create(self, **kwargs):
        if self._error:
            raise self._error
        message = type("M", (), {"content": self._content})
        choice = type("C", (), {"message": message, "finish_reason": self._finish_reason})
        return type("R", (), {"choices": [choice]})
