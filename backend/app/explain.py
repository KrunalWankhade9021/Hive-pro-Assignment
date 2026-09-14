"""Plain-English "why it ranks here" explanations for a ranked risk.

Two paths, same signature:

* ``template_explanation`` builds a deterministic sentence purely from the score
  breakdown and evidence already computed by the engine. It is the primary
  correctness path -- the live system falls back to it whenever the LLM is
  missing, rate-limited, or errors -- so it must read well on its own.
* ``Explainer`` optionally uses Groq to phrase the same evidence more naturally,
  but is constrained to the provided facts and degrades to the template on any
  failure, so the LLM can never invent a reason or break the response.
"""
import logging

from app.engine import RankedRisk

log = logging.getLogger(__name__)

_GROQ_MODEL = "llama-3.3-70b-versatile"

_PROMPT = (
    "You are a cyber-risk analyst briefing a technical manager. In ONE plain-English "
    "sentence, explain why this risk ranks #{rank} out of the organisation's open risks. "
    "Use ONLY the facts below -- do not invent CVEs, scores, or campaigns, and do not "
    "recommend fixes. Facts: {facts}"
)


def template_explanation(risk: RankedRisk) -> str:
    """Return a deterministic one-sentence rationale for this risk's ranking."""
    asset, vuln, breakdown = risk.asset, risk.vulnerability, risk.score_breakdown
    service = (risk.business_service or {}).get("business_service", "an unmapped service")

    reasons: list[str] = []
    if breakdown.get("internet_exposed"):
        reasons.append("it is internet-exposed")
    if breakdown.get("exploit_available"):
        reasons.append("a working exploit is available")
    if breakdown.get("kev_ransomware"):
        reasons.append("it is ransomware-associated in the CISA KEV catalog")
    if breakdown.get("threat_campaign") and risk.matched_threat:
        reasons.append(f"an active campaign ({risk.matched_threat.get('campaign_name')}) targets it")
    if breakdown.get("business_criticality"):
        reasons.append("it supports a revenue-critical service")
    if breakdown.get("compliance_scope"):
        reasons.append("the service is in PCI/GDPR compliance scope")
    if breakdown.get("missing_edr"):
        reasons.append("the host has no EDR coverage")

    reason = "; ".join(reasons) if reasons else "of its base severity"
    return (
        f"{vuln.get('vulnerability_name')} ({vuln.get('cve')}, CVSS {vuln.get('cvss')}) "
        f"on {asset.get('asset_name')} supporting {service} ranks #{risk.rank} "
        f"(weighted score {risk.risk_score}) because {reason}."
    )


class Explainer:
    """Generates risk explanations via Groq, falling back to the template."""

    def __init__(self, groq_api_key: str | None):
        self._client = None
        if groq_api_key:
            try:
                from groq import Groq

                self._client = Groq(api_key=groq_api_key)
            except Exception as exc:  # pragma: no cover - defensive init guard
                log.warning("Groq client init failed; using template explanations: %s", exc)

    def explain(self, risk: RankedRisk) -> str:
        """Return an LLM-phrased rationale, or the deterministic template on any failure."""
        if self._client is None:
            return template_explanation(risk)

        facts = {
            "rank": risk.rank,
            "weighted_score": risk.risk_score,
            "score_breakdown": risk.score_breakdown,
            "asset": risk.asset.get("asset_name"),
            "environment": risk.asset.get("environment"),
            "cve": risk.vulnerability.get("cve"),
            "vulnerability": risk.vulnerability.get("vulnerability_name"),
            "cvss": risk.vulnerability.get("cvss"),
            "business_service": (risk.business_service or {}).get("business_service"),
            "compliance_scope": (risk.business_service or {}).get("compliance_scope"),
            "matched_campaign": (risk.matched_threat or {}).get("campaign_name"),
            "kev_ransomware": risk.kev.ransomware,
            "in_cisa_kev": risk.kev.in_kev,
        }
        try:
            response = self._client.chat.completions.create(
                model=_GROQ_MODEL,
                temperature=0.2,
                max_tokens=160,
                messages=[{"role": "user", "content": _PROMPT.format(rank=risk.rank, facts=facts)}],
            )
            text = response.choices[0].message.content.strip()
            return text or template_explanation(risk)
        except Exception as exc:
            log.warning("Groq call failed; using template explanation: %s", exc)
            return template_explanation(risk)
