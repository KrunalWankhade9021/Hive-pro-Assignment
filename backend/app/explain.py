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
import os

from app.engine import RankedRisk

log = logging.getLogger(__name__)

# Groq's hosted model lineup rotates; the model id is env-configurable so it can
# be updated without a code change. Qwen 3 returns clean single-sentence output
# (the gpt-oss models emit only hidden reasoning tokens here).
_GROQ_MODEL = os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b")

# One sentence needs well under this; the headroom exists so a chattier model
# (GROQ_MODEL is overridable) is not silently truncated. Truncation is detected
# via finish_reason regardless.
_MAX_TOKENS = 220

# The assignment requires "a plain-English sentence explaining why this ranks
# here", readable by a technical manager. The rules below encode the boundaries
# that keep that sentence defensible: the scoring engine owns the rank, the
# retrieved NIST control owns the remediation, and the model owns only the
# phrasing of evidence it was handed.
_PROMPT = (
    "You are a cyber-risk analyst briefing a technical manager.\n"
    "Write ONE plain-English sentence explaining why this risk is ranked #{rank}.\n"
    "Rules:\n"
    "- Use ONLY the facts provided. Never state a number, CVE, campaign, product "
    "or control that does not appear in them.\n"
    "- The rank and score come from a deterministic scoring engine. Report them if "
    "useful; never recompute, adjust or dispute them.\n"
    "- Ground the sentence in the drivers that are actually true here: internet "
    "exposure, an available exploit, CISA KEV ransomware association, a matched "
    "threat campaign, business criticality or compliance scope, and missing "
    "compensating controls such as EDR.\n"
    "- Do NOT recommend remediation or next steps. The applicable NIST SP 800-53 "
    "control is retrieved and shown separately.\n"
    "- No preamble, no list, no quotation marks. Return the sentence and nothing else.\n"
    "Facts: {facts}"
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

    @staticmethod
    def _facts(risk: RankedRisk) -> dict:
        """Build the fact payload the model is allowed to draw on.

        Each of the assignment's ranking factors is passed as its own labelled
        value rather than left to be inferred from the score breakdown, so the
        model cites evidence instead of reverse-engineering weights.

        Scoring *weights* are deliberately passed as factor names only, with no
        numbers: a weight such as ``cvss_base`` (CVSS scaled onto a 25-point
        slot) is not a CVSS score, and sending both invites the model to quote
        an impossible severity like "CVSS 23.5". The only number named ``cvss``
        here is the real one.
        """
        asset, vuln = risk.asset, risk.vulnerability
        service = risk.business_service or {}
        threat = risk.matched_threat or {}
        return {
            "rank": risk.rank,
            "score_out_of_100": risk.normalized_score,
            "vulnerability": vuln.get("vulnerability_name"),
            "cve": vuln.get("cve"),
            "cvss": vuln.get("cvss"),
            "days_open": vuln.get("days_open"),
            "authentication_required": vuln.get("auth_required"),
            "asset": asset.get("asset_name"),
            "environment": asset.get("environment"),
            "internet_exposed": asset.get("internet_exposed"),
            "edr_installed": asset.get("edr_installed"),
            "exploit_available": vuln.get("exploit_available"),
            "in_cisa_kev": risk.kev.in_kev,
            "kev_ransomware_associated": risk.kev.ransomware,
            "matched_threat_campaign": threat.get("campaign_name"),
            "threat_actor": threat.get("threat_actor"),
            "business_service": service.get("business_service"),
            "revenue_impact": service.get("revenue_impact"),
            "compliance_scope": service.get("compliance_scope"),
            "ranking_factors_that_applied": sorted(risk.score_breakdown),
        }

    def explain(self, risk: RankedRisk) -> str:
        """Return an LLM-phrased rationale, or the deterministic template on any failure."""
        if self._client is None:
            return template_explanation(risk)

        facts = self._facts(risk)
        try:
            response = self._client.chat.completions.create(
                model=_GROQ_MODEL,
                temperature=0.2,
                max_tokens=_MAX_TOKENS,
                messages=[{"role": "user", "content": _PROMPT.format(rank=risk.rank, facts=facts)}],
            )
            choice = response.choices[0]
            # A response cut off at the token cap would surface as a half sentence,
            # so treat truncation as a failure rather than returning it verbatim.
            if getattr(choice, "finish_reason", None) == "length":
                log.warning("Groq response hit the token cap; using template explanation")
                return template_explanation(risk)
            text = (choice.message.content or "").strip()
            return text or template_explanation(risk)
        except Exception as exc:
            log.warning("Groq call failed; using template explanation: %s", exc)
            return template_explanation(risk)
