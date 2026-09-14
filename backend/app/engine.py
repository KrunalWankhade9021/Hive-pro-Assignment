from collections import Counter
from typing import Callable

from pydantic import BaseModel

from app.join import join, JoinedRisk
from app.kev import match_kev, KevEntry, KevMatch
from app.threat_match import index_threats, match_threat
from app.scoring import score_risk


_REVENUE_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
_ENV_RANK = {"Production": 3, "Staging": 2, "Development": 1}

# Theoretical maximum of the additive scoring formula, used to normalise the raw
# score onto a 0-100 scale for display: cvss_base 25 + internet 20 + exploit 15
# + kev_ransomware 15 + threat_campaign 15 + revenue 10 + compliance 5
# + missing_edr 5 + no_auth 3 + long_open 2 = 115. Dividing by a constant
# preserves ordering exactly (unlike clamping, which flattens the top).
_MAX_SCORE = 115.0


def _sort_key(entry):
    """Deterministic ranking key so tied scores never fall back to input order.

    Descending on raw score, then business revenue-impact rank, then CVSS, then
    days_open, then environment rank (Production > Staging > Development); final
    ascending tiebreak on vuln_id for full determinism.
    """
    sr, jr, _km, _th = entry
    rev_rank = _REVENUE_RANK.get(jr.service.revenue_impact, 0) if jr.service else 0
    env_rank = _ENV_RANK.get(jr.asset.environment, 0)
    return (
        -sr.score,
        -rev_rank,
        -jr.vulnerability.cvss,
        -jr.vulnerability.days_open,
        -env_rank,
        jr.vulnerability.vuln_id,
    )


class NistControl(BaseModel):
    id: str
    title: str
    text: str
    similarity: float


class RankedRisk(BaseModel):
    rank: int
    risk_score: float
    normalized_score: float = 0.0
    score_breakdown: dict[str, float]
    asset: dict
    vulnerability: dict
    matched_threat: dict | None
    kev: KevMatch
    business_service: dict | None
    nist_control: NistControl | None = None
    alternative_controls: list[NistControl] = []
    cve_concentration: int = 1
    explanation: str = ""


def _alternatives(ranked: list[NistControl], primary_id: str, limit: int = 2) -> list[NistControl]:
    """Return up to ``limit`` ranked controls with ids distinct from the primary."""
    seen = {primary_id}
    out: list[NistControl] = []
    for control in ranked:
        if control.id in seen:
            continue
        seen.add(control.id)
        out.append(control)
        if len(out) >= limit:
            break
    return out


def build_risks(
    data,
    kev: dict[str, KevEntry],
    retriever: Callable[[JoinedRisk], list[NistControl]],
    explainer: Callable[["RankedRisk"], str],
    n: int = 5,
) -> list[RankedRisk]:
    joined = join(data["vulns"], data["assets"], data["services"])
    tindex = index_threats(data["intel"])
    scored = []
    for jr in joined:
        km = match_kev(jr.vulnerability.cve, kev)
        th = match_threat(jr.vulnerability.cve, tindex)
        sr = score_risk(jr, km, th)
        scored.append((sr, jr, km, th))
    scored.sort(key=_sort_key)

    top = scored[:n]
    # How many of the returned risks share each CVE, so the UI can flag a single
    # vulnerability hitting multiple assets in the top list.
    cve_counts = Counter(jr.vulnerability.cve for _sr, jr, _km, _th in top)

    out: list[RankedRisk] = []
    for i, (sr, jr, km, th) in enumerate(top, start=1):
        risk = RankedRisk(
            rank=i,
            risk_score=sr.score,
            normalized_score=round(sr.score / _MAX_SCORE * 100, 1),
            score_breakdown=sr.breakdown,
            asset=jr.asset.model_dump(),
            vulnerability=jr.vulnerability.model_dump(),
            matched_threat=th.model_dump() if th else None,
            kev=km,
            business_service=jr.service.model_dump() if jr.service else None,
            cve_concentration=cve_counts[jr.vulnerability.cve],
        )
        ranked_controls = retriever(jr)
        if ranked_controls:
            risk.nist_control = ranked_controls[0]
            risk.alternative_controls = _alternatives(ranked_controls, ranked_controls[0].id)
        risk.explanation = explainer(risk)
        out.append(risk)
    return out
