from typing import Callable

from pydantic import BaseModel

from app.join import join, JoinedRisk
from app.kev import match_kev, KevEntry, KevMatch
from app.threat_match import index_threats, match_threat
from app.scoring import score_risk


class NistControl(BaseModel):
    id: str
    title: str
    text: str
    similarity: float


class RankedRisk(BaseModel):
    rank: int
    risk_score: float
    score_breakdown: dict[str, float]
    asset: dict
    vulnerability: dict
    matched_threat: dict | None
    kev: KevMatch
    business_service: dict | None
    nist_control: NistControl | None = None
    explanation: str = ""


def build_risks(
    data,
    kev: dict[str, KevEntry],
    retriever: Callable[[JoinedRisk], NistControl],
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
    scored.sort(key=lambda x: x[0].score, reverse=True)
    out: list[RankedRisk] = []
    for i, (sr, jr, km, th) in enumerate(scored[:n], start=1):
        risk = RankedRisk(
            rank=i,
            risk_score=sr.score,
            score_breakdown=sr.breakdown,
            asset=jr.asset.model_dump(),
            vulnerability=jr.vulnerability.model_dump(),
            matched_threat=th.model_dump() if th else None,
            kev=km,
            business_service=jr.service.model_dump() if jr.service else None,
        )
        risk.nist_control = retriever(jr)
        risk.explanation = explainer(risk)
        out.append(risk)
    return out
