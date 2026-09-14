from collections import defaultdict

from app.models import ThreatIntel

_CONF = {"High": 3, "Medium": 2, "Low": 1}


def index_threats(intel: list[ThreatIntel]) -> dict[str, list[ThreatIntel]]:
    idx: dict[str, list[ThreatIntel]] = defaultdict(list)
    for t in intel:
        idx[t.matched_cve_or_control].append(t)
    return dict(idx)


def match_threat(cve: str, index: dict[str, list[ThreatIntel]]) -> ThreatIntel | None:
    hits = index.get(cve)
    if not hits:
        return None
    return sorted(
        hits,
        key=lambda t: (t.ransomware_association, _CONF.get(t.confidence, 0)),
        reverse=True,
    )[0]
