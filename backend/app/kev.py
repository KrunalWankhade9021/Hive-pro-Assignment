import logging
from pathlib import Path

import requests
import pandas as pd
from pydantic import BaseModel

log = logging.getLogger(__name__)
_SOURCES = [
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
]


class KevEntry(BaseModel):
    cve: str
    ransomware: bool
    date_added: str | None = None
    required_action: str | None = None


class KevMatch(BaseModel):
    in_kev: bool
    ransomware: bool
    date_added: str | None = None
    required_action: str | None = None


def fetch_kev(dest: Path) -> Path:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    data = None
    for url in _SOURCES:
        try:
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            data = r.json()
            break
        except Exception as e:
            log.warning("KEV source failed %s: %s", url, e)
    if data is None:
        raise RuntimeError("all KEV sources failed")
    rows = [
        {
            "cve": v["cveID"],
            "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
            "date_added": v.get("dateAdded"),
            "required_action": v.get("requiredAction"),
        }
        for v in data["vulnerabilities"]
    ]
    pd.DataFrame(rows).to_parquet(dest, index=False)
    log.info("wrote %d KEV entries to %s", len(rows), dest)
    return dest


def load_kev(path: Path) -> dict[str, KevEntry]:
    df = pd.read_parquet(path)
    return {
        row.cve: KevEntry(
            cve=row.cve,
            ransomware=bool(row.ransomware),
            date_added=row.date_added,
            required_action=row.required_action,
        )
        for row in df.itertuples()
    }


def match_kev(cve: str, kev: dict[str, KevEntry]) -> KevMatch:
    e = kev.get(cve)
    if e is None:
        return KevMatch(in_kev=False, ransomware=False)
    return KevMatch(
        in_kev=True,
        ransomware=e.ransomware,
        date_added=e.date_added,
        required_action=e.required_action,
    )
