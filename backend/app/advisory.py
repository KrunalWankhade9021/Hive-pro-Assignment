"""Ingest the MDR threat advisory (synthetic_threat_report.md).

The advisory is the 1-page report that "arrives in the inbox this morning" and
triggers the whole assessment. It is surfaced verbatim in the dashboard for
context, and its individual campaigns are parsed out so they can be listed
alongside the raw text. The parser is intentionally lenient: any field it cannot
find is left as None, and the raw markdown is always returned intact.
"""
import re
from pathlib import Path

from pydantic import BaseModel

# Matches a campaign heading of the form:  ### 1. CrimsonJackal — "Gateway Breaker"
_HEADING = re.compile(
    r'^###\s*\d+\.\s*(?P<actor>[^—–-]+?)\s*[—–-]\s*"(?P<name>[^"]+)"\s*$'
)
# Matches a "**Field:** value" line inside a campaign block.
_FIELD = re.compile(r'^\*\*(?P<field>[^:*]+):\*\*\s*(?P<value>.+?)\s*$')


class Campaign(BaseModel):
    """One active threat campaign described in the advisory."""

    name: str
    threat_actor: str | None = None
    target_profile: str | None = None
    exploit_chain: str | None = None
    ransomware: str | None = None
    confidence: str | None = None
    summary: str | None = None


class Advisory(BaseModel):
    """The full MDR advisory: the raw markdown plus its parsed campaigns."""

    raw_markdown: str
    campaigns: list[Campaign]


def _parse_campaigns(markdown: str) -> list[Campaign]:
    """Extract each campaign block from the advisory markdown.

    Splits on the numbered campaign headings and reads the bold key/value lines
    (Target profile, Exploit chain, Ransomware, Confidence) plus the first prose
    paragraph as the summary. Robust to missing fields.
    """
    lines = markdown.splitlines()
    campaigns: list[Campaign] = []
    current: dict | None = None
    summary_parts: list[str] = []

    def _flush() -> None:
        if current is None:
            return
        summary = " ".join(p.strip() for p in summary_parts if p.strip()) or None
        campaigns.append(
            Campaign(
                name=current["name"],
                threat_actor=current.get("threat_actor"),
                target_profile=current.get("target_profile"),
                exploit_chain=current.get("exploit_chain"),
                ransomware=current.get("ransomware"),
                confidence=current.get("confidence"),
                summary=summary,
            )
        )

    for line in lines:
        heading = _HEADING.match(line.strip())
        if heading:
            _flush()
            current = {
                "name": heading.group("name").strip(),
                "threat_actor": heading.group("actor").strip() or None,
            }
            summary_parts = []
            continue
        if current is None:
            continue
        # A new section ("## ...") ends the campaign list.
        if line.startswith("## "):
            _flush()
            current = None
            continue
        field = _FIELD.match(line.strip())
        if field:
            key = field.group("field").strip().lower()
            value = field.group("value").strip()
            if key.startswith("target"):
                current["target_profile"] = value
            elif key.startswith("exploit"):
                current["exploit_chain"] = value
            elif key.startswith("ransomware"):
                current["ransomware"] = value
            elif key.startswith("confidence"):
                current["confidence"] = value
            # IOCs and any other bold fields are ignored for the summary.
            continue
        if line.startswith("**IOCs"):
            continue
        # Remaining non-empty, non-separator prose becomes the summary.
        stripped = line.strip()
        if stripped and stripped != "---":
            summary_parts.append(stripped)

    _flush()
    return campaigns


def load_advisory(path) -> Advisory:
    """Load and parse the MDR advisory markdown at ``path``."""
    raw = Path(path).read_text(encoding="utf-8")
    return Advisory(raw_markdown=raw, campaigns=_parse_campaigns(raw))
