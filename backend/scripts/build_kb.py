"""Build the knowledge base: CISA KEV catalog + NIST 800-53 vector store.

Run once before serving the API (and at deploy time). Fetches the CISA KEV
catalog into a parquet file for structured lookups, and the NIST SP 800-53
OSCAL catalog which is parsed and embedded into a persisted ChromaDB store
for semantic retrieval.

Usage:  python scripts/build_kb.py
"""
import logging
from pathlib import Path

from app.kev import fetch_kev
from app.nist import build_chroma, fetch_oscal, parse_oscal

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("build_kb")

DATA = Path(__file__).resolve().parents[1] / "data"


def main() -> None:
    log.info("fetching CISA KEV catalog...")
    fetch_kev(DATA / "kev.parquet")

    log.info("fetching NIST 800-53 OSCAL catalog...")
    controls = parse_oscal(fetch_oscal())
    log.info("parsed %d NIST controls; embedding...", len(controls))
    build_chroma(controls, DATA / "chroma")
    log.info("knowledge base build complete")


if __name__ == "__main__":
    main()
