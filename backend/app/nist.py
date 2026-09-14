"""NIST SP 800-53 Rev.5 retrieval knowledge base.

Fetches the authoritative machine-readable OSCAL control catalog published by
NIST (usnistgov/oscal-content), flattens every control and control
enhancement into ``{id, title, text}`` records, and embeds them into a
persisted ChromaDB collection for semantic retrieval.

The control text is taken verbatim from the fetched catalog — never hardcoded
and never sourced from the LLM — so remediation guidance is genuinely grounded
in the real document.
"""
import logging
from pathlib import Path

import chromadb
import requests
from sentence_transformers import SentenceTransformer

log = logging.getLogger(__name__)

OSCAL_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)
MODEL = "BAAI/bge-small-en-v1.5"
COLLECTION = "nist80053"


def _prose(part: dict) -> str:
    """Recursively collect prose from an OSCAL part and its sub-parts."""
    text = part.get("prose", "") or ""
    for sub in part.get("parts", []):
        text += " " + _prose(sub)
    return text


def _statement(control: dict) -> str:
    """Join the prose of a control's ``statement`` parts into one string."""
    return " ".join(
        _prose(part)
        for part in control.get("parts", [])
        if part.get("name") == "statement"
    ).strip()


def _walk(node: dict, out: list[dict]) -> None:
    """Depth-first flatten controls, nested enhancements, and sub-groups."""
    for control in node.get("controls", []):
        out.append(
            {
                "id": control["id"],
                "title": control.get("title", ""),
                "text": _statement(control),
            }
        )
        _walk(control, out)  # control enhancements nest under "controls"
    for group in node.get("groups", []):
        _walk(group, out)


def parse_oscal(catalog_json: dict) -> list[dict]:
    """Flatten an OSCAL catalog into ``[{id, title, text}]`` records."""
    out: list[dict] = []
    _walk(catalog_json["catalog"], out)
    return out


def fetch_oscal() -> dict:
    """Download the NIST 800-53 Rev.5 OSCAL catalog JSON."""
    resp = requests.get(OSCAL_URL, timeout=60)
    resp.raise_for_status()
    return resp.json()


def build_chroma(controls: list[dict], persist_dir: Path) -> None:
    """Embed controls with the configured model into a persisted cosine collection."""
    persist_dir = Path(persist_dir)
    persist_dir.mkdir(parents=True, exist_ok=True)

    model = SentenceTransformer(MODEL)
    documents = [f"{c['id'].upper()} {c['title']}. {c['text']}" for c in controls]
    embeddings = model.encode(
        documents, show_progress_bar=True, normalize_embeddings=True
    ).tolist()

    client = chromadb.PersistentClient(path=str(persist_dir))
    try:
        client.delete_collection(COLLECTION)
    except Exception:  # collection does not exist yet
        pass
    collection = client.create_collection(
        COLLECTION, metadata={"hnsw:space": "cosine"}
    )
    collection.add(
        ids=[c["id"] for c in controls],
        embeddings=embeddings,
        documents=[c["text"] for c in controls],
        metadatas=[{"id": c["id"], "title": c["title"]} for c in controls],
    )
    log.info("indexed %d NIST controls", len(controls))
