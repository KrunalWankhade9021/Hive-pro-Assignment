"""NIST SP 800-53 Rev.5 retrieval knowledge base.

Fetches the authoritative machine-readable OSCAL control catalog published by
NIST (usnistgov/oscal-content), flattens every control and control
enhancement into ``{id, title, text}`` records, and embeds them into a
persisted ChromaDB collection for semantic retrieval.

The control text is taken verbatim from the fetched catalog, never hardcoded
and never sourced from the LLM, so remediation guidance is genuinely grounded
in the real document.
"""
import logging
import re
from pathlib import Path

import chromadb
import requests
from sentence_transformers import SentenceTransformer

log = logging.getLogger(__name__)

# OSCAL embeds organization-defined parameters in control prose as
# ``{{ insert: param, <param_id> }}``. Left raw, these leak into the UI, so we
# resolve them to the human-readable form NIST uses in the published catalog:
# ``[assignment: <label>]`` for assignments and ``[selection: a; b]`` for choices.
_PARAM_RE = re.compile(r"\{\{\s*insert:\s*param,\s*([^}]+?)\s*\}\}")
_PLACEHOLDER_RE = re.compile(r"\{\{[^}]*\}\}")
_ODP_FALLBACK = "[assignment: organization-defined value]"

OSCAL_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)
MODEL = "BAAI/bge-small-en-v1.5"
COLLECTION = "nist80053"


def _param_display(param: dict) -> str:
    """Render one OSCAL parameter as readable ``[assignment: ...]``/``[selection: ...]``."""
    select = param.get("select")
    if select:
        choices = "; ".join(str(c).strip() for c in select.get("choice", []))
        return f"[selection: {choices}]" if choices else _ODP_FALLBACK
    label = param.get("label")
    if label:
        return f"[assignment: {label.strip()}]"
    guidelines = param.get("guidelines") or []
    if guidelines:
        prose = (guidelines[0].get("prose") or "").strip().rstrip(";. ")
        if prose:
            return f"[assignment: {prose}]"
    return _ODP_FALLBACK


def _param_map(params: list[dict]) -> dict[str, str]:
    """Map each parameter id to its readable display text."""
    return {p["id"]: _param_display(p) for p in params if "id" in p}


def _resolve_params(text: str, params: dict[str, str]) -> str:
    """Replace ``{{ insert: param, X }}`` placeholders with readable parameter text.

    Runs a few passes so placeholders nested inside substituted selection choices
    are resolved too, then guarantees no raw ``{{ ... }}`` survives.
    """
    for _ in range(3):
        if "{{" not in text:
            break
        text = _PARAM_RE.sub(
            lambda m: params.get(m.group(1).strip(), _ODP_FALLBACK), text
        )
    return _PLACEHOLDER_RE.sub(_ODP_FALLBACK, text)


def _prose(part: dict) -> str:
    """Recursively collect prose from an OSCAL part and its sub-parts."""
    text = part.get("prose", "") or ""
    for sub in part.get("parts", []):
        text += " " + _prose(sub)
    return text


def _raw_statement(control: dict) -> str:
    """Join a control's ``statement`` prose verbatim (parameter placeholders intact)."""
    return " ".join(
        _prose(part)
        for part in control.get("parts", [])
        if part.get("name") == "statement"
    ).strip()


def _walk(node: dict, out: list[dict], inherited: dict[str, str] | None = None) -> None:
    """Depth-first flatten controls, nested enhancements, and sub-groups.

    Parameters defined on a control are inherited by its enhancements, since an
    enhancement's prose can reference a parameter declared on its parent control.
    Each record carries ``text`` (readable, parameters resolved, for display) and
    ``embed_text`` (verbatim statement, used for embedding, where resolving the
    parameters into shared boilerplate would blur controls together and hurt
    retrieval).
    """
    inherited = inherited or {}
    for control in node.get("controls", []):
        params = {**inherited, **_param_map(control.get("params", []))}
        raw = _raw_statement(control)
        out.append(
            {
                "id": control["id"],
                "title": control.get("title", ""),
                "text": _resolve_params(raw, params),
                "embed_text": raw,
            }
        )
        _walk(control, out, params)  # control enhancements nest under "controls"
    for group in node.get("groups", []):
        _walk(group, out, inherited)


def parse_oscal(catalog_json: dict) -> list[dict]:
    """Flatten an OSCAL catalog into ``[{id, title, text, embed_text}]`` records.

    ``text`` has parameters resolved for display; ``embed_text`` is the verbatim
    statement used as the embedding input.
    """
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
    # Embed the verbatim statement (``embed_text``); the resolved, readable prose
    # (``text``) is what we store and display. Resolving parameters into shared
    # organization-defined boilerplate before embedding measurably hurt retrieval.
    embed_inputs = [
        f"{c['id'].upper()} {c['title']}. {c.get('embed_text', c['text'])}"
        for c in controls
    ]
    embeddings = model.encode(
        embed_inputs, show_progress_bar=True, normalize_embeddings=True
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
