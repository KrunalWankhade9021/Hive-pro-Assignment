"""FastAPI service exposing the prioritised, explainable risk picture.

The heavy work (loading the embedding model, the vector store, and building the
ranked risks) happens once and is cached, so each HTTP request just serves the
prepared result. The retriever, KEV lookup, and explainer are isolated behind
module-level factory functions so tests can substitute lightweight stubs.
"""
import logging
from functools import lru_cache

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

from app.advisory import load_advisory
from app.config import settings
from app.engine import build_risks
from app.explain import Explainer
from app.kev import load_kev
from app.loaders import (
    load_assets,
    load_remediation_hints,
    load_services,
    load_threat_intel,
    load_vulnerabilities,
)
from app.retriever import NistRetriever
from app.stats import compute_stats

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = FastAPI(
    title="TawasolPay Cyber Risk Assistant",
    description="Prioritised, explainable cyber-risk picture with NIST SP 800-53 guidance.",
    version="0.1.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


@lru_cache(maxsize=1)
def _load_data() -> dict:
    """Load and cache the full data pack from the dataset directory.

    Cached because several entry points need it (the ranked build, the retriever's
    remediation hints, the stats summary); without this the five CSVs are parsed
    once per caller on every cold build.
    """
    d = settings.dataset_dir
    return {
        "assets": load_assets(d / "assets.csv"),
        "vulns": load_vulnerabilities(d / "vulnerabilities.csv"),
        "intel": load_threat_intel(d / "threat_intelligence.csv"),
        "services": load_services(d / "business_services.csv"),
        "hints": load_remediation_hints(d / "remediation_guidance.csv"),
    }


def _load_kev_dict() -> dict:
    """Load the CISA KEV catalog built by scripts/build_kb.py."""
    return load_kev(settings.data_dir / "kev.parquet")


def _load_advisory():
    """Load the MDR threat advisory from the dataset directory."""
    return load_advisory(settings.dataset_dir / "synthetic_threat_report.md")


@lru_cache(maxsize=1)
def _build_retriever():
    """Build and cache the NIST retriever bound to the persisted vector store.

    Returns the ranked-retrieval callable so the engine can surface the primary
    control plus alternatives from a single query. Cached because constructing a
    retriever loads the sentence-transformer model and re-embeds the remediation
    hints; without this, every distinct ``n`` passed to /risks/top reloads both.
    """
    hints = _load_data()["hints"]
    return NistRetriever(settings.data_dir / "chroma", hints=hints).retrieve_ranked


def _build_explainer():
    """Build the risk explainer (Groq-backed, with template fallback)."""
    return Explainer(settings.groq_api_key).explain


@lru_cache(maxsize=8)
def _risks(n: int = 5):
    """Build and cache the top-n ranked risks (heavy; computed once per n)."""
    log.info("building top-%d risks", n)
    return build_risks(
        _load_data(),
        kev=_load_kev_dict(),
        retriever=_build_retriever(),
        explainer=_build_explainer(),
        n=n,
    )


@lru_cache(maxsize=1)
def _stats() -> dict:
    """Compute and cache portfolio-level summary counts (cheap; no model/LLM)."""
    data = _load_data()
    return compute_stats(data["assets"], data["vulns"], data["intel"], _load_kev_dict())


@lru_cache(maxsize=1)
def _advisory() -> dict:
    """Load and cache the MDR advisory (raw markdown plus parsed campaigns)."""
    return _load_advisory().model_dump()


@app.get("/health")
def health():
    """Liveness probe."""
    return {"status": "ok", "groq_enabled": settings.groq_api_key is not None}


@app.get("/stats")
def stats():
    """Return portfolio-level summary counts for the dashboard header."""
    return _stats()


@app.get("/advisory")
def advisory():
    """Return the ingested MDR threat advisory (raw markdown and parsed campaigns)."""
    return _advisory()


@app.get("/risks/top")
def top(n: int = Query(5, ge=1, le=25)):
    """Return the top-n ranked risks with evidence, NIST guidance, and explanation.

    ``n`` is bounded: each risk costs two embeddings plus one LLM call, and an
    unbounded value would build (and cache) the whole 114-risk set per request.
    A negative value would also slice the ranked list from the end.
    """
    return [r.model_dump() for r in _risks(n)]
