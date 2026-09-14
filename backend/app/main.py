"""FastAPI service exposing the prioritised, explainable risk picture.

The heavy work (loading the embedding model, the vector store, and building the
ranked risks) happens once and is cached, so each HTTP request just serves the
prepared result. The retriever, KEV lookup, and explainer are isolated behind
module-level factory functions so tests can substitute lightweight stubs.
"""
import logging
from functools import lru_cache

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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


def _load_data() -> dict:
    """Load the full data pack from the dataset directory."""
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


def _build_retriever():
    """Build the NIST retriever bound to the persisted vector store."""
    hints = _load_data()["hints"]
    return NistRetriever(settings.data_dir / "chroma", hints=hints).retrieve


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


@app.get("/health")
def health():
    """Liveness probe."""
    return {"status": "ok", "groq_enabled": settings.groq_api_key is not None}


@app.get("/risks/top")
def top(n: int = 5):
    """Return the top-n ranked risks with evidence, NIST guidance, and explanation."""
    return [r.model_dump() for r in _risks(n)]
