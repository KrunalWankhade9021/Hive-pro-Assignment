"""Regression guard on RAG retrieval quality over the golden set.

Skipped when the persisted vector store is absent (fresh clone), so the suite
stays green without a built index. The floor is deliberately modest: the goal is
to catch a regression that collapses retrieval quality, not to freeze exact
scores that legitimately drift with the embedding model or catalog version.
"""
from pathlib import Path

import pytest

_CHROMA = Path(__file__).resolve().parents[1] / "data" / "chroma"
pytestmark = pytest.mark.skipif(not _CHROMA.exists(), reason="run scripts/build_kb.py first")


def test_dense_retrieval_meets_quality_floor():
    """Dense retrieval clears a modest family-level hit-rate floor on the golden set."""
    from eval.evaluate_rag import evaluate

    result = evaluate("dense")

    assert result["n"] >= 18, "golden set should hold a meaningful number of cases"
    assert result["hit_rate_3"] >= 0.5, f"Hit-rate@3 regressed: {result['hit_rate_3']:.2f}"
    assert result["hit_rate_1"] >= 0.35, f"Hit-rate@1 regressed: {result['hit_rate_1']:.2f}"
    assert result["mean_similarity"] >= 0.4, "top-1 similarity unexpectedly low"


def test_evaluate_runs_in_hybrid_mode():
    """The hybrid experiment path runs and returns the same metric shape."""
    from eval.evaluate_rag import evaluate

    result = evaluate("hybrid")

    assert result["mode"] == "hybrid"
    assert set(result) >= {"hit_rate_1", "hit_rate_3", "mrr", "mean_similarity", "rows"}
    assert len(result["rows"]) == result["n"]
