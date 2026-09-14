"""Retrieve the most relevant NIST SP 800-53 control for a risk.

The structured risk data is joined and scored elsewhere; this module handles the
semantic half of the system: given a vulnerability, find the control in the
embedded NIST catalog whose prose best matches the remediation need.

Two embedding lookups shape the query, and both use the ``remediation_guidance.csv``
hints only to *build the query*, never as the answer:

1. The vulnerability is matched to its closest remediation hint by cosine
   similarity (the hint is a domain expert's one-line categorisation of the
   finding, which describes the remediation intent far better than the
   product-specific vulnerability name does).
2. That hint's ``finding_type`` + ``recommended_action`` becomes the query text
   used to retrieve the best-matching NIST control.

Retrieval runs in one of two modes:

- ``"dense"``, pure cosine similarity over the embedded control catalog.
- ``"hybrid"``, the dense ranking fused with a BM25 lexical ranking over the
  same control corpus via Reciprocal Rank Fusion (RRF).

The returned guidance text always comes from the embedded NIST catalog itself,
and the displayed ``similarity`` is always the dense cosine score so the number
shown to a user stays meaningful regardless of mode.
"""
import re
from pathlib import Path

import chromadb
from rank_bm25 import BM25Okapi
from sentence_transformers import SentenceTransformer

from app.engine import NistControl
from app.join import JoinedRisk
from app.models import RemediationHint
from app.nist import COLLECTION, MODEL

# Base controls only (e.g. "si-2"), excluding enhancements ("si-2.2"). For
# remediation guidance a technical manager can act on, the primary control is
# more useful than a narrow sub-enhancement.
_BASE_CONTROL = re.compile(r"^[a-z]{2}-\d+$")

# Candidate pool pulled from the dense index before filtering / fusion.
_CANDIDATES = 40

# Standard RRF dampening constant (Cormack et al. 2009).
_RRF_K = 60

_WORD = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> list[str]:
    return _WORD.findall(text.lower())


class NistRetriever:
    """Semantic (and optionally hybrid) retriever over the NIST 800-53 catalog."""

    def __init__(
        self,
        persist_dir: Path,
        hints: list[RemediationHint],
        mode: str = "dense",
    ):
        if mode not in ("dense", "hybrid"):
            raise ValueError(f"unknown retriever mode: {mode!r}")
        self.mode = mode
        self.model = SentenceTransformer(MODEL)
        self.collection = chromadb.PersistentClient(
            path=str(persist_dir)
        ).get_collection(COLLECTION)
        self.hints = hints
        # Precompute hint embeddings once; reused for every retrieval.
        self._hint_embeddings = (
            self.model.encode(
                [f"{h.finding_type}. {h.recommended_action}" for h in hints],
                normalize_embeddings=True,
            )
            if hints
            else None
        )
        # A BM25 index over the whole control corpus is only needed for hybrid.
        self._bm25: BM25Okapi | None = None
        self._corpus_ids: list[str] = []
        self._corpus_meta: dict[str, dict] = {}
        self._corpus_doc: dict[str, str] = {}
        if mode == "hybrid":
            self._build_bm25_index()

    def _build_bm25_index(self) -> None:
        """Index every control's 'id title. prose' text for lexical search."""
        data = self.collection.get(include=["documents", "metadatas"])
        corpus_tokens = []
        for cid, doc, meta in zip(data["ids"], data["documents"], data["metadatas"]):
            self._corpus_ids.append(cid)
            self._corpus_meta[cid] = meta
            self._corpus_doc[cid] = doc or ""
            corpus_tokens.append(
                _tokenize(f"{meta.get('id', cid)} {meta.get('title', '')}. {doc or ''}")
            )
        self._bm25 = BM25Okapi(corpus_tokens)

    def _best_hint(self, joined: JoinedRisk) -> RemediationHint | None:
        """Return the remediation hint whose text is closest to the vulnerability."""
        if self._hint_embeddings is None:
            return None
        vuln = joined.vulnerability
        query = self.model.encode(
            [f"{vuln.vulnerability_name}. {vuln.affected_component}"],
            normalize_embeddings=True,
        )[0]
        scores = self._hint_embeddings @ query
        return self.hints[int(scores.argmax())]

    def _query_text(self, joined: JoinedRisk) -> str:
        """Build the retrieval query, biased toward the remediation intent."""
        hint = self._best_hint(joined)
        if hint is not None:
            return f"{hint.finding_type}. Remediation: {hint.recommended_action}"
        vuln = joined.vulnerability
        return f"{vuln.vulnerability_name}. Component: {vuln.affected_component}."

    def _dense_candidates(self, query_text: str) -> list[tuple[str, str, dict, float]]:
        """Return dense candidates as (id, doc, meta, cosine_similarity), best first."""
        embedding = self.model.encode([query_text], normalize_embeddings=True).tolist()
        result = self.collection.query(query_embeddings=embedding, n_results=_CANDIDATES)
        docs = result["documents"][0]
        metas = result["metadatas"][0]
        dists = result["distances"][0] if result.get("distances") else [0.0] * len(docs)
        return [
            (meta["id"], doc, meta, round(1 - dist, 3))
            for doc, meta, dist in zip(docs, metas, dists)
        ]

    def _base_with_prose(
        self, candidates: list[tuple[str, str, dict, float]]
    ) -> list[NistControl]:
        """Keep base controls that carry prose, preserving order."""
        return [
            NistControl(id=cid, title=meta["title"], text=doc, similarity=sim)
            for cid, doc, meta, sim in candidates
            if _BASE_CONTROL.match(cid) and doc and doc.strip()
        ]

    def _hybrid_ranked(self, query_text: str, k: int) -> list[NistControl]:
        """Fuse dense and BM25 rankings over base controls via RRF."""
        assert self._bm25 is not None
        dense = self._dense_candidates(query_text)
        dense_sim = {cid: sim for cid, _doc, _meta, sim in dense}
        dense_base = [
            cid for cid, doc, _m, _s in dense
            if _BASE_CONTROL.match(cid) and doc and doc.strip()
        ]

        scores = self._bm25.get_scores(_tokenize(query_text))
        order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        bm25_base: list[str] = []
        for i in order:
            cid = self._corpus_ids[i]
            if _BASE_CONTROL.match(cid) and self._corpus_doc.get(cid, "").strip():
                bm25_base.append(cid)
            if len(bm25_base) >= _CANDIDATES:
                break

        rrf: dict[str, float] = {}
        for rank, cid in enumerate(dense_base):
            rrf[cid] = rrf.get(cid, 0.0) + 1.0 / (_RRF_K + rank)
        for rank, cid in enumerate(bm25_base):
            rrf[cid] = rrf.get(cid, 0.0) + 1.0 / (_RRF_K + rank)

        fused = sorted(rrf, key=lambda c: rrf[c], reverse=True)[:k]
        controls = []
        for cid in fused:
            meta = self._corpus_meta.get(cid, {"title": ""})
            controls.append(
                NistControl(
                    id=cid,
                    title=meta.get("title", ""),
                    text=self._corpus_doc.get(cid, ""),
                    similarity=dense_sim.get(cid, 0.0),  # display the cosine score
                )
            )
        return controls

    def retrieve_ranked(self, joined: JoinedRisk, k: int = 10) -> list[NistControl]:
        """Return up to ``k`` base controls, best first, per the active mode."""
        query_text = self._query_text(joined)
        if self.mode == "hybrid":
            ranked = self._hybrid_ranked(query_text, k)
            if ranked:
                return ranked
        candidates = self._dense_candidates(query_text)
        ranked = self._base_with_prose(candidates)
        if ranked:
            return ranked[:k]
        # Nothing matched the base-control filter: fall back to any non-empty hit.
        for cid, doc, meta, sim in candidates:
            if doc and doc.strip():
                return [NistControl(id=cid, title=meta["title"], text=doc, similarity=sim)]
        cid, doc, meta, sim = candidates[0]
        return [NistControl(id=cid, title=meta["title"], text=doc, similarity=sim)]

    def retrieve(self, joined: JoinedRisk) -> NistControl:
        """Return the single most relevant base NIST control for this risk."""
        return self.retrieve_ranked(joined, k=1)[0]
