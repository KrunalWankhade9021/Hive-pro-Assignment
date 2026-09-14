"""Retrieve the most relevant NIST SP 800-53 control for a risk via embeddings.

The structured risk data is joined and scored elsewhere; this module handles the
semantic half of the system: given a vulnerability, find the control in the
embedded NIST catalog whose prose best matches the remediation need.

Two embedding lookups happen here, and both use the ``remediation_guidance.csv``
hints only to *shape the query* — never as the answer:

1. The vulnerability is matched to its closest remediation hint by cosine
   similarity (the hint is a domain expert's one-line categorisation of the
   finding, which describes the remediation intent far better than the
   product-specific vulnerability name does).
2. That hint's ``finding_type`` + ``recommended_action`` becomes the query text
   used to retrieve the best-matching NIST control.

The returned guidance text always comes from the embedded NIST catalog itself.
"""
import re
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

from app.engine import NistControl
from app.join import JoinedRisk
from app.models import RemediationHint
from app.nist import COLLECTION, MODEL

# Base controls only (e.g. "si-2"), excluding enhancements ("si-2.2"). For
# remediation guidance a technical manager can act on, the primary control is
# more useful than a narrow sub-enhancement.
_BASE_CONTROL = re.compile(r"^[a-z]{2}-\d+$")

# Number of candidates to pull before filtering to a base control with prose.
_CANDIDATES = 40


class NistRetriever:
    """Semantic retriever over the embedded NIST 800-53 control catalog."""

    def __init__(self, persist_dir: Path, hints: list[RemediationHint]):
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

    def _best_hint(self, joined: JoinedRisk) -> RemediationHint | None:
        """Return the remediation hint whose text is closest to the vulnerability."""
        if self._hint_embeddings is None:
            return None
        vuln = joined.vulnerability
        query = self.model.encode(
            [f"{vuln.vulnerability_name}. {vuln.affected_component}"],
            normalize_embeddings=True,
        )[0]
        # Both sides are normalised, so the dot product is cosine similarity.
        scores = self._hint_embeddings @ query
        return self.hints[int(scores.argmax())]

    def _query_text(self, joined: JoinedRisk) -> str:
        """Build the retrieval query, biased toward the remediation intent."""
        hint = self._best_hint(joined)
        if hint is not None:
            return f"{hint.finding_type}. Remediation: {hint.recommended_action}"
        vuln = joined.vulnerability
        return f"{vuln.vulnerability_name}. Component: {vuln.affected_component}."

    def retrieve(self, joined: JoinedRisk) -> NistControl:
        """Return the most relevant base NIST control (with prose) for this risk."""
        embedding = self.model.encode(
            [self._query_text(joined)], normalize_embeddings=True
        ).tolist()
        result = self.collection.query(
            query_embeddings=embedding, n_results=_CANDIDATES
        )
        docs = result["documents"][0]
        metas = result["metadatas"][0]
        dists = result["distances"][0] if result.get("distances") else [0.0] * len(docs)

        # Prefer the first base control that carries prose.
        for doc, meta, dist in zip(docs, metas, dists):
            if _BASE_CONTROL.match(meta["id"]) and doc and doc.strip():
                return self._to_control(meta, doc, dist)
        # No base control in range: fall back to the first non-empty candidate.
        for doc, meta, dist in zip(docs, metas, dists):
            if doc and doc.strip():
                return self._to_control(meta, doc, dist)
        # Everything was empty (should not happen for real queries): top hit.
        return self._to_control(metas[0], docs[0], dists[0])

    @staticmethod
    def _to_control(meta: dict, doc: str, dist: float) -> NistControl:
        return NistControl(
            id=meta["id"],
            title=meta["title"],
            text=doc,
            similarity=round(1 - dist, 3),
        )
