"""Integration checks against the built NIST 800-53 vector store.

These run only when the ChromaDB store exists (i.e. after ``build_kb.py`` has
been executed); they are skipped otherwise so the unit suite stays fast and
network-free. They guard the properties that make retrieval trustworthy: the
full catalog is indexed, the controls the scenario relies on are present with
real prose, and the embedding space behaves (a control retrieves itself).
"""
from pathlib import Path

import chromadb
import pytest
from sentence_transformers import SentenceTransformer

from app.nist import COLLECTION, MODEL

CHROMA_DIR = Path(__file__).resolve().parents[1] / "data" / "chroma"
pytestmark = pytest.mark.skipif(
    not CHROMA_DIR.exists(), reason="NIST store not built; run scripts/build_kb.py"
)

# Controls the assignment names as most relevant to this scenario.
SCENARIO_CONTROLS = ["si-2", "ra-5", "ir-4", "ac-2", "sa-22"]


@pytest.fixture(scope="module")
def collection():
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    return client.get_collection(COLLECTION)


def test_full_catalog_is_indexed(collection):
    """The store holds the whole Rev.5 catalog (controls + enhancements)."""
    count = collection.count()
    assert 1000 <= count <= 1300, f"unexpected control count: {count}"


def test_scenario_controls_present_with_prose(collection):
    """Each assignment-named control exists and carries non-empty prose."""
    got = collection.get(ids=SCENARIO_CONTROLS, include=["documents", "metadatas"])
    returned_ids = set(got["ids"])

    for control_id in SCENARIO_CONTROLS:
        assert control_id in returned_ids, f"{control_id} missing from store"

    for doc in got["documents"]:
        assert doc and doc.strip(), "control indexed with empty prose"


def test_no_raw_oscal_placeholders_in_store(collection):
    """Indexed prose is free of raw ``{{ insert: param, ... }}`` placeholders."""
    docs = collection.get(include=["documents"])["documents"]

    offenders = [doc for doc in docs if "{{" in doc]
    assert not offenders, f"{len(offenders)} controls still contain raw placeholders"


def test_collection_uses_cosine_space(collection):
    """The collection is configured for cosine similarity."""
    assert collection.metadata.get("hnsw:space") == "cosine"


def test_control_retrieves_itself_at_low_distance(collection):
    """A control's own prose retrieves that control as the nearest neighbour.

    The stored/displayed prose has parameters resolved for readability, while the
    embedding is computed from the verbatim statement, so the self-distance is
    small but not exactly zero — the identity (top-1 is the control itself) is the
    property that matters.
    """
    model = SentenceTransformer(MODEL)
    si2 = collection.get(ids=["si-2"], include=["documents", "metadatas"])
    query = f"SI-2 {si2['metadatas'][0]['title']}. {si2['documents'][0]}"
    emb = model.encode([query], normalize_embeddings=True).tolist()

    res = collection.query(query_embeddings=emb, n_results=1)
    assert res["ids"][0][0] == "si-2"
    assert res["distances"][0][0] < 0.15
