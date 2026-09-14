"""Integration tests for the NIST RAG retriever.

These exercise the real embedded catalog (built by ``scripts/build_kb.py``) using
the production remediation hints, and assert that representative vulnerabilities
retrieve a control from the expected NIST family, the behaviour the assignment
specifically evaluates. They are skipped when the persisted store is absent so a
fresh clone stays green.
"""
from pathlib import Path

import pytest

from app.join import JoinedRisk
from app.loaders import load_remediation_hints
from app.models import Asset, Vulnerability

CHROMA = Path(__file__).resolve().parents[1] / "data" / "chroma"
DATASET = Path(__file__).resolve().parents[2] / "Dataset"
pytestmark = pytest.mark.skipif(
    not CHROMA.exists(), reason="run scripts/build_kb.py first"
)


@pytest.fixture(scope="module")
def retriever():
    """A retriever bound to the real store and the production remediation hints."""
    from app.retriever import NistRetriever

    hints = load_remediation_hints(DATASET / "remediation_guidance.csv")
    return NistRetriever(CHROMA, hints=hints)


def _risk(name: str, component: str) -> JoinedRisk:
    """Build a minimal JoinedRisk carrying only the fields retrieval reads."""
    asset = Asset(
        asset_id="A", asset_name="host", asset_type="Server", environment="Production",
        owner_team="Team", business_service="Svc", internet_exposed=True,
        criticality="Critical", data_classification="PII", edr_installed=True,
        last_seen_days=1, location="UAE", vendor_product="vendor",
    )
    vuln = Vulnerability(
        vuln_id="V", asset_id="A", vulnerability_name=name, cve="CVE-1",
        severity="Critical", cvss=9.8, exploit_available=True, patch_available=True,
        days_open=40, asset_exposure="Internet", auth_required=False, status="Open",
        affected_component=component,
    )
    return JoinedRisk(vulnerability=vuln, asset=asset, service=None)


# Each case: (label, vuln name, affected component, allowed base-control prefixes).
# Families are the defensible NIST controls for each remediation shape.
_MATRIX = [
    ("patching_rce", "Fortinet SSL-VPN Heap Buffer Overflow RCE", "SSL-VPN",
     ("si-2", "ra-5")),
    ("priv_esc", "PostgreSQL Privilege Escalation", "Database",
     ("ac-6", "ac-2", "ac-3")),
    ("session_leak", "Citrix ADC Session Token Leak (CitrixBleed)", "NetScaler",
     ("sc-23", "sc-10", "ac-12")),
    ("eol", "Windows Server 2012 R2 End of Support", "Operating System",
     ("sa-22", "si-2")),
]


@pytest.mark.parametrize(
    "label,name,component,allowed", _MATRIX, ids=[c[0] for c in _MATRIX]
)
def test_retrieves_expected_control_family(retriever, label, name, component, allowed):
    """A representative vulnerability retrieves a control from its expected family."""
    ctrl = retriever.retrieve(_risk(name, component))

    assert ctrl.id.startswith(allowed), (
        f"[{label}] expected one of {allowed}, got {ctrl.id} "
        f"({ctrl.title!r}, similarity={ctrl.similarity})"
    )
    assert ctrl.text and ctrl.text.strip(), f"[{label}] returned control has empty prose"
    assert ctrl.similarity > 0.4, (
        f"[{label}] similarity {ctrl.similarity} too low -- likely a weak match"
    )


def test_returns_base_control_not_enhancement(retriever):
    """Retrieval surfaces a primary control (e.g. si-2), never an enhancement (si-2.2)."""
    ctrl = retriever.retrieve(
        _risk("Fortinet SSL-VPN Heap Buffer Overflow RCE", "SSL-VPN")
    )
    assert "." not in ctrl.id, f"expected a base control, got enhancement {ctrl.id}"


def test_similarity_is_bounded(retriever):
    """Cosine-derived similarity stays within [-1, 1]."""
    ctrl = retriever.retrieve(_risk("SQL injection in web application", "Web App"))
    assert -1.0 <= ctrl.similarity <= 1.0


def test_retrieval_is_deterministic(retriever):
    """The same vulnerability returns the same control across repeated calls."""
    risk = _risk("Fortinet SSL-VPN Heap Buffer Overflow RCE", "SSL-VPN")
    first = retriever.retrieve(risk)
    second = retriever.retrieve(risk)
    assert (first.id, first.similarity) == (second.id, second.similarity)
