"""Evaluate NIST control retrieval against the hand-labelled golden set.

Runs the retriever over every golden case and reports family-level metrics:

- Hit-rate@1  — top-ranked control's base id is in the expected families.
- Hit-rate@3  — any of the top 3 base controls is in the expected families.
- MRR         — mean reciprocal rank of the first correct control (within top-k).
- mean top-1 similarity — average dense cosine score of the top result.

Run:  python -m eval.evaluate_rag           (both modes)
      python -m eval.evaluate_rag dense     (one mode)
"""
from __future__ import annotations

import sys
from pathlib import Path

from app.join import JoinedRisk
from app.loaders import load_remediation_hints
from app.models import Asset, Vulnerability
from app.retriever import NistRetriever
from eval.golden_set import GOLDEN_SET, GoldenCase

_CHROMA = Path(__file__).resolve().parents[1] / "data" / "chroma"
_DATASET = Path(__file__).resolve().parents[2] / "Dataset"
_TOPK = 10


def _base_id(control_id: str) -> str:
    """'si-2.2' -> 'si-2'; 'si-2' -> 'si-2'."""
    return control_id.split(".")[0]


def _case_to_joined(case: GoldenCase) -> JoinedRisk:
    """Build a minimal JoinedRisk carrying only the fields retrieval reads."""
    asset = Asset(
        asset_id="A", asset_name="host", asset_type="Server", environment="Production",
        owner_team="Team", business_service="Svc", internet_exposed=True,
        criticality="Critical", data_classification="PII", edr_installed=True,
        last_seen_days=1, location="UAE", vendor_product="vendor",
    )
    vuln = Vulnerability(
        vuln_id=case.vuln_id, asset_id="A", vulnerability_name=case.vulnerability_name,
        cve=case.cve, severity="Critical", cvss=9.8, exploit_available=True,
        patch_available=True, days_open=40, asset_exposure="Internet",
        auth_required=False, status="Open", affected_component=case.affected_component,
    )
    return JoinedRisk(vulnerability=vuln, asset=asset, service=None)


def evaluate(mode: str) -> dict:
    """Run the golden set through the retriever in ``mode`` and return metrics."""
    hints = load_remediation_hints(_DATASET / "remediation_guidance.csv")
    retriever = NistRetriever(_CHROMA, hints=hints, mode=mode)

    rows = []
    hit1 = hit3 = 0
    reciprocal_sum = 0.0
    sim_sum = 0.0

    for case in GOLDEN_SET:
        ranked = retriever.retrieve_ranked(_case_to_joined(case), k=_TOPK)
        base_ids = [_base_id(c.id) for c in ranked]
        expected = set(case.expected_families)

        top1 = base_ids[0] if base_ids else "-"
        is_hit1 = top1 in expected
        is_hit3 = any(b in expected for b in base_ids[:3])

        first_rank = next((i + 1 for i, b in enumerate(base_ids) if b in expected), None)
        reciprocal = 1.0 / first_rank if first_rank else 0.0

        hit1 += int(is_hit1)
        hit3 += int(is_hit3)
        reciprocal_sum += reciprocal
        sim_sum += ranked[0].similarity if ranked else 0.0

        rows.append({
            "case": case.cve, "top1": top1,
            "sim": ranked[0].similarity if ranked else 0.0,
            "hit1": is_hit1, "hit3": is_hit3,
            "expected": ",".join(sorted(expected)),
        })

    n = len(GOLDEN_SET)
    return {
        "mode": mode, "n": n,
        "hit_rate_1": hit1 / n, "hit_rate_3": hit3 / n,
        "mrr": reciprocal_sum / n, "mean_similarity": sim_sum / n,
        "rows": rows,
    }


def _print_report(result: dict) -> None:
    print(f"\n=== RAG evaluation — mode: {result['mode']} (n={result['n']}) ===")
    print(f"{'case':18}{'top-1':9}{'sim':7}{'hit@1':7}{'hit@3':7}expected")
    for r in result["rows"]:
        print(
            f"{r['case']:18}{r['top1']:9}{r['sim']:<7}"
            f"{('Y' if r['hit1'] else 'n'):7}{('Y' if r['hit3'] else 'n'):7}{r['expected']}"
        )
    print(
        f"\nHit-rate@1={result['hit_rate_1']:.2f}  "
        f"Hit-rate@3={result['hit_rate_3']:.2f}  "
        f"MRR={result['mrr']:.2f}  "
        f"mean top-1 similarity={result['mean_similarity']:.3f}"
    )


def main() -> None:
    modes = sys.argv[1:] or ["dense", "hybrid"]
    results = [evaluate(m) for m in modes]
    for r in results:
        _print_report(r)
    if len(results) == 2:
        d, h = results
        print("\n=== dense vs hybrid ===")
        print(f"{'metric':22}{'dense':>10}{'hybrid':>10}")
        for key, label in [
            ("hit_rate_1", "Hit-rate@1"),
            ("hit_rate_3", "Hit-rate@3"),
            ("mrr", "MRR"),
            ("mean_similarity", "mean top-1 sim"),
        ]:
            print(f"{label:22}{d[key]:>10.3f}{h[key]:>10.3f}")


if __name__ == "__main__":
    main()
