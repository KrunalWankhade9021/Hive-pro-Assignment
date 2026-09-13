import csv
from pathlib import Path

from app.models import (
    Asset,
    Vulnerability,
    ThreatIntel,
    BusinessService,
    RemediationHint,
    _yn,
)


def _rows(path: Path):
    with open(path, newline="", encoding="utf-8") as fh:
        yield from csv.DictReader(fh)


def load_assets(path) -> list[Asset]:
    out = []
    for r in _rows(Path(path)):
        out.append(Asset(
            asset_id=r["asset_id"], asset_name=r["asset_name"], asset_type=r["asset_type"],
            environment=r["environment"], owner_team=r["owner_team"].strip() or None,
            business_service=r["business_service"], internet_exposed=_yn(r["internet_exposed"]),
            criticality=r["criticality"], data_classification=r["data_classification"],
            edr_installed=_yn(r["edr_installed"]), last_seen_days=int(r["last_seen_days"]),
            location=r["location"], vendor_product=r["vendor_product"],
        ))
    return out


def load_vulnerabilities(path) -> list[Vulnerability]:
    out = []
    for r in _rows(Path(path)):
        out.append(Vulnerability(
            vuln_id=r["vuln_id"], asset_id=r["asset_id"], vulnerability_name=r["vulnerability_name"],
            cve=r["cve"], severity=r["severity"], cvss=float(r["cvss"]),
            exploit_available=_yn(r["exploit_available"]), patch_available=_yn(r["patch_available"]),
            days_open=int(r["days_open"]), asset_exposure=r["asset_exposure"],
            auth_required=_yn(r["auth_required"]), status=r["status"], affected_component=r["affected_component"],
        ))
    return out


def load_threat_intel(path) -> list[ThreatIntel]:
    out = []
    for r in _rows(Path(path)):
        out.append(ThreatIntel(
            intel_id=r["intel_id"], threat_actor=r["threat_actor"], campaign_name=r["campaign_name"],
            target_sector=r["target_sector"], target_region=r["target_region"],
            matched_cve_or_control=r["matched_cve_or_control"], exploit_maturity=r["exploit_maturity"],
            active_last_seen=r["active_last_seen"], ransomware_association=_yn(r["ransomware_association"]),
            confidence=r["confidence"], summary=r["summary"],
        ))
    return out


def load_services(path) -> dict[str, BusinessService]:
    out = {}
    for r in _rows(Path(path)):
        svc = BusinessService(
            business_service=r["business_service"], business_owner=r["business_owner"],
            business_impact=r["business_impact"], customer_facing=_yn(r["customer_facing"]),
            compliance_scope=r["compliance_scope"], revenue_impact=r["revenue_impact"],
            rto_hours=float(r["rto_hours"]), depends_on=r["depends_on"], risk_appetite=r["risk_appetite"],
        )
        out[svc.business_service] = svc
    return out


def load_remediation_hints(path) -> list[RemediationHint]:
    return [
        RemediationHint(**{k: r[k] for k in ("finding_type", "recommended_action", "priority_hint", "validation_evidence")})
        for r in _rows(Path(path))
    ]
