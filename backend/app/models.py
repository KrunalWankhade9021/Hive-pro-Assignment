from pydantic import BaseModel


def _yn(v: str) -> bool:
    return str(v).strip().lower() in {"yes", "true", "1"}


class Asset(BaseModel):
    asset_id: str
    asset_name: str
    asset_type: str
    environment: str
    owner_team: str | None
    business_service: str
    internet_exposed: bool
    criticality: str
    data_classification: str
    edr_installed: bool
    last_seen_days: int
    location: str
    vendor_product: str


class Vulnerability(BaseModel):
    vuln_id: str
    asset_id: str
    vulnerability_name: str
    cve: str
    severity: str
    cvss: float
    exploit_available: bool
    patch_available: bool
    days_open: int
    asset_exposure: str
    auth_required: bool
    status: str
    affected_component: str


class ThreatIntel(BaseModel):
    intel_id: str
    threat_actor: str
    campaign_name: str
    target_sector: str
    target_region: str
    matched_cve_or_control: str
    exploit_maturity: str
    active_last_seen: str
    ransomware_association: bool
    confidence: str
    summary: str


class BusinessService(BaseModel):
    business_service: str
    business_owner: str
    business_impact: str
    customer_facing: bool
    compliance_scope: str
    revenue_impact: str
    rto_hours: float
    depends_on: str
    risk_appetite: str


class RemediationHint(BaseModel):
    finding_type: str
    recommended_action: str
    priority_hint: str
    validation_evidence: str
