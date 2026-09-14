/** Types mirroring the FastAPI `/risks/top` payload (see backend/app/engine.py). */

export interface NistControl {
  id: string;
  title: string;
  text: string;
  similarity: number;
}

export interface KevInfo {
  in_kev: boolean;
  ransomware: boolean;
  date_added: string | null;
  required_action: string | null;
}

export interface MatchedThreat {
  threat_actor: string;
  campaign_name: string;
  ransomware_association: boolean;
  confidence: string;
}

export interface Asset {
  asset_id: string;
  asset_name: string;
  asset_type: string;
  environment: string;
  internet_exposed: boolean;
  criticality: string;
  owner_team: string | null;
  [key: string]: unknown;
}

export interface Vulnerability {
  vuln_id: string;
  cve: string;
  vulnerability_name: string;
  cvss: number;
  severity: string;
  exploit_available: boolean;
  days_open: number;
  [key: string]: unknown;
}

export interface BusinessService {
  business_service: string;
  business_owner: string;
  revenue_impact: string;
  compliance_scope: string;
  rto_hours: number;
  [key: string]: unknown;
}

export interface Risk {
  rank: number;
  /** Weighted risk score — can exceed 100. Not a 0–100 percentage. */
  risk_score: number;
  score_breakdown: Record<string, number>;
  asset: Asset;
  vulnerability: Vulnerability;
  matched_threat: MatchedThreat | null;
  kev: KevInfo;
  business_service: BusinessService | null;
  nist_control: NistControl | null;
  explanation: string;
}
