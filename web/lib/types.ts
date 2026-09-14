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
  edr_installed: boolean;
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

export interface Stats {
  total_assets: number;
  internet_exposed_assets: number;
  critical_assets: number;
  total_vulnerabilities: number;
  exploited_count: number;
  kev_matches: number;
  ransomware_vulns: number;
  matched_campaigns: number;
  noise_campaigns: number;
  generated_at: string;
}

export interface Risk {
  rank: number;
  /** Raw additive weighted score — can exceed 100. Shown only as a breakdown detail. */
  risk_score: number;
  /** Raw score normalised onto 0–100 (raw / 115 * 100); the headline figure. */
  normalized_score: number;
  score_breakdown: Record<string, number>;
  asset: Asset;
  vulnerability: Vulnerability;
  matched_threat: MatchedThreat | null;
  kev: KevInfo;
  business_service: BusinessService | null;
  nist_control: NistControl | null;
  /** Next-best NIST controls from the same retrieval, ids distinct from the primary. */
  alternative_controls: NistControl[];
  /** How many of the returned top-n risks share this CVE (1 = unique). */
  cve_concentration: number;
  explanation: string;
}
