import { Risk } from "@/lib/types";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

function severityIntent(severity: string): "danger" | "warning" | "info" | "neutral" {
  switch (severity.toLowerCase()) {
    case "critical":
      return "danger";
    case "high":
      return "warning";
    case "medium":
      return "info";
    default:
      return "neutral";
  }
}

export function RiskCard({ risk }: { risk: Risk }) {
  const { asset, vulnerability: vuln, business_service: svc, kev, matched_threat, nist_control } = risk;

  const compliance =
    svc?.compliance_scope && svc.compliance_scope !== "None" ? svc.compliance_scope : null;

  return (
    <Card className="overflow-hidden">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 border-b border-slate-100 p-5">
        <div className="flex items-start gap-3">
          <span className="mt-0.5 flex h-8 w-8 flex-none items-center justify-center rounded-lg bg-slate-900 text-sm font-semibold text-white">
            {risk.rank}
          </span>
          <div>
            <h2 className="text-base font-semibold leading-snug text-slate-900">
              {vuln.vulnerability_name}
            </h2>
            <p className="mt-0.5 text-sm text-slate-500">
              {vuln.cve} · CVSS {vuln.cvss} ·{" "}
              <Badge intent={severityIntent(vuln.severity)}>{vuln.severity}</Badge>
            </p>
          </div>
        </div>
        <div className="flex-none text-right">
          <div className="text-2xl font-bold tabular-nums text-slate-900">{risk.risk_score}</div>
          <div className="text-[11px] uppercase tracking-wide text-slate-400">weighted risk score</div>
        </div>
      </div>

      {/* Asset & service */}
      <div className="grid gap-3 px-5 py-4 text-sm sm:grid-cols-2">
        <div>
          <div className="text-xs font-medium uppercase tracking-wide text-slate-400">Asset</div>
          <div className="mt-0.5 font-medium text-slate-800">{asset.asset_name}</div>
          <div className="text-slate-500">
            {asset.asset_type} · {asset.environment}
            {asset.owner_team ? ` · ${asset.owner_team}` : " · unassigned owner"}
          </div>
        </div>
        <div>
          <div className="text-xs font-medium uppercase tracking-wide text-slate-400">Business service</div>
          <div className="mt-0.5 font-medium text-slate-800">
            {svc ? svc.business_service : "Unmapped service"}
          </div>
          {svc && (
            <div className="text-slate-500">
              revenue impact: {svc.revenue_impact} · RTO {svc.rto_hours}h
            </div>
          )}
        </div>
      </div>

      {/* Evidence chips */}
      <div className="flex flex-wrap gap-1.5 px-5 pb-4">
        {asset.internet_exposed && <Badge intent="warning">Internet-exposed</Badge>}
        {vuln.exploit_available && <Badge intent="warning">Exploit available</Badge>}
        {kev.in_kev && <Badge intent="danger">In CISA KEV</Badge>}
        {kev.ransomware && <Badge intent="danger">Ransomware</Badge>}
        {matched_threat && <Badge intent="danger">Campaign: {matched_threat.campaign_name}</Badge>}
        {compliance && <Badge intent="info">{compliance}</Badge>}
      </div>

      {/* Why it ranks here */}
      <div className="mx-5 mb-4 rounded-lg bg-slate-50 p-3">
        <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Why it ranks here</div>
        <p className="mt-1 text-sm leading-relaxed text-slate-700">{risk.explanation}</p>
      </div>

      {/* NIST control */}
      {nist_control && (
        <div className="border-t border-slate-100 bg-slate-900/[0.02] px-5 py-4">
          <div className="flex items-center justify-between">
            <div className="text-sm font-semibold text-slate-800">
              NIST {nist_control.id.toUpperCase()} — {nist_control.title}
            </div>
            <span className="text-[11px] text-slate-400">
              match {Math.round(nist_control.similarity * 100)}%
            </span>
          </div>
          <p className="mt-1 line-clamp-4 text-sm leading-relaxed text-slate-600">{nist_control.text}</p>
        </div>
      )}
    </Card>
  );
}
