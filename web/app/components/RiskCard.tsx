"use client";

import { useState } from "react";
import { Risk } from "@/lib/types";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScoreBreakdown } from "./ScoreBreakdown";

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

function yn(value: boolean): string {
  return value ? "Yes" : "No";
}

/** A compact key/value row for the evidence table. */
function EvidenceRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between border-b border-slate-100 py-1 last:border-0">
      <span className="text-slate-500">{label}</span>
      <span className="font-medium tabular-nums text-slate-800">{value}</span>
    </div>
  );
}

export function RiskCard({ risk, topN }: { risk: Risk; topN: number }) {
  const { asset, vulnerability: vuln, business_service: svc, kev, matched_threat, nist_control } = risk;
  const [open, setOpen] = useState(false);

  const compliance =
    svc?.compliance_scope && svc.compliance_scope !== "None" ? svc.compliance_scope : null;

  return (
    <Card className="overflow-hidden">
      {/* DECISION — rank, severity, name, and the headline score */}
      <div className="flex items-start justify-between gap-4 border-b border-slate-100 p-5">
        <div className="flex items-start gap-3">
          <span className="mt-0.5 flex h-8 w-8 flex-none items-center justify-center rounded-lg bg-slate-900 text-sm font-semibold text-white">
            {risk.rank}
          </span>
          <div>
            <div className="mb-1">
              <Badge intent={severityIntent(vuln.severity)}>{vuln.severity.toUpperCase()}</Badge>
            </div>
            <h2 className="text-base font-semibold leading-snug text-slate-900">
              {vuln.vulnerability_name}
            </h2>
            <p className="mt-0.5 text-sm text-slate-500">
              {vuln.cve} · CVSS {vuln.cvss}
            </p>
          </div>
        </div>
        <div className="flex-none text-right">
          <div className="text-2xl font-bold tabular-nums text-slate-900">
            {risk.normalized_score}
            <span className="text-base font-medium text-slate-400"> / 100</span>
          </div>
          <div className="text-[11px] uppercase tracking-wide text-slate-400">risk score</div>
        </div>
      </div>

      {/* Concentration banner — a single CVE hitting multiple top-N assets */}
      {risk.cve_concentration > 1 && (
        <div className="flex items-center gap-2 border-b border-amber-200 bg-amber-50 px-5 py-2 text-xs text-amber-800">
          <span aria-hidden>⚠</span>
          <span>
            Same CVE ({vuln.cve}) affects {risk.cve_concentration} of the top {topN} assets.
          </span>
        </div>
      )}

      {/* Score bar (always visible) */}
      <div className="px-5 pt-4">
        <ScoreBreakdown
          breakdown={risk.score_breakdown}
          score={risk.risk_score}
          normalized={risk.normalized_score}
          full={open}
        />
      </div>

      {/* Asset & business impact */}
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
          <div className="text-xs font-medium uppercase tracking-wide text-slate-400">Business impact</div>
          <div className="mt-0.5 font-medium text-slate-800">
            {svc ? svc.business_service : "Unmapped service"}
          </div>
          {svc && (
            <div className="text-slate-500">
              {svc.revenue_impact} revenue impact · RTO {svc.rto_hours}h
              {compliance ? ` · ${compliance}` : ""}
            </div>
          )}
        </div>
      </div>

      {/* WHY */}
      <div className="mx-5 mb-4 rounded-lg bg-slate-50 p-3">
        <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
          Why #{risk.rank}
        </div>
        <p className="mt-1 text-sm leading-relaxed text-slate-700">{risk.explanation}</p>
      </div>

      {/* NIST remediation (primary control always visible) */}
      {nist_control && (
        <div className="border-t border-slate-100 bg-slate-900/[0.02] px-5 py-4">
          <div className="text-xs font-medium uppercase tracking-wide text-slate-400">
            NIST remediation
          </div>
          <div className="mt-1 flex items-center justify-between">
            <div className="text-sm font-semibold text-slate-800">
              {nist_control.id.toUpperCase()} — {nist_control.title}
            </div>
            <span className="text-[11px] text-slate-400">
              semantic match {Math.round(nist_control.similarity * 100)}%
            </span>
          </div>
          <p className={`mt-1 text-sm leading-relaxed text-slate-600 ${open ? "" : "line-clamp-3"}`}>
            {nist_control.text}
          </p>

          {open && risk.alternative_controls.length > 0 && (
            <div className="mt-3">
              <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-400">
                Other relevant controls
              </div>
              <ul className="mt-1 space-y-0.5">
                {risk.alternative_controls.map((c) => (
                  <li key={c.id} className="flex items-center justify-between text-xs text-slate-600">
                    <span>
                      {c.id.toUpperCase()} — {c.title}
                    </span>
                    <span className="tabular-nums text-slate-400">
                      {Math.round(c.similarity * 100)}%
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div className="mt-2 text-[11px] text-slate-400">Source: NIST SP 800-53 Rev. 5</div>
        </div>
      )}

      {/* Expanded detail: threat intel, CISA KEV, and the evidence table */}
      {open && (
        <div className="grid gap-5 border-t border-slate-100 px-5 py-4 text-sm sm:grid-cols-2">
          {matched_threat && (
            <div>
              <div className="text-xs font-medium uppercase tracking-wide text-slate-400">
                Threat intelligence
              </div>
              <div className="mt-1 text-slate-700">
                {matched_threat.campaign_name} · {matched_threat.threat_actor}
              </div>
              <div className="text-slate-500">
                {matched_threat.ransomware_association ? "ransomware-associated · " : ""}
                {matched_threat.confidence} confidence
              </div>
            </div>
          )}

          {kev.in_kev && (
            <div>
              <div className="text-xs font-medium uppercase tracking-wide text-slate-400">CISA KEV</div>
              {kev.date_added && <div className="mt-1 text-slate-600">Added {kev.date_added}</div>}
              {kev.required_action && (
                <div className="mt-0.5 text-slate-600">Required action: {kev.required_action}</div>
              )}
            </div>
          )}

          {/* EVIDENCE — facts, traceable to the source data */}
          <div className="sm:col-span-2">
            <div className="mb-1 text-xs font-medium uppercase tracking-wide text-slate-400">
              Evidence
            </div>
            <div className="grid gap-x-6 sm:grid-cols-2">
              <div>
                <EvidenceRow label="CVSS" value={String(vuln.cvss)} />
                <EvidenceRow label="Internet exposed" value={yn(asset.internet_exposed)} />
                <EvidenceRow label="Exploit available" value={yn(vuln.exploit_available)} />
                <EvidenceRow label="Days open" value={String(vuln.days_open)} />
              </div>
              <div>
                <EvidenceRow label="CISA KEV" value={yn(kev.in_kev)} />
                <EvidenceRow label="Ransomware" value={yn(kev.ransomware)} />
                <EvidenceRow label="Active campaign" value={yn(matched_threat !== null)} />
                <EvidenceRow label="EDR installed" value={yn(asset.edr_installed)} />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Expand / collapse */}
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="w-full border-t border-slate-100 bg-slate-50/60 py-2.5 text-xs font-medium text-slate-500 transition hover:bg-slate-100 hover:text-slate-700"
      >
        {open ? "Show less ▲" : "Show risk drivers, threat intel, alternatives & evidence ▼"}
      </button>
    </Card>
  );
}
