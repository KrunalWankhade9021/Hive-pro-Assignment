"use client";

import { useState } from "react";
import { Risk } from "@/lib/types";
import { Card } from "@/components/ui/card";
import { Chip } from "@/components/ui/badge";
import { ScoreBreakdown } from "./ScoreBreakdown";

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#B42318",
  high: "#B54708",
  medium: "#475467",
  low: "#5B616E",
};

function severityColor(severity: string): string {
  return SEVERITY_COLOR[severity.toLowerCase()] ?? SEVERITY_COLOR.low;
}

// score_breakdown key → short chip label (base severity is implicit, so skipped).
const FACTOR_LABELS: Record<string, string> = {
  internet_exposed: "Internet-exposed",
  exploit_available: "Active exploit",
  kev_ransomware: "Ransomware (KEV)",
  threat_campaign: "Active campaign",
  business_criticality: "Business-critical",
  compliance_scope: "Compliance scope",
  missing_edr: "No EDR",
  no_auth_required: "No auth required",
  long_open: "Open >30d",
};
const FACTOR_ORDER = Object.keys(FACTOR_LABELS);

function yn(value: boolean): string {
  return value ? "Yes" : "No";
}

function EvidenceRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between border-b border-line py-1 last:border-0">
      <span className="text-muted">{label}</span>
      <span className="font-mono tabular-nums text-ink">{value}</span>
    </div>
  );
}

export function RiskCard({ risk, topN }: { risk: Risk; topN: number }) {
  const { asset, vulnerability: vuln, business_service: svc, kev, matched_threat, nist_control } = risk;
  const [open, setOpen] = useState(false);
  const sev = severityColor(vuln.severity);

  const compliance =
    svc?.compliance_scope && svc.compliance_scope !== "None" ? svc.compliance_scope : null;

  const firedFactors = FACTOR_ORDER.filter((k) => (risk.score_breakdown[k] ?? 0) > 0);

  return (
    <Card className="overflow-hidden border-l-4" style={{ borderLeftColor: sev }}>
      {/* HEADER — rank marker, title, severity, score */}
      <div className="flex items-start justify-between gap-4 p-4">
        <div className="flex items-start gap-3">
          <span className="mt-0.5 w-7 flex-none font-mono text-2xl font-semibold leading-none text-navy">
            {risk.rank}
          </span>
          <div>
            <h2 className="text-[15px] font-semibold leading-snug text-ink">
              {vuln.vulnerability_name}
            </h2>
            <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1">
              <span className="font-mono text-xs text-muted">{vuln.cve}</span>
              <span className="text-muted/50">·</span>
              <span className="font-mono text-xs text-muted">CVSS {vuln.cvss}</span>
              <span
                className="rounded-sm border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide"
                style={{ color: sev, borderColor: sev }}
              >
                {vuln.severity}
              </span>
            </div>
          </div>
        </div>
        <div className="flex-none text-right">
          <div className="font-mono text-2xl font-semibold tabular-nums text-ink">
            {risk.normalized_score}
            <span className="text-sm font-normal text-muted"> / 100</span>
          </div>
          <div className="text-[10px] uppercase tracking-wider text-muted">risk score</div>
        </div>
      </div>

      {/* Quiet score bar */}
      <div className="px-4">
        <ScoreBreakdown
          breakdown={risk.score_breakdown}
          score={risk.risk_score}
          normalized={risk.normalized_score}
          full={open}
        />
      </div>

      {/* Concentration — a quiet inline note, not a loud banner */}
      {risk.cve_concentration > 1 && (
        <p
          className="mx-4 mt-3 border-l-2 pl-2 text-xs text-muted"
          style={{ borderLeftColor: sev }}
        >
          {vuln.cve} affects {risk.cve_concentration} of the top {topN} assets.
        </p>
      )}

      {/* Factor chips — the multi-factor scoring made visible */}
      {firedFactors.length > 0 && (
        <div className="flex flex-wrap gap-1.5 px-4 pt-3">
          {firedFactors.map((k) => (
            <Chip key={k}>{FACTOR_LABELS[k]}</Chip>
          ))}
        </div>
      )}

      {/* Compact meta row */}
      <div className="grid gap-x-6 gap-y-2 px-4 pt-4 text-xs sm:grid-cols-3">
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-wider text-muted">Asset</div>
          <div className="mt-0.5 font-medium text-ink">{asset.asset_name}</div>
          <div className="text-muted">
            {asset.asset_type} · {asset.environment}
            {asset.owner_team ? ` · ${asset.owner_team}` : " · unassigned owner"}
          </div>
        </div>
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-wider text-muted">Threat</div>
          {matched_threat ? (
            <>
              <div className="mt-0.5 font-medium text-ink">{matched_threat.campaign_name}</div>
              <div className="text-muted">
                {matched_threat.threat_actor}
                {matched_threat.ransomware_association ? " · ransomware" : ""}
              </div>
            </>
          ) : (
            <div className="mt-0.5 text-muted">No matched campaign</div>
          )}
        </div>
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-wider text-muted">
            Business service
          </div>
          <div className="mt-0.5 font-medium text-ink">
            {svc ? svc.business_service : "Unmapped service"}
          </div>
          {svc && (
            <div className="text-muted">
              {svc.revenue_impact} impact{compliance ? ` · ${compliance}` : ""}
            </div>
          )}
        </div>
      </div>

      {/* WHY — considered prose, set in serif */}
      <div className="px-4 pt-4">
        <div className="text-[10px] font-semibold uppercase tracking-wider text-muted">
          Why it ranks here
        </div>
        <p className="mt-1 font-serif text-[13.5px] leading-relaxed text-ink/90">
          {risk.explanation}
        </p>
      </div>

      {/* NIST remediation — primary control always visible */}
      {nist_control && (
        <div className="mt-4 border-t border-line px-4 py-3">
          <div className="flex items-baseline justify-between gap-3">
            <div className="text-sm font-semibold text-ink">
              <span className="font-mono text-navy">{nist_control.id.toUpperCase()}</span>{" "}
              — {nist_control.title}
            </div>
            <span className="flex-none font-mono text-[11px] text-muted">
              {Math.round(nist_control.similarity * 100)}% match
            </span>
          </div>
          <p className={`mt-1 text-xs leading-relaxed text-muted ${open ? "" : "line-clamp-2"}`}>
            {nist_control.text}
          </p>

          {open && risk.alternative_controls.length > 0 && (
            <div className="mt-2">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-muted">
                Other relevant controls
              </div>
              <ul className="mt-1 space-y-0.5">
                {risk.alternative_controls.map((c) => (
                  <li key={c.id} className="flex items-center justify-between text-xs text-muted">
                    <span>
                      <span className="font-mono text-ink">{c.id.toUpperCase()}</span> — {c.title}
                    </span>
                    <span className="font-mono tabular-nums text-muted">
                      {Math.round(c.similarity * 100)}%
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div className="mt-1.5 text-[10px] text-muted/70">Source: NIST SP 800-53 Rev. 5</div>
        </div>
      )}

      {/* Expanded detail: CISA KEV + evidence table */}
      {open && (
        <div className="grid gap-4 border-t border-line px-4 py-3 text-xs sm:grid-cols-2">
          {kev.in_kev && (
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider text-muted">
                CISA KEV
              </div>
              {kev.date_added && <div className="mt-1 text-muted">Added {kev.date_added}</div>}
              {kev.required_action && (
                <div className="mt-0.5 text-muted">Required action: {kev.required_action}</div>
              )}
            </div>
          )}

          <div className="sm:col-span-2">
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted">
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
        className="w-full border-t border-line py-2 text-[11px] font-medium uppercase tracking-wider text-muted transition hover:bg-paper hover:text-ink"
      >
        {open ? "Hide detail" : "Show drivers, control text, KEV & evidence"}
      </button>
    </Card>
  );
}
