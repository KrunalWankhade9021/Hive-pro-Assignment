"use client";

import { useState } from "react";
import { Risk } from "@/lib/types";
import { ScoreBreakdown } from "./ScoreBreakdown";

function yn(value: boolean): string {
  return value ? "Yes" : "No";
}

/** CISA writes vendor advisory links inline as "[https://...]". Left raw they
 *  swallow several lines of the card, so lift the first one out as a link and
 *  read the rest as prose. */
function splitKevAction(action: string): { text: string; href: string | null } {
  const match = action.match(/\[?(https?:\/\/[^\s\]]+)\]?/);
  const text = action
    .replace(/\[?https?:\/\/[^\s\]]+\]?/g, "")
    .replace(/\s{2,}/g, " ")
    .replace(/\s+([.,])/g, "$1")
    .trim();
  return { text, href: match ? match[1] : null };
}

/** A labelled fact in the three-up context row. */
function Facet({
  label,
  primary,
  lines,
}: {
  label: string;
  primary: string;
  lines: (string | null)[];
}) {
  return (
    <div>
      <div className="text-[11px] text-faint">{label}</div>
      <div className="mt-1 text-[14px] font-medium leading-snug text-ink">
        {primary}
      </div>
      {lines.filter(Boolean).map((line) => (
        <div key={line} className="text-[12px] leading-snug text-muted">
          {line}
        </div>
      ))}
    </div>
  );
}

function EvidenceRow({
  label,
  value,
  alarm,
}: {
  label: string;
  value: string;
  alarm?: boolean;
}) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-line/60 py-1.5 last:border-0">
      <span className="text-[12.5px] text-muted">{label}</span>
      <span
        className={`nums font-mono text-[12.5px] ${
          alarm && value === "Yes" ? "text-alarm" : "text-ink"
        }`}
      >
        {value}
      </span>
    </div>
  );
}

/** The full body: context, reasoning, scoring, retrieved control, evidence. */
function RiskDetail({ risk, topN }: { risk: Risk; topN: number }) {
  const {
    asset,
    vulnerability: vuln,
    business_service: svc,
    kev,
    matched_threat,
    nist_control,
  } = risk;
  const compliance =
    svc?.compliance_scope && svc.compliance_scope !== "None"
      ? svc.compliance_scope
      : null;

  return (
    <>
      {/* Context: what it is, where it sits, and who it matters to */}
      <div className="grid gap-5 border-t border-line px-5 py-4 sm:grid-cols-3 sm:px-6">
        <Facet
          label="Asset"
          primary={asset.asset_name}
          lines={[
            `${asset.asset_type}, ${asset.environment}`,
            asset.owner_team ?? "No assigned owner",
          ]}
        />
        <Facet
          label="Business service"
          primary={svc ? svc.business_service : "Unmapped service"}
          lines={
            svc
              ? [`${svc.revenue_impact} revenue impact`, compliance]
              : ["No mapped owner"]
          }
        />
        <Facet
          label="Threat campaign"
          primary={
            matched_threat
              ? matched_threat.campaign_name
              : "No matched campaign"
          }
          lines={
            matched_threat
              ? [
                  matched_threat.threat_actor,
                  matched_threat.ransomware_association
                    ? "Ransomware-associated"
                    : null,
                ]
              : ["No active campaign targets this CVE"]
          }
        />
      </div>

      {risk.cve_concentration > 1 && (
        <p className="border-t border-line px-5 py-2.5 text-[12.5px] text-muted sm:px-6">
          <span className="font-mono text-ink">{vuln.cve}</span> affects{" "}
          {risk.cve_concentration} of the top {topN} risks, so one fix closes
          more than one row.
        </p>
      )}

      {/* The reasoning, the arithmetic, and the retrieved guidance, side by side.
          Prioritisation and remediation stay visibly separate: the scoring engine
          decides the rank, the NIST control says what the practice should be. */}
      <div className="grid gap-x-10 gap-y-7 border-t border-line px-5 py-5 sm:px-6 lg:grid-cols-[1.45fr_1fr]">
        {/* The narrative side: why this one, then what the practice should be.
            Stacked, because together they balance the arithmetic beside them. */}
        <div className="space-y-7">
          <section>
            <h3 className="text-[11px] text-faint">Why it ranks here</h3>
            <p className="mt-2 max-w-prose font-serif text-[14px] leading-relaxed text-ink/90">
              {risk.explanation}
            </p>
          </section>

          <section>
            <h3 className="text-[11px] text-faint">Remediation guidance</h3>
            {nist_control ? (
              <>
                <div className="mt-2 flex items-baseline justify-between gap-3">
                  <span className="text-[14px] font-medium text-ink">
                    <span className="font-mono text-signal">
                      {nist_control.id.toUpperCase()}
                    </span>{" "}
                    {nist_control.title}
                  </span>
                  <span className="nums flex-none font-mono text-[12px] text-faint">
                    {Math.round(nist_control.similarity * 100)}%
                  </span>
                </div>
                <p className="mt-2 text-[13px] leading-relaxed text-muted">
                  {nist_control.text}
                </p>

                {risk.alternative_controls.length > 0 && (
                  <div className="mt-3">
                    <div className="text-[11px] text-faint">Also relevant</div>
                    <ul className="mt-1.5 space-y-1">
                      {risk.alternative_controls.map((c) => (
                        <li
                          key={c.id}
                          className="flex items-baseline justify-between gap-3 text-[12.5px] text-muted"
                        >
                          <span className="truncate">
                            <span className="font-mono text-ink">
                              {c.id.toUpperCase()}
                            </span>{" "}
                            {c.title}
                          </span>
                          <span className="nums flex-none font-mono text-faint">
                            {Math.round(c.similarity * 100)}%
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                <p className="mt-3 text-[11px] text-faint">
                  Retrieved from NIST SP 800-53 Rev. 5, not generated.
                </p>
              </>
            ) : (
              <p className="mt-2 text-[13px] text-muted">
                No control retrieved for this finding.
              </p>
            )}
          </section>
        </div>

        <section>
          <h3 className="mb-2.5 text-[11px] text-faint">Risk drivers</h3>
          <ScoreBreakdown
            breakdown={risk.score_breakdown}
            score={risk.risk_score}
            normalized={risk.normalized_score}
          />
        </section>
      </div>

      {/* Evidence: every claim above, traceable back to its source record. */}
      <div className="grid gap-x-8 gap-y-5 border-t border-line bg-ground/40 px-5 py-4 sm:px-6 lg:grid-cols-[1fr_1fr_1.15fr]">
        <div>
          <div className="mb-1 text-[11px] text-faint">Evidence</div>
          <EvidenceRow label="CVSS" value={String(vuln.cvss)} />
          <EvidenceRow
            label="Internet exposed"
            value={yn(asset.internet_exposed)}
          />
          <EvidenceRow
            label="Exploit available"
            value={yn(vuln.exploit_available)}
          />
          <EvidenceRow label="Days open" value={String(vuln.days_open)} />
        </div>
        <div>
          <div className="mb-1 text-[11px] text-faint" aria-hidden>
            &nbsp;
          </div>
          <EvidenceRow label="In CISA KEV" value={yn(kev.in_kev)} alarm />
          <EvidenceRow
            label="Ransomware-associated"
            value={yn(kev.ransomware)}
            alarm
          />
          <EvidenceRow
            label="Active campaign"
            value={yn(matched_threat !== null)}
            alarm
          />
          <EvidenceRow label="EDR installed" value={yn(asset.edr_installed)} />
        </div>
        <div>
          <div className="mb-1 text-[11px] text-faint">CISA KEV</div>
          {kev.in_kev ? (
            <>
              {kev.date_added && (
                <p className="text-[12.5px] text-muted">
                  Confirmed exploited since{" "}
                  <span className="font-mono text-ink">{kev.date_added}</span>
                </p>
              )}
              {kev.required_action &&
                (() => {
                  const { text, href } = splitKevAction(kev.required_action);
                  return (
                    <p className="mt-1.5 text-[12.5px] leading-relaxed text-muted">
                      {text}
                      {href && (
                        <>
                          {" "}
                          <a
                            href={href}
                            target="_blank"
                            rel="noreferrer"
                            className="text-signal underline-offset-4 hover:underline"
                          >
                            Vendor advisory
                          </a>
                        </>
                      )}
                    </p>
                  );
                })()}
            </>
          ) : (
            <p className="text-[12.5px] leading-relaxed text-muted">
              Not in the catalogue. That is not an all-clear: KEV lists only
              exploitation CISA has confirmed.
            </p>
          )}
        </div>
      </div>
    </>
  );
}

/**
 * A ranked risk. The top risk is presented open as the briefing's centrepiece;
 * the rest are compact rows that expand into the same body, so the page has one
 * thing to read and four to scan.
 */
export function RiskCard({
  risk,
  topN,
  featured = false,
}: {
  risk: Risk;
  topN: number;
  featured?: boolean;
}) {
  const { asset, vulnerability: vuln, business_service: svc } = risk;
  const [open, setOpen] = useState(false);
  const detailId = `detail-${vuln.vuln_id}`;

  if (featured) {
    return (
      <article className="overflow-hidden rounded-lg border border-l-2 border-line border-l-alarm bg-surface">
        <div className="flex flex-wrap items-start justify-between gap-4 px-5 py-5 sm:px-6">
          <div className="flex items-start gap-4">
            <span className="nums mt-0.5 flex h-7 w-7 flex-none items-center justify-center rounded border border-signal/50 font-mono text-[14px] text-signal">
              {risk.rank}
            </span>
            <div>
              <h2 className="text-[19px] font-semibold leading-tight tracking-tight text-ink">
                {vuln.vulnerability_name}
              </h2>
              <div className="mt-1.5 flex flex-wrap items-baseline gap-x-4 gap-y-1 font-mono text-[12.5px] text-muted">
                <span>{vuln.cve}</span>
                <span>CVSS {vuln.cvss}</span>
                <span className="text-alarm">{vuln.severity}</span>
              </div>
            </div>
          </div>
          {/* Sans, not mono: at display size the mono period claims a full cell
              and the number reads as spaced-out digits rather than one figure. */}
          <div className="text-right">
            <div className="nums text-[42px] font-medium leading-none tracking-tight text-ink">
              {risk.normalized_score}
            </div>
            {/* Name which number this is: the raw weighted total runs to 115 and
                is itemised in the breakdown, so an unqualified "of 100" would
                read as a different scale rather than a normalisation of it. */}
            <div className="mt-1.5 text-[11px] text-faint">
              risk score, normalised to 100
            </div>
          </div>
        </div>
        <RiskDetail risk={risk} topN={topN} />
      </article>
    );
  }

  return (
    <article className="overflow-hidden rounded-lg border border-line bg-surface">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-controls={detailId}
        className="flex w-full items-center gap-4 px-5 py-3.5 text-left transition-colors hover:bg-raised sm:px-6"
      >
        <span className="nums flex h-6 w-6 flex-none items-center justify-center rounded border border-line font-mono text-[12px] text-muted">
          {risk.rank}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-[14.5px] font-medium text-ink">
            {vuln.vulnerability_name}
          </span>
          <span className="mt-0.5 block truncate font-mono text-[12px] text-faint">
            {vuln.cve}&nbsp;&nbsp; {asset.asset_name}&nbsp;&nbsp;{" "}
            {svc ? svc.business_service : "Unmapped service"}
          </span>
        </span>
        <span className="nums flex-none text-[18px] font-medium tracking-tight text-ink">
          {risk.normalized_score}
        </span>
        <span
          aria-hidden
          className={`flex-none text-faint transition-transform ${open ? "rotate-180" : ""}`}
        >
          ▾
        </span>
      </button>
      <div id={detailId} hidden={!open}>
        <RiskDetail risk={risk} topN={topN} />
      </div>
    </article>
  );
}
