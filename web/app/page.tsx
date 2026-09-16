"use client";

import { useCallback, useEffect, useState } from "react";
import { getTopRisks, getStats, getAdvisory } from "@/lib/api";
import { Advisory, Risk, Stats } from "@/lib/types";
import { RiskCard } from "./components/RiskCard";
import { StatBar } from "./components/StatBar";
import { AdvisoryPanel } from "./components/AdvisoryPanel";

/** A short, factual synthesis of the top-N risks. Computed from the data, not
 *  an LLM, so it is always consistent with the ranked list below it. */
function assessment(risks: Risk[]): { headline: string; priority: string } | null {
  if (risks.length === 0) return null;
  const n = risks.length;
  const internet = risks.filter((r) => r.asset.internet_exposed).length;
  const ransomware = risks.filter(
    (r) => r.kev.ransomware || r.matched_threat?.ransomware_association,
  ).length;
  const top = risks[0];
  const topService = top.business_service?.business_service ?? "an unmapped service";

  const isAre = (c: number) => (c === 1 ? "is" : "are");
  const headline =
    `${internet} of the top ${n} risks ${isAre(internet)} internet-facing, and ` +
    `${ransomware} ${isAre(ransomware)} associated with active ransomware campaigns.`;
  // States the ranking and its basis, not an instruction: the scoring engine
  // decides order, the retrieved NIST control (shown per risk below) is the
  // remediation guidance. Keeping the two separate keeps each claim traceable.
  const priority =
    `Highest-ranked risk: ${top.vulnerability.vulnerability_name} ` +
    `(${top.vulnerability.cve}) on ${topService}, scoring ${top.normalized_score}/100 ` +
    `on the configured risk factors.`;
  return { headline, priority };
}

export default function Home() {
  const [risks, setRisks] = useState<Risk[] | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [advisory, setAdvisory] = useState<Advisory | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [generatedAt, setGeneratedAt] = useState<string>("");
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [riskData, statData] = await Promise.all([getTopRisks(5), getStats()]);
      setRisks(riskData);
      setStats(statData);
      setGeneratedAt(new Date().toLocaleString());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load risks");
    } finally {
      setLoading(false);
    }
    // The advisory is supporting context; a failure here must not break the page.
    try {
      setAdvisory(await getAdvisory());
    } catch {
      setAdvisory(null);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const summary = risks ? assessment(risks) : null;

  return (
    <div className="min-h-screen bg-paper">
      {/* Slim navy header bar, the one structural accent. Prints as plain ink. */}
      <header className="bg-navy text-white print:bg-white print:text-ink print:border-b print:border-line">
        <div className="mx-auto flex max-w-4xl items-baseline justify-between gap-4 px-4 py-4 sm:px-6">
          <div>
            <h1 className="text-base font-semibold tracking-tight">
              TawasolPay Cyber Risk Briefing
            </h1>
            <p className="mt-0.5 text-xs text-white/70 print:text-muted">
              Prioritised, explainable risk picture with retrieved NIST SP 800-53 guidance
            </p>
          </div>
          <div className="no-print flex flex-none items-center gap-4">
            <button
              type="button"
              onClick={() => window.print()}
              className="text-xs font-medium text-white/80 underline-offset-4 transition hover:text-white hover:underline"
            >
              Print / Save as PDF
            </button>
            <button
              type="button"
              onClick={() => void load()}
              disabled={loading}
              className="text-xs font-medium text-white/80 underline-offset-4 transition hover:text-white hover:underline disabled:opacity-50"
            >
              {loading ? "Refreshing..." : "Refresh"}
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-4xl px-4 py-8 sm:px-6">
        {generatedAt && (
          <p className="mb-4 font-mono text-[11px] text-muted">Generated {generatedAt}</p>
        )}

        {advisory && <AdvisoryPanel advisory={advisory} />}

        {stats && (
          <section className="mb-6">
            <StatBar stats={stats} />
          </section>
        )}

        {summary && (
          <section
            className="mb-6 border-l-2 border-navy bg-card px-4 py-3"
            aria-label="Executive summary"
          >
            <div className="text-[10px] font-semibold uppercase tracking-wider text-navy">
              Assessment
            </div>
            <p className="mt-1 text-sm leading-relaxed text-ink">
              <span className="font-semibold">{summary.headline}</span> {summary.priority}
            </p>
          </section>
        )}

        {error && (
          <div className="rounded-md border border-line bg-card p-4 text-sm">
            <p className="font-medium text-sev-critical">Could not reach the risk API.</p>
            <p className="mt-1 text-muted">{error}</p>
            <p className="mt-2 text-muted">
              Check that the backend is running and{" "}
              <code className="rounded bg-paper px-1 font-mono">NEXT_PUBLIC_API_URL</code> points to it.
            </p>
          </div>
        )}

        {!error && !risks && (
          <div className="space-y-3">
            {[0, 1, 2].map((i) => (
              <div key={i} className="h-32 rounded-md border border-line bg-card" />
            ))}
          </div>
        )}

        {risks && (
          <div className="space-y-3">
            {risks.map((risk) => (
              <RiskCard
                key={`${risk.rank}-${risk.vulnerability.vuln_id}`}
                risk={risk}
                topN={risks.length}
              />
            ))}
          </div>
        )}

        <footer className="mt-8 border-t border-line pt-4 text-[11px] leading-relaxed text-muted">
          <p>
            Ranking blends internet exposure, exploit availability, CISA KEV and ransomware
            association, active threat campaigns, business criticality and compliance scope, and
            missing compensating controls, not CVSS alone.
          </p>
          <p className="mt-2">
            Sources: CISA Known Exploited Vulnerabilities catalog, NIST SP 800-53 Rev. 5.
            {generatedAt ? ` Generated ${generatedAt}.` : ""}
          </p>
        </footer>
      </main>
    </div>
  );
}
