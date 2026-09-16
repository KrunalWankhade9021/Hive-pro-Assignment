"use client";

import { useCallback, useEffect, useState } from "react";
import { getTopRisks, getStats, getAdvisory } from "@/lib/api";
import { Advisory, Risk, Stats } from "@/lib/types";
import { RiskCard } from "./components/RiskCard";
import { StatBar } from "./components/StatBar";
import { AdvisoryPanel } from "./components/AdvisoryPanel";

/** A short, factual synthesis of the top-N risks. Computed from the data, not
 *  an LLM, so it is always consistent with the ranked list below it. */
function assessment(
  risks: Risk[],
): { headline: string; priority: string } | null {
  if (risks.length === 0) return null;
  const n = risks.length;
  const internet = risks.filter((r) => r.asset.internet_exposed).length;
  const ransomware = risks.filter(
    (r) => r.kev.ransomware || r.matched_threat?.ransomware_association,
  ).length;
  const top = risks[0];
  const topService =
    top.business_service?.business_service ?? "an unmapped service";

  // "5 of the top 5" reads as a coincidence rather than the finding it is.
  const count = (c: number) => (c === n ? `all ${n}` : `${c} of the ${n}`);
  const isAre = (c: number) => (c === 1 ? "is" : "are");
  const headline =
    `Of the top ${n} risks, ${count(internet)} ${isAre(internet)} internet-facing ` +
    `and ${count(ransomware)} ${isAre(ransomware)} tied to an active ransomware campaign.`;
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
      const [riskData, statData] = await Promise.all([
        getTopRisks(5),
        getStats(),
      ]);
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
    <div className="min-h-screen bg-ground">
      <header className="border-b border-line">
        <div className="mx-auto flex max-w-6xl flex-wrap items-baseline justify-between gap-x-6 gap-y-2 px-5 py-5 sm:px-8">
          <div>
            <h1 className="text-[17px] font-semibold tracking-tight text-ink">
              TawasolPay Cyber Risk Briefing
            </h1>
            <p className="mt-1 text-[13px] text-muted">
              Prioritised, explainable risk picture with retrieved NIST SP
              800-53 guidance
            </p>
          </div>
          <div className="flex flex-none items-baseline gap-5">
            {generatedAt && (
              <span className="font-mono text-[12px] text-faint">
                Generated {generatedAt}
              </span>
            )}
            <button
              type="button"
              onClick={() => void load()}
              disabled={loading}
              className="text-[13px] text-signal underline-offset-4 transition hover:underline disabled:opacity-50"
            >
              {loading ? "Refreshing" : "Refresh"}
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl space-y-10 px-5 py-8 sm:px-8 sm:py-10">
        {advisory && <AdvisoryPanel advisory={advisory} />}

        {stats && (
          <section
            aria-label="Portfolio summary"
            className="rounded-lg border border-line bg-surface px-5 py-5 sm:px-6"
          >
            <StatBar stats={stats} />
          </section>
        )}

        {error && (
          <div className="rounded-lg border border-line bg-surface px-5 py-4 sm:px-6">
            <p className="text-[14px] font-medium text-alarm">
              The risk API did not respond.
            </p>
            <p className="mt-1.5 text-[13px] text-muted">{error}</p>
            <p className="mt-2 text-[13px] text-muted">
              Start the backend, and point{" "}
              <code className="rounded bg-ground px-1 font-mono text-ink">
                NEXT_PUBLIC_API_URL
              </code>{" "}
              at it.
            </p>
          </div>
        )}

        {!error && !risks && (
          <div className="space-y-3" aria-hidden>
            <div className="h-64 rounded-lg border border-line bg-surface" />
            {[0, 1, 2, 3].map((i) => (
              <div
                key={i}
                className="h-14 rounded-lg border border-line bg-surface"
              />
            ))}
          </div>
        )}

        {risks && (
          <section aria-label="Prioritised risks">
            {/* The section opens with its own finding, so the heading, the basis
                for the ranking, and what the ranking found read as one statement
                rather than three stacked paragraphs. */}
            <h2 className="text-[19px] font-semibold tracking-tight text-ink">
              Top {risks.length} prioritised risks
            </h2>
            {summary && (
              <p className="mt-2 max-w-3xl text-[15px] leading-relaxed text-ink">
                {summary.headline}
              </p>
            )}
            <p className="mt-2 max-w-3xl text-[13px] leading-relaxed text-muted">
              {summary?.priority} Ranked on internet exposure, exploit
              availability, threat intelligence, business impact and control
              weaknesses, not CVSS alone.
            </p>

            <div className="mt-6 space-y-3">
              {risks.map((risk, i) => (
                <RiskCard
                  key={`${risk.rank}-${risk.vulnerability.vuln_id}`}
                  risk={risk}
                  topN={risks.length}
                  featured={i === 0}
                />
              ))}
            </div>
          </section>
        )}

        <footer className="grid gap-8 border-t border-line pt-6 sm:grid-cols-2">
          <div>
            <h2 className="text-[13px] text-ink">How the ranking works</h2>
            <p className="mt-2 max-w-md text-[12.5px] leading-relaxed text-muted">
              Each risk is scored on ten weighted factors totalling 115 points,
              then normalised to 100. CVSS contributes at most 25 of those
              points, so severity alone cannot carry a risk to the top. Every
              factor that applied is itemised on the risk itself.
            </p>
          </div>
          <div>
            <h2 className="text-[13px] text-ink">Sources</h2>
            <ul className="mt-2 space-y-1 text-[12.5px] text-muted">
              <li>
                CISA Known Exploited Vulnerabilities catalogue, fetched at build
                time
              </li>
              <li>
                NIST SP 800-53 Rev. 5 OSCAL catalogue, embedded and retrieved
                per risk
              </li>
              <li>
                TawasolPay asset inventory, vulnerability scan, threat
                intelligence feed
              </li>
              <li>MDR threat advisory</li>
            </ul>
            {generatedAt && (
              <p className="mt-3 font-mono text-[11px] text-faint">
                Generated {generatedAt}
              </p>
            )}
          </div>
        </footer>
      </main>
    </div>
  );
}
