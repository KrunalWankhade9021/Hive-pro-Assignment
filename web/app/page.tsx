"use client";

import { useCallback, useEffect, useState } from "react";
import { getTopRisks, getStats, getAdvisory } from "@/lib/api";
import { Advisory, Risk, Stats } from "@/lib/types";
import { RiskCard } from "./components/RiskCard";
import { StatBar } from "./components/StatBar";
import { AdvisoryPanel } from "./components/AdvisoryPanel";

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

  return (
    <div className="min-h-screen bg-paper">
      {/* Slim navy header bar, the one structural accent */}
      <header className="bg-navy text-white">
        <div className="mx-auto flex max-w-4xl items-baseline justify-between gap-4 px-4 py-4 sm:px-6">
          <div>
            <h1 className="text-base font-semibold tracking-tight">
              TawasolPay Cyber Risk Briefing
            </h1>
            <p className="mt-0.5 text-xs text-white/70">
              Prioritised, explainable risk picture with retrieved NIST SP 800-53 guidance
            </p>
          </div>
          <button
            type="button"
            onClick={() => void load()}
            disabled={loading}
            className="flex-none text-xs font-medium text-white/80 underline-offset-4 transition hover:text-white hover:underline disabled:opacity-50"
          >
            {loading ? "Refreshing…" : "Refresh"}
          </button>
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
          Ranking blends internet exposure, exploit availability, CISA KEV / ransomware association,
          active threat campaigns, business criticality and compliance scope, and missing
          compensating controls, not CVSS alone.
        </footer>
      </main>
    </div>
  );
}
