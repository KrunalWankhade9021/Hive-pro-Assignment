"use client";

import { useEffect, useState } from "react";
import { getTopRisks } from "@/lib/api";
import { Risk } from "@/lib/types";
import { RiskCard } from "./components/RiskCard";

export default function Home() {
  const [risks, setRisks] = useState<Risk[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [generatedAt, setGeneratedAt] = useState<string>("");

  useEffect(() => {
    getTopRisks(5)
      .then((data) => {
        setRisks(data);
        setGeneratedAt(new Date().toLocaleString());
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "Failed to load risks"));
  }, []);

  return (
    <main className="mx-auto min-h-screen max-w-4xl px-4 py-10 sm:px-6">
      <header className="mb-8">
        <p className="text-xs font-semibold uppercase tracking-widest text-sky-700">
          TawasolPay · MDR Advisory Response
        </p>
        <h1 className="mt-1 text-2xl font-bold tracking-tight text-slate-900 sm:text-3xl">
          Top Cyber Risks
        </h1>
        <p className="mt-2 max-w-2xl text-sm leading-relaxed text-slate-600">
          A prioritised, explainable risk picture across assets, vulnerabilities, threat
          intelligence and business services — each risk backed by retrieved NIST SP 800-53
          remediation guidance.
        </p>
        {generatedAt && <p className="mt-2 text-xs text-slate-400">Generated {generatedAt}</p>}
      </header>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">
          <p className="font-medium">Could not reach the risk API.</p>
          <p className="mt-1 text-red-600">{error}</p>
          <p className="mt-2 text-red-500">
            Check that the backend is running and{" "}
            <code className="rounded bg-red-100 px-1">NEXT_PUBLIC_API_URL</code> points to it.
          </p>
        </div>
      )}

      {!error && !risks && (
        <div className="space-y-4">
          {[0, 1, 2].map((i) => (
            <div key={i} className="h-40 animate-pulse rounded-xl bg-slate-100" />
          ))}
        </div>
      )}

      {risks && (
        <div className="space-y-4">
          {risks.map((risk) => (
            <RiskCard key={`${risk.rank}-${risk.vulnerability.vuln_id}`} risk={risk} />
          ))}
        </div>
      )}

      <footer className="mt-10 border-t border-slate-100 pt-4 text-xs text-slate-400">
        Ranking blends internet exposure, exploit availability, CISA KEV / ransomware association,
        active threat campaigns, business criticality and missing controls — not CVSS alone.
      </footer>
    </main>
  );
}
