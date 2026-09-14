import { Stats } from "@/lib/types";

interface Stat {
  label: string;
  value: number;
  sub?: string;
  emphasis?: boolean; // subtle severity-red for KEV / ransomware counts
}

/** A quiet strip of portfolio stats, small mono numbers, tiny labels, hairline
 *  dividers. Context for the ranked risks, not a hero of number cards. */
export function StatBar({ stats }: { stats: Stats }) {
  const items: Stat[] = [
    { label: "Assets", value: stats.total_assets, sub: `${stats.internet_exposed_assets} internet-exposed` },
    { label: "Critical assets", value: stats.critical_assets, sub: "business-critical" },
    { label: "Vulnerabilities", value: stats.total_vulnerabilities, sub: `${stats.exploited_count} with exploit` },
    { label: "In CISA KEV", value: stats.kev_matches, sub: "actively exploited", emphasis: true },
    { label: "Ransomware-linked", value: stats.ransomware_vulns, sub: "KEV or campaign", emphasis: true },
    { label: "Active campaigns", value: stats.matched_campaigns, sub: `${stats.noise_campaigns} noise filtered` },
  ];

  return (
    <div className="grid grid-cols-2 divide-line rounded-md border border-line bg-card sm:grid-cols-3 lg:grid-cols-6 lg:divide-x">
      {items.map((s) => (
        <div key={s.label} className="stat-block border-b border-line px-4 py-3 lg:border-b-0">
          <div
            className={`font-mono text-xl tabular-nums ${s.emphasis ? "text-sev-critical" : "text-ink"}`}
          >
            {s.value}
          </div>
          <div className="mt-0.5 text-[11px] font-medium uppercase tracking-wide text-muted">
            {s.label}
          </div>
          {s.sub && <div className="mt-0.5 text-[11px] leading-tight text-muted/70">{s.sub}</div>}
        </div>
      ))}
    </div>
  );
}
