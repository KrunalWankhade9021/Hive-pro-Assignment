import { Stats } from "@/lib/types";

interface Tile {
  label: string;
  value: number;
  sub?: string;
  accent: string;
}

/** A row of summary tiles giving the portfolio context behind the top risks. */
export function StatBar({ stats }: { stats: Stats }) {
  const tiles: Tile[] = [
    {
      label: "Assets",
      value: stats.total_assets,
      sub: `${stats.internet_exposed_assets} internet-exposed`,
      accent: "text-slate-900",
    },
    {
      label: "Critical assets",
      value: stats.critical_assets,
      sub: "business-critical",
      accent: "text-slate-900",
    },
    {
      label: "Vulnerabilities",
      value: stats.total_vulnerabilities,
      sub: `${stats.exploited_count} with known exploit`,
      accent: "text-slate-900",
    },
    {
      label: "In CISA KEV",
      value: stats.kev_matches,
      sub: "actively exploited",
      accent: "text-orange-600",
    },
    {
      label: "Ransomware-linked",
      value: stats.ransomware_vulns,
      sub: "KEV or campaign",
      accent: "text-red-600",
    },
    {
      label: "Active campaigns",
      value: stats.matched_campaigns,
      sub: `${stats.noise_campaigns} noise filtered`,
      accent: "text-red-600",
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
      {tiles.map((t) => (
        <div key={t.label} className="rounded-xl border border-slate-200 bg-white p-3.5">
          <div className={`text-2xl font-bold tabular-nums ${t.accent}`}>{t.value}</div>
          <div className="mt-0.5 text-xs font-medium text-slate-700">{t.label}</div>
          {t.sub && <div className="mt-0.5 text-[11px] leading-tight text-slate-400">{t.sub}</div>}
        </div>
      ))}
    </div>
  );
}
