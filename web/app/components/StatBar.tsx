import { Stats } from "@/lib/types";

interface Stat {
  label: string;
  value: number;
  sub?: string;
  alarm?: boolean; // KEV / ransomware counts, the only red numbers on the page
}

/**
 * Portfolio context for the ranked risks: what was assessed, and how much of it
 * is actually exploited. A typographic strip rather than a row of number cards,
 * so it reads as the preamble to the ranking instead of competing with it.
 */
export function StatBar({ stats }: { stats: Stats }) {
  const items: Stat[] = [
    {
      label: "Assets",
      value: stats.total_assets,
      sub: `${stats.internet_exposed_assets} internet-exposed`,
    },
    {
      label: "Business-critical",
      value: stats.critical_assets,
      sub: "of those assets",
    },
    {
      label: "Vulnerabilities",
      value: stats.total_vulnerabilities,
      sub: `${stats.exploited_count} with a known exploit`,
    },
    {
      label: "In CISA KEV",
      value: stats.kev_matches,
      sub: "confirmed exploited",
      alarm: true,
    },
    {
      label: "Ransomware-linked",
      value: stats.ransomware_vulns,
      sub: "via KEV or campaign",
      alarm: true,
    },
    {
      label: "Active campaigns",
      value: stats.matched_campaigns,
      sub: `${stats.noise_campaigns} industry-noise records matched nothing we run`,
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-x-6 gap-y-5 sm:grid-cols-3 lg:grid-cols-6">
      {items.map((s) => (
        <div key={s.label}>
          <div
            className={`nums font-mono text-[26px] leading-none ${
              s.alarm ? "text-alarm" : "text-ink"
            }`}
          >
            {s.value}
          </div>
          <div className="mt-1.5 text-[13px] text-muted">{s.label}</div>
          {s.sub && (
            <div className="mt-0.5 text-[11px] leading-snug text-faint">
              {s.sub}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
