/** Metadata for each scoring factor: human label, category, and bar colour. */
const FACTORS: Record<string, { label: string; category: string; color: string }> = {
  internet_exposed: { label: "Internet-exposed", category: "Threat exposure", color: "bg-orange-500" },
  exploit_available: { label: "Exploit available", category: "Threat exposure", color: "bg-orange-400" },
  kev_ransomware: { label: "CISA KEV + ransomware", category: "Threat exposure", color: "bg-red-600" },
  threat_campaign: { label: "Active campaign", category: "Threat exposure", color: "bg-red-500" },
  business_criticality: { label: "Critical revenue service", category: "Business impact", color: "bg-sky-600" },
  compliance_scope: { label: "Compliance scope", category: "Business impact", color: "bg-sky-400" },
  missing_edr: { label: "No EDR", category: "Control weakness", color: "bg-amber-500" },
  no_auth_required: { label: "No authentication required", category: "Control weakness", color: "bg-amber-400" },
  long_open: { label: "Open >30 days", category: "Control weakness", color: "bg-amber-300" },
  cvss_base: { label: "CVSS severity", category: "Base severity", color: "bg-slate-400" },
};

// Category display order (threat first, base severity last).
const CATEGORY_ORDER = ["Threat exposure", "Business impact", "Control weakness", "Base severity"];

function meta(key: string) {
  return FACTORS[key] ?? { label: key.replace(/_/g, " "), category: "Other", color: "bg-slate-300" };
}

/**
 * The visual "why": a stacked bar showing each factor's contribution, and — when
 * expanded — the drivers grouped by category so the reasoning reads top-down.
 */
export function ScoreBreakdown({
  breakdown,
  score,
  normalized,
  full = false,
}: {
  breakdown: Record<string, number>;
  score: number;
  normalized: number;
  full?: boolean;
}) {
  const entries = Object.entries(breakdown)
    .filter(([, points]) => points > 0)
    .sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((sum, [, p]) => sum + p, 0) || 1;

  // Group entries by category for the expanded legend.
  const byCategory = new Map<string, [string, number][]>();
  for (const entry of entries) {
    const cat = meta(entry[0]).category;
    if (!byCategory.has(cat)) byCategory.set(cat, []);
    byCategory.get(cat)!.push(entry);
  }
  const orderedCategories = [
    ...CATEGORY_ORDER.filter((c) => byCategory.has(c)),
    ...Array.from(byCategory.keys()).filter((c) => !CATEGORY_ORDER.includes(c)),
  ];

  return (
    <div>
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-slate-100">
        {entries.map(([key, points]) => (
          <div
            key={key}
            className={meta(key).color}
            style={{ width: `${(points / total) * 100}%` }}
            title={`${meta(key).label}: +${points}`}
          />
        ))}
      </div>

      {full && (
        <div className="mt-3 space-y-3">
          {orderedCategories.map((cat) => (
            <div key={cat}>
              <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                {cat}
              </div>
              <ul className="space-y-1">
                {byCategory.get(cat)!.map(([key, points]) => (
                  <li key={key} className="flex items-center gap-2 text-xs text-slate-600">
                    <span className={`h-2.5 w-2.5 flex-none rounded-sm ${meta(key).color}`} />
                    <span className="flex-1">{meta(key).label}</span>
                    <span className="font-medium tabular-nums text-slate-800">+{points}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
          <div className="flex items-center justify-between border-t border-slate-100 pt-2 text-xs">
            <span className="font-semibold text-slate-700">Raw total → normalised</span>
            <span className="font-bold tabular-nums text-slate-900">
              {score} → {normalized} / 100
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
