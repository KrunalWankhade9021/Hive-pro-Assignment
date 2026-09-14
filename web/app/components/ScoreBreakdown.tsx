/** Metadata for each scoring factor: human label + category. Category colours use
 *  one muted navy-to-grey ramp so the breakdown stays quiet and authoritative;
 *  severity is the only place bright colour appears elsewhere in the UI. */
const FACTORS: Record<string, { label: string; category: string }> = {
  internet_exposed: { label: "Internet-exposed", category: "Threat exposure" },
  exploit_available: { label: "Active exploit", category: "Threat exposure" },
  kev_ransomware: { label: "Ransomware (KEV)", category: "Threat exposure" },
  threat_campaign: { label: "Active campaign", category: "Threat exposure" },
  business_criticality: { label: "Business-critical service", category: "Business impact" },
  compliance_scope: { label: "Compliance scope", category: "Business impact" },
  missing_edr: { label: "No EDR", category: "Control weakness" },
  no_auth_required: { label: "No auth required", category: "Control weakness" },
  long_open: { label: "Open >30 days", category: "Control weakness" },
  cvss_base: { label: "CVSS base severity", category: "Base severity" },
};

const CATEGORY_ORDER = ["Threat exposure", "Business impact", "Control weakness", "Base severity"];

// One muted ramp: deep navy for threat, mid slate for business/control, faint
// grey for base severity. No bright colour; this is quiet by design.
const CATEGORY_COLOR: Record<string, string> = {
  "Threat exposure": "#1B3A5B",
  "Business impact": "#475467",
  "Control weakness": "#8A909C",
  "Base severity": "#C7CBD2",
  Other: "#C7CBD2",
};

function meta(key: string) {
  return FACTORS[key] ?? { label: key.replace(/_/g, " "), category: "Other" };
}

/**
 * The itemized "why": the scoring drivers grouped by category, each with the
 * points it contributed, plus the raw and normalised totals. This is the single
 * place the multi-factor scoring is spelled out.
 */
export function ScoreBreakdown({
  breakdown,
  score,
  normalized,
}: {
  breakdown: Record<string, number>;
  score: number;
  normalized: number;
}) {
  const entries = Object.entries(breakdown)
    .filter(([, points]) => points > 0)
    .sort((a, b) => b[1] - a[1]);

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
    <div className="space-y-3">
      {orderedCategories.map((cat) => (
        <div key={cat}>
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted">
            {cat}
          </div>
          <ul className="space-y-1">
            {byCategory.get(cat)!.map(([key, points]) => (
              <li key={key} className="flex items-center gap-2 text-xs text-muted">
                <span
                  className="h-2 w-2 flex-none rounded-[1px]"
                  style={{ backgroundColor: CATEGORY_COLOR[cat] ?? CATEGORY_COLOR.Other }}
                />
                <span className="flex-1">{meta(key).label}</span>
                <span className="font-mono tabular-nums text-ink">+{points}</span>
              </li>
            ))}
          </ul>
        </div>
      ))}
      <div className="flex items-center justify-between border-t border-line pt-2 text-xs">
        <span className="font-semibold text-muted">Raw weighted total</span>
        <span className="font-mono tabular-nums text-ink">
          {score} (normalised {normalized} / 100)
        </span>
      </div>
    </div>
  );
}
