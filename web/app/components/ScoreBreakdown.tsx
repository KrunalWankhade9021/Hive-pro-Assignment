/** Metadata for each scoring factor: human label + the group it belongs to. */
const FACTORS: Record<string, { label: string; group: string }> = {
  internet_exposed: { label: "Internet-exposed", group: "Threat exposure" },
  exploit_available: { label: "Active exploit", group: "Threat exposure" },
  kev_ransomware: { label: "Ransomware (KEV)", group: "Threat exposure" },
  threat_campaign: { label: "Active campaign", group: "Threat exposure" },
  business_criticality: {
    label: "Business-critical service",
    group: "Business impact",
  },
  compliance_scope: { label: "Compliance scope", group: "Business impact" },
  missing_edr: { label: "No EDR", group: "Control weakness" },
  no_auth_required: { label: "No auth required", group: "Control weakness" },
  long_open: { label: "Open over 30 days", group: "Control weakness" },
  cvss_base: { label: "CVSS base severity", group: "Base severity" },
};

const GROUP_ORDER = [
  "Threat exposure",
  "Business impact",
  "Control weakness",
  "Base severity",
];

function meta(key: string) {
  return FACTORS[key] ?? { label: key.replace(/_/g, " "), group: "Other" };
}

/**
 * The itemised "why": every factor that contributed, with its points and a bar
 * sized to them, grouped so the shape of the judgement reads at a glance. This
 * is the single place the multi-factor scoring is spelled out, and the reason
 * the ranking is defensible rather than asserted.
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
  const max = Math.max(...entries.map(([, p]) => p), 1);

  const byGroup = new Map<string, [string, number][]>();
  for (const entry of entries) {
    const group = meta(entry[0]).group;
    if (!byGroup.has(group)) byGroup.set(group, []);
    byGroup.get(group)!.push(entry);
  }
  const groups = [
    ...GROUP_ORDER.filter((g) => byGroup.has(g)),
    ...Array.from(byGroup.keys()).filter((g) => !GROUP_ORDER.includes(g)),
  ];

  return (
    <div className="space-y-3.5">
      {groups.map((group) => (
        <div key={group}>
          <div className="mb-1.5 text-[11px] text-faint">{group}</div>
          <ul className="space-y-1.5">
            {byGroup.get(group)!.map(([key, points]) => (
              <li key={key} className="flex items-center gap-3 text-[13px]">
                <span className="flex-1 truncate text-muted">
                  {meta(key).label}
                </span>
                <span className="h-1.5 w-16 flex-none overflow-hidden rounded-full bg-line">
                  <span
                    className="block h-full rounded-full bg-signal"
                    style={{ width: `${(points / max) * 100}%` }}
                  />
                </span>
                <span className="nums w-8 flex-none text-right text-[13px] font-medium text-ink">
                  +{points}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ))}

      <div className="border-t border-line pt-2.5">
        <div className="flex items-baseline justify-between gap-3">
          <span className="text-[13px] text-muted">Weighted total</span>
          <span className="nums text-[13px] font-medium text-ink">{score}</span>
        </div>
        <p className="mt-0.5 text-[11px] text-faint">
          of a possible 115, normalised to {normalized} of 100
        </p>
      </div>
    </div>
  );
}
