/** Metadata for each scoring factor: human label + a category colour. */
const FACTORS: Record<string, { label: string; color: string }> = {
  cvss_base: { label: "CVSS severity", color: "bg-slate-400" },
  internet_exposed: { label: "Internet-exposed", color: "bg-orange-500" },
  exploit_available: { label: "Exploit available", color: "bg-orange-400" },
  kev_ransomware: { label: "KEV ransomware", color: "bg-red-600" },
  threat_campaign: { label: "Active campaign", color: "bg-red-500" },
  business_criticality: { label: "Business criticality", color: "bg-sky-600" },
  compliance_scope: { label: "Compliance scope", color: "bg-sky-400" },
  missing_edr: { label: "No EDR", color: "bg-amber-500" },
  no_auth_required: { label: "No auth required", color: "bg-amber-400" },
  long_open: { label: "Long open (>30d)", color: "bg-amber-300" },
};

function meta(key: string) {
  return FACTORS[key] ?? { label: key.replace(/_/g, " "), color: "bg-slate-300" };
}

/**
 * Horizontal stacked bar showing how each factor contributes to the weighted
 * score — the visual form of "why this ranks here, and not on CVSS alone".
 * `full` also renders a labelled legend with per-factor points.
 */
export function ScoreBreakdown({
  breakdown,
  score,
  full = false,
}: {
  breakdown: Record<string, number>;
  score: number;
  full?: boolean;
}) {
  const entries = Object.entries(breakdown)
    .filter(([, points]) => points > 0)
    .sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((sum, [, p]) => sum + p, 0) || 1;

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
        <ul className="mt-3 grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-2">
          {entries.map(([key, points]) => (
            <li key={key} className="flex items-center gap-2 text-xs text-slate-600">
              <span className={`h-2.5 w-2.5 flex-none rounded-sm ${meta(key).color}`} />
              <span className="flex-1">{meta(key).label}</span>
              <span className="font-medium tabular-nums text-slate-800">+{points}</span>
            </li>
          ))}
          <li className="col-span-full mt-1 flex items-center justify-between border-t border-slate-100 pt-1 text-xs">
            <span className="font-semibold text-slate-700">Weighted total</span>
            <span className="font-bold tabular-nums text-slate-900">{score}</span>
          </li>
        </ul>
      )}
    </div>
  );
}
