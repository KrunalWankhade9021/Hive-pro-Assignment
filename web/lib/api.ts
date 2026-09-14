import { Advisory, Risk, Stats } from "./types";

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

/** Fetch the ranked top-N risks from the backend. Throws on a non-OK response. */
export async function getTopRisks(n = 5): Promise<Risk[]> {
  const res = await fetch(`${BASE}/risks/top?n=${n}`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`Risk API returned ${res.status}`);
  }
  return res.json();
}

/** Fetch portfolio-level summary counts for the dashboard header. */
export async function getStats(): Promise<Stats> {
  const res = await fetch(`${BASE}/stats`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`Stats API returned ${res.status}`);
  }
  return res.json();
}

/** Fetch the ingested MDR threat advisory (the report that triggered the assessment). */
export async function getAdvisory(): Promise<Advisory> {
  const res = await fetch(`${BASE}/advisory`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`Advisory API returned ${res.status}`);
  }
  return res.json();
}
