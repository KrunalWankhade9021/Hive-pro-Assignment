"""Portfolio-level aggregate counts for the dashboard summary header.

These are cheap structured aggregations over the data pack + KEV catalog -- no
embedding model or LLM is needed -- so the summary can be served quickly and
independently of the (heavier) ranked-risk build.
"""
from datetime import datetime, timezone

from app.kev import KevEntry
from app.models import Asset, ThreatIntel, Vulnerability


def compute_stats(
    assets: list[Asset],
    vulns: list[Vulnerability],
    intel: list[ThreatIntel],
    kev: dict[str, KevEntry],
) -> dict:
    """Return portfolio counts summarising exposure across the environment."""
    vuln_cves = {v.cve for v in vulns}

    # Threat campaigns that reference a CVE actually present in our environment
    # vs. industry "noise" campaigns that match nothing we run.
    matched_campaigns = {t.campaign_name for t in intel if t.matched_cve_or_control in vuln_cves}
    noise_campaigns = {t.campaign_name for t in intel} - matched_campaigns

    # A CVE is ransomware-associated if CISA KEV flags it, or an active campaign
    # targeting it is ransomware-linked.
    ransomware_cves = {
        t.matched_cve_or_control for t in intel
        if t.ransomware_association and t.matched_cve_or_control in vuln_cves
    }
    ransomware_cves |= {cve for cve in vuln_cves if cve in kev and kev[cve].ransomware}
    ransomware_vulns = sum(1 for v in vulns if v.cve in ransomware_cves)

    return {
        "total_assets": len(assets),
        "internet_exposed_assets": sum(1 for a in assets if a.internet_exposed),
        "critical_assets": sum(1 for a in assets if a.criticality == "Critical"),
        "total_vulnerabilities": len(vulns),
        "exploited_count": sum(1 for v in vulns if v.exploit_available),
        "kev_matches": sum(1 for v in vulns if v.cve in kev),
        "ransomware_vulns": ransomware_vulns,
        "matched_campaigns": len(matched_campaigns),
        "noise_campaigns": len(noise_campaigns),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
