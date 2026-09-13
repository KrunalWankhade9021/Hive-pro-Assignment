from app.models import ThreatIntel
from app.threat_match import index_threats, match_threat


def _ti(cve, ranw, conf="High"):
    return ThreatIntel(
        intel_id="TI", threat_actor="A", campaign_name="C",
        target_sector="Financial Services", target_region="Middle East",
        matched_cve_or_control=cve, exploit_maturity="Weaponized",
        active_last_seen="2026-04-22", ransomware_association=ranw,
        confidence=conf, summary="s",
    )


def test_matches_present_cve():
    idx = index_threats([_ti("CVE-2024-21762", True)])
    assert match_threat("CVE-2024-21762", idx).ransomware_association is True


def test_noise_cve_no_match():
    idx = index_threats([_ti("CVE-9999-0000", True)])
    assert match_threat("CVE-2024-21762", idx) is None


def test_prefers_ransomware_match():
    idx = index_threats([_ti("CVE-1", False), _ti("CVE-1", True)])
    assert match_threat("CVE-1", idx).ransomware_association is True
