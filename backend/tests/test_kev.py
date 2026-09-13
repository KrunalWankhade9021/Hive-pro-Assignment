from app.kev import match_kev, KevEntry

KEV = {"CVE-2024-21762": KevEntry(cve="CVE-2024-21762", ransomware=True, date_added="2024-02-09", required_action="Apply patch")}


def test_match_known_ransomware_cve():
    m = match_kev("CVE-2024-21762", KEV)
    assert m.in_kev is True and m.ransomware is True


def test_match_synthetic_cve_not_in_kev():
    m = match_kev("CVE-SYN-2026-0001", KEV)
    assert m.in_kev is False and m.ransomware is False and m.date_added is None
