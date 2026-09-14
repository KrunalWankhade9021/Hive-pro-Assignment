"""Hand-labelled golden set for evaluating NIST 800-53 retrieval.

Each case is a real vulnerability from ``Dataset/vulnerabilities.csv`` paired with
the NIST SP 800-53 control family (or families) that a security engineer would
consider a correct remediation reference. Labels are assigned by *what the
control should be*, independent of what the retriever actually returns, then
measured against retrieval output.

Families are expressed as base-control id prefixes (e.g. ``si-2``); a retrieved
control matches if its base id is in the case's ``expected_families``. Where a
finding legitimately maps to more than one control area, several families are
listed. The set is deliberately small and family-level (not exact-control),
which the README states as a caveat.
"""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class GoldenCase:
    """One labelled retrieval expectation."""

    vuln_id: str
    cve: str
    vulnerability_name: str
    affected_component: str
    expected_families: tuple[str, ...]
    rationale: str = field(default="")


GOLDEN_SET: list[GoldenCase] = [
    GoldenCase(
        "V-2064", "CVE-2023-4966", "Citrix ADC Session Token Leak (CitrixBleed)",
        "NetScaler ADC", ("sc-23", "sc-10", "ac-12"),
        "Session token leakage -> session authenticity / termination controls.",
    ),
    GoldenCase(
        "V-2015", "CVE-2024-21762", "Fortinet SSL-VPN Heap Buffer Overflow RCE",
        "VPN Firmware", ("si-2", "ra-5"),
        "Patchable memory-safety RCE -> flaw remediation / vulnerability monitoring.",
    ),
    GoldenCase(
        "V-2016", "CVE-2024-55591", "Fortinet FortiOS Authentication Bypass",
        "VPN Auth Module", ("ia-2", "ac-3", "si-2", "ia-5"),
        "Authentication bypass -> identification/authentication and access enforcement.",
    ),
    GoldenCase(
        "V-2002", "CVE-2024-6387", "OpenSSH Unauthenticated RCE (regreSSHion)",
        "OpenSSH", ("si-2", "ra-5"),
        "Vendor-patchable RCE -> flaw remediation.",
    ),
    GoldenCase(
        "V-2027", "CVE-2024-10978", "PostgreSQL Privilege Escalation",
        "Database Engine", ("ac-6", "ac-2", "ac-3", "si-2"),
        "Privilege escalation -> least privilege / account management.",
    ),
    GoldenCase(
        "V-2033", "CVE-2025-24813", "Apache Tomcat Partial PUT RCE",
        "Tomcat Server", ("si-2", "ra-5"),
        "Patchable RCE -> flaw remediation.",
    ),
    GoldenCase(
        "V-2040", "CVE-2023-22527", "Confluence RCE via OGNL Injection",
        "OGNL Template Engine", ("si-10", "si-2", "ra-5"),
        "Injection RCE -> input validation and flaw remediation.",
    ),
    GoldenCase(
        "V-2037", "CVE-2023-22515", "Atlassian Jira Server-Side Template Injection",
        "Template Engine", ("si-10", "si-2"),
        "Template injection -> input validation.",
    ),
    GoldenCase(
        "V-2041", "CVE-2023-22518", "Confluence Broken Access Control",
        "Access Control", ("ac-3", "ac-6", "ac-2"),
        "Broken access control -> access enforcement / least privilege.",
    ),
    GoldenCase(
        "V-2043", "CVE-2024-27198", "JetBrains TeamCity Authentication Bypass",
        "Authentication Handler", ("ia-2", "ac-3", "si-2", "ia-5"),
        "Authentication bypass -> identification/authentication.",
    ),
    GoldenCase(
        "V-2061", "CVE-2024-23897", "Jenkins Arbitrary File Read via CLI",
        "Jenkins CLI", ("ac-3", "ac-6", "si-2"),
        "Unauthorized file read -> access enforcement / least privilege.",
    ),
    GoldenCase(
        "V-2047", "CVE-2024-4577", "PHP CGI Argument Injection",
        "PHP CGI", ("si-10", "si-2", "ra-5"),
        "Argument injection -> input validation / flaw remediation.",
    ),
    GoldenCase(
        "V-2054", "CVE-2024-28987", "SolarWinds WHD Hardcoded Credentials",
        "Authentication", ("ia-5", "ac-2", "ia-2"),
        "Hardcoded credentials -> authenticator management.",
    ),
    GoldenCase(
        "V-2056", "CVE-2024-21410", "Microsoft Exchange NTLM Relay Privilege Escalation",
        "NTLM Auth", ("ia-2", "ac-6", "sc-8", "ia-5"),
        "Auth relay / privilege escalation -> authentication and least privilege.",
    ),
    GoldenCase(
        "V-2028", "CVE-SYN-2024-0420", "Unencrypted Database Backup Files",
        "Backup Config", ("cp-9", "sc-28"),
        "Unencrypted backups -> system backup / protection at rest.",
    ),
    GoldenCase(
        "V-2031", "CTRL-SYN-004", "Missing Encryption at Rest",
        "Storage Encryption", ("sc-28", "sc-13"),
        "Data-at-rest exposure -> protection of information at rest.",
    ),
    GoldenCase(
        "V-2070", "CTRL-SYN-006", "Firewall Rule Allows Overly Broad Inbound Access",
        "Firewall Policy", ("sc-7", "ac-17", "ca-3"),
        "Over-permissive inbound -> boundary protection.",
    ),
    GoldenCase(
        "V-2018", "CTRL-SYN-002", "VPN Management Plane Internet-Exposed",
        "Network Configuration", ("sc-7", "ac-17", "cm-7"),
        "Exposed management plane -> boundary protection / remote access.",
    ),
    GoldenCase(
        "V-2074", "K8S-SYN-001", "Kubernetes Dashboard Exposed Without Auth",
        "K8s Dashboard", ("ac-3", "ia-2", "sc-7"),
        "Unauthenticated admin surface -> access enforcement / authentication.",
    ),
    GoldenCase(
        "V-2001", "CVE-SYN-2026-0001", "Remote Code Execution in Web Framework",
        "Web Framework", ("si-2", "ra-5", "si-10"),
        "Framework RCE -> flaw remediation / vulnerability monitoring.",
    ),
    GoldenCase(
        "V-2029", "CTRL-SYN-003", "Excessive DB User Privileges",
        "Database Permissions", ("ac-6", "ac-2"),
        "Excessive privileges -> least privilege / account management.",
    ),
    GoldenCase(
        "V-2073", "CTRL-SYN-007", "No Immutable Backup Policy",
        "Backup Policy", ("cp-9", "cp-10", "si-7"),
        "Missing immutability -> system backup / recovery integrity.",
    ),
]
