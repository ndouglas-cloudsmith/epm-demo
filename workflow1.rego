package cloudsmith
import rego.v1

# Default match rule
default match := false

# Define minimum CVSS score threshold
max_cvss_score := 4

# Define time-based policy threshold (Vulnerabilities older than 60 days)
older_than_days := -60

# Define CVEs to ignore
ignored_cves := {"CVE-2023-45853", "CVE-2024-12345"}

# Generate reasons for matching vulnerabilities
reason contains msg if {
    # Loop through all vulnerabilities
    some vulnerability in input.v0.security_scan.Vulnerabilities

    # Ignore specific CVEs
    not ignored_cve(vulnerability)

    # Only consider vulnerabilities with a fixed version
    vulnerability.FixedVersion
    vulnerability.Status == "fixed"

    # Ensure the CVSS score exceeds the threshold
    some _, val in vulnerability.CVSS
    val.V3Score >= max_cvss_score

    # Apply time-based filtering (only consider vulnerabilities older than X days)
    t := time.add_date(time.now_ns(), 0, 0, older_than_days)
    published_date := time.parse_rfc3339_ns(vulnerability.PublishedDate)
    published_date <= t

    # Message for logging the reason
    msg := sprintf(
        "CVSS Score: %v | Package: %v | Vulnerability: %v | Reason: %v",
        [val.V3Score, input.v0["package"].name, vulnerability.VulnerabilityID, vulnerability.Description]
    )
}

# Rule to check if CVE is ignored
ignored_cve(vulnerability) if {
    vulnerability.VulnerabilityID in ignored_cves
}
