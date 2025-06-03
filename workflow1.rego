package cloudsmith
import rego.v1

default match := false

# Define minimum CVSS score threshold
max_cvss_score := 4

# Define time-based policy threshold (Vulnerabilities older than 10 days)
older_than_days := -10

# Define CVEs to ignore
ignored_cves := {"CVE-2023-45853", "CVE-2024-12345"}

match if {
  # some vulnerability in input.v0.security_scan.Vulnerabilities (Deprecated)
    some vulnerability in target.Vulnerabilities

    not ignored_cve(vulnerability)
    vulnerability.FixedVersion
    vulnerability.Status == "fixed"

    some _, val in vulnerability.CVSS
    val.V3Score >= max_cvss_score

    t := time.add_date(time.now_ns(), 0, 0, older_than_days)
    published_date := time.parse_rfc3339_ns(vulnerability.PublishedDate)
    published_date <= t
}

ignored_cve(vulnerability) if {
    vulnerability.VulnerabilityID in ignored_cves
}
