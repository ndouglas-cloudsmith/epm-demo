package cloudsmith

import rego.v1

default match := false

max_cvss_score := 7
older_than_days := -30
target_repository := "testing-policy"
ignored_cves := {"CVE-2023-45853", "CVE-2024-12345"}

match if {
    in_target_repository
    count(reason) != 0
}

in_target_repository if {
    input.v0["repository"]["name"] == target_repository
}

reason contains msg if {
    some vulnerability in input.v0["security_scan"]["Vulnerabilities"]

    not ignored_cve(vulnerability)

    vulnerability["FixedVersion"]
    vulnerability["Status"] == "fixed"

    some _, val in vulnerability["CVSS"]
    val["V3Score"] >= max_cvss_score

    t := time.add_date(time.now_ns(), 0, 0, older_than_days)
    published_date := time.parse_rfc3339_ns(vulnerability["PublishedDate"])
    published_date <= t

    msg := sprintf("CVSS Score: %v | Package: %v | Vulnerability: %v | Reason: %v",
      [val["V3Score"], input.v0["package"]["name"], vulnerability["VulnerabilityID"], vulnerability["Description"]])
}

ignored_cve(vulnerability) if {
    vulnerability["VulnerabilityID"] in ignored_cves
}
