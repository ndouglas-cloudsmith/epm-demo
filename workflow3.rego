package cloudsmith
import rego.v1
default match := false
max_epss := 0.2
target_repository := "acme-corporation"
ignored_cves := {"CVE-2023-45853"}

match if {
    input.v0["repository"]["name"] == target_repository
    some vulnerability in input.v0["vulnerabilities"]
    vulnerability["patched_versions"]
    vulnerability["severity"] == "HIGH"
    not ignored_cve(vulnerability)
    exceeded_max_epss(vulnerability)
}

exceeded_max_epss(vulnerability) if {
    some _, val in vulnerability
    val["score"] > max_epss
}

ignored_cve(vulnerability) if {
    vulnerability["VulnerabilityID"] in ignored_cves
}
