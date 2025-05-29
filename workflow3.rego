package cloudsmith
import rego.v1
default match := false

max_epss := 0.0001
# target_repository := "rf-prod"
ignored_cves := {"CVE-2025-27122"}

match if {
    input.v0["repository"]["name"] == target_repository
    some vulnerability in input.v0[vulnerabilities]
    vulnerability["patched_versions"]
    not ignored_cve(vulnerability)
    exceeded_max_epss(vulnerability)
}

exceeded_max_epss(vulnerability) if {
    some _, val in vulnerability
    val["score"] > max_epss
}

ignored_cve(vulnerability) if {
    vulnerability["identifier"] in ignored_cves
}
