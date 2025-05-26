package cloudsmith
import rego.v1

max_epss := 0.0002
ignored_cves := {"CVE-2023-45853"}

match if {
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
