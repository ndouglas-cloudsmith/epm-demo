package cloudsmith
import rego.v1

max_epss := 0.0002
# Ignoring the Spotipy lightweight Python library CVE for the Spotify Web API.
ignored_cves := {"CVE-2025-27154"}

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
