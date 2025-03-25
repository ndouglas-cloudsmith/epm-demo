# References from - https://help.cloudsmith.io/edit/enterprise-policy-management-getting-started

package cloudsmith
import rego.v1
default match := false
max_cvss_score := 6

match if {
	count(reason) != 0
}

reason contains msg if {
	some vulnerability in input.v0.security_scan.Vulnerabilities
    vulnerability.FixedVersion
    vulnerability.Status == "fixed"
	some _, val in vulnerability.CVSS
	val.V3Score > max_cvss_score
	msg := "CVSS Score >= 6"
}
