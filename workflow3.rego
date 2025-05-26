package cloudsmith
import rego.v1

max_epss := 0.0002

match if {
    some vulnerability in input.v0["vulnerabilities"]
    vulnerability.epss.score > max_epss
}
