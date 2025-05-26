package cloudsmith
import rego.v1

max_epss := 0.0001

match if {
    some vulnerability in input.vulnerabilities
    vulnerability.epss.score > max_epss
}
