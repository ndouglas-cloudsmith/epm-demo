package cloudsmith
import rego.v1

default match := false
required_tag := "ready-for-production"

match if {
    has_required_tag
}

has_required_tag if {
    some i
    input.v0["package"]["tags"]["info"][i] == required_tag
}
