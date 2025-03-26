# epm-demo
This repo was created for the purpose of demonstrating Enterprise Policy Management (EPM) in Cloudsmith


## Creating the Payload for my policy.rego file
https://github.com/ndouglas-cloudsmith/epm-demo/blob/main/policy.rego


```
escaped_policy=$(jq -Rs . < policy.rego)

cat <<EOF > payload.json
{
  "name": "nigel-opa-policy",
  "description": "Policy to quarantine and tag CVSS > 6",
  "rego": $escaped_policy,
  "enabled": false,
  "is_terminal": false,
  "precedence": 1
}
EOF
```

## Incorrect Content-Type or Headers
```
curl -X POST "https://api.cloudsmith.io/v2/orgs/acme-corporation/policies/nigel-opa-policy/actions/" \
-H "Content-Type: application/json" \
-H "X-Api-Key: $CLOUDSMITH_API_KEY" \
--data-binary @- <<EOF
{
  "action_type": "SetPackageState",
  "precedence": 1,
  "package_state": "QUARANTINED"
}
EOF
```
