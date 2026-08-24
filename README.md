# identity-policy-as-code

> A deterministic security gate that reads a normalized Terraform-plan JSON
> and **denies wildcard IAM permissions and inline policies** — enforced by
> OPA/Rego in CI, not in a PDF.

[![security-gate](https://github.com/nurazhardotcom/identity-policy-as-code/actions/workflows/security-gate.yml/badge.svg)](https://github.com/nurazhardotcom/identity-policy-as-code/actions/workflows/security-gate.yml)

## Why

Compliance findings are history; gates are prevention. Wildcard actions
(`"actions": ["*"]`), unbounded resources, and bolted-on inline IAM policies
are three structural risks that survive every review cycle — because review
cycles end and the permissions stay.

This repo makes them **merge-blocking**: two fixtures prove the gate works in
both directions (vulnerable input denied, clean input allowed) on every push
and pull request.

## Input contract

```jsonc
{
  "role_permissions": [ { "role": "...", "actions": ["s3:GetObject"], "resources": ["arn:..."] } ],
  "inline_policies":  [ { "principal": "...", "attached": false } ]
}
```

Normalized Terraform-plan / access-review output. Three rules, no exceptions:

| Rule | Denies |
|---|---|
| wildcard action | `"*"` in any role's action list |
| wildcard resource | bare `"*"` bound to any role |
| inline policy | `attached: true` on any principal |

## Run locally

```bash
./scripts/gate.sh        # needs opa on PATH
```

## CI

Two jobs on every push/PR:

1. **opa-gate** — syntax check, unit tests, both fixture gates (`scripts/gate.sh`)
2. **pdpa-secret-scan** — [pdpa-sg-clj](https://github.com/nurazhardotcom/pdpa-sg-clj)
   scans the repo for Singapore PII (NRIC checksums) and secrets; fails on any finding

## The bigger story

This is the public slice of a working compliance-automation practice:
zero-dependency CLI scanners, deterministic scoring, evidence over assertions.

- Blog: [Replacing imperative scan code with Rego](https://nurazhar.com/rego-replaces-clojure-iam.html)
- Tooling: [pdpa-sg-clj](https://github.com/nurazhardotcom/pdpa-sg-clj) · [aur-audit](https://github.com/nurazhardotcom/aur-audit) · [security-tools](https://github.com/nurazhardotcom/security-tools)

## License

MIT
