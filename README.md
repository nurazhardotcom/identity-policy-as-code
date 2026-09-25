# identity-policy-as-code

> **Status:** Active — maintained. See [AI_DISCLOSURE.md](AI_DISCLOSURE.md).

> A deterministic security gate that reads a normalized Terraform-plan JSON
> and **denies wildcard IAM permissions and inline policies** — enforced by
> OPA/Rego in CI, not in a PDF.

[![security-gate](https://github.com/nurazhardotcom/identity-policy-as-code/actions/workflows/security-gate.yml/badge.svg)](https://github.com/nurazhardotcom/identity-policy-as-code/actions/workflows/security-gate.yml)

> **Enterprise IAM/PAM & Policy-as-Code gate.**
> Enforces least-privilege access and automated compliance checks for
> enterprise directory and cloud platforms.

## 1. Enterprise context

* **Target environment:** Enterprise hybrid / CyberArk Vault & Conjur /
  Active Directory / OPA.
* **Regulatory focus:** SG PDPA compliance-as-code.
* **Core function:** Replaces manual privilege auditing and risky IAM drift
  with deterministic, version-controlled policy evaluation. The same Rego
  source enforces both the CI gate (offline, `gate.sh`) and request-time
  checks via `service/server.clj` (OPA as PDP, this service as PEP) —
  one policy, two enforcement points, no drift possible.

## Why

Compliance findings are history; gates are prevention. Wildcard actions
(`"actions": ["*"]`), unbounded resources, and bolted-on inline IAM policies
are three structural risks that survive every review cycle — because review
cycles end and the permissions stay.

This repo makes them **merge-blocking**: three fixtures prove the gate in all
directions (vulnerable denied, clean allowed, malformed input denied) on
every push and pull request.

## Input contract

```jsonc
{
  "role_permissions": [ { "role": "...", "actions": ["s3:GetObject"], "resources": ["arn:..."] } ],
  "inline_policies":  [ { "principal": "...", "attached": false } ]
}
```

Normalized Terraform-plan / access-review output. Four rules, no exceptions:

| Rule | Denies |
|---|---|
| wildcard action | `"*"` in any role's action list |
| wildcard resource | bare `"*"` bound to any role |
| inline policy | `attached: true` on any principal |
| missing section | absent **or** `null` `role_permissions` or `inline_policies` |

An explicitly empty list (`[]`) is valid and means "none of that kind"; an
absent or `null` section is denied, so a truncated normalizer can never read
as clean.

## Run locally (1 command)

```bash
./scripts/gate.sh        # needs opa on PATH — runs the full gate
```

## Automated testing

```bash
opa check --strict policy/  # syntax check
opa fmt --fail policy/      # format check (non-zero on drift)
opa test policy/ -v         # Rego unit suite (policy/iam_guard_test.rego)
```

`scripts/gate.sh` runs all three in order: strict syntax check + format
check → unit tests → fixture gates (vulnerable and malformed inputs must
be denied, clean input must be allowed). Exit 0 = merge allowed, exit 1 =
blocked. CI (`opa-gate` job) runs this exact script on every push/PR.

## CI

Three jobs on every push/PR:

1. **opa-gate** — strict syntax + format check, unit tests, all fixture gates (`scripts/gate.sh`)
2. **pdpa-secret-scan** — [pdpa-sg-clj](https://github.com/nurazhardotcom/pdpa-sg-clj)
   scans the repo for Singapore PII (NRIC checksums) and secrets; fails on any finding
3. **supply-chain-attest** — re-runs `scripts/gate.sh`, then bundles `policy/`, `fixtures/`
   and `scripts/`, and produces keyless Sigstore build provenance plus a signed
   `checksums.txt` restricted to `nurazhardotcom`

## The bigger story

This is the public slice of a working compliance-automation practice:
zero-dependency CLI scanners, deterministic scoring, evidence over assertions.

- Blog: [Replacing imperative scan code with Rego](https://nurazhar.com/rego-replaces-clojure-iam.html)
- Tooling: [pdpa-sg-clj](https://github.com/nurazhardotcom/pdpa-sg-clj) · [pam-audit-clj](https://github.com/nurazhardotcom/pam-audit-clj) · [identity-control-plane](https://github.com/nurazhardotcom/identity-control-plane)

## License

MIT
