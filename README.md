# identity-policy-as-code

> **Status:** Active — maintained. See [AI_DISCLOSURE.md](AI_DISCLOSURE.md).

> A deterministic security gate that reads a normalized Terraform-plan JSON
> and **denies wildcard IAM permissions and inline policies** — enforced by
> the same version-pinned Rego policy in native OPA and in an OPA Wasm module.

[![security-gate](https://github.com/nurazhardotcom/identity-policy-as-code/actions/workflows/security-gate.yml/badge.svg)](https://github.com/nurazhardotcom/identity-policy-as-code/actions/workflows/security-gate.yml)

> **Enterprise IAM/PAM & Policy-as-Code gate.**
> Enforces least-privilege access and automated compliance checks for
> enterprise directory and cloud platforms.

## 1. Enterprise context

* **Target environment:** Enterprise hybrid / CyberArk Vault & Conjur /
  Active Directory / OPA.
* **Regulatory focus:** SG PDPA compliance-as-code.
* **Core function:** Replaces manual privilege auditing and risky IAM drift
  with deterministic, version-controlled policy evaluation. The production
  source is `policy/iam_guard.rego`, compiled by **OPA 1.21.0** for the native
  gate and for the `iam/guard/deny` Wasm entrypoint.

The three enforcement paths have different runtime boundaries:

| Path | What it proves | What it does not claim |
|---|---|---|
| `scripts/gate.sh` | OPA 1.21.0 parses, formats, unit-tests, and evaluates the Rego source natively in CI. | It does not run a browser or a remote PDP. |
| `npm run verify:wasm` | The same production source, compiled by OPA 1.21.0, evaluates through `@open-policy-agent/opa-wasm` 1.10.0 and matches native results for the parity vectors. | It is a Node SDK verification, not a browser integration test and not a replacement for the OPA server. |
| `service/server.clj` | The Babashka PEP forwards a request to the OPA Data API PDP at `iam/guard/deny` and returns a deny-by-default decision. | It does not load Wasm in the request path; the OPA server remains the runtime PDP. |

The Wasm module is suitable for a browser or another embedded WebAssembly
host because it is the raw module produced by OPA, but this repository only
automates the Node/npm host. Browser integration, network transport, and
production PDP operations remain deployment responsibilities.

## Why

Compliance findings are history; gates are prevention. Wildcard actions
(`"actions": ["*"]`), unbounded resources, and bolted-on inline IAM policies
are structural risks that survive every review cycle — because review cycles
end and the permissions stay.

This repo makes them **merge-blocking**: all three fixtures plus the edge-case
parity vectors prove the gate in both native OPA and Wasm on every push and
pull request.

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

An explicitly empty list (`[]`) is valid and means “none of that kind”. An
absent or `null` section is denied, so a truncated normalizer cannot read as
clean. The service also treats a null section as present contract data rather
than switching to its convenience-request shape.

## Native gate

The compiler is pinned; a different `opa` on `PATH` is a hard failure, not an
implicit fallback:

```bash
OPA=/path/to/opa-1.21.0 ./scripts/gate.sh
# or, when opa 1.21.0 is already on PATH:
./scripts/gate.sh
```

The gate runs:

```bash
opa check --strict policy/
opa fmt --fail policy/
opa test policy/ -v
```

It then evaluates the vulnerable, clean, and missing-sections fixtures. Exit 0
means merge allowed; a non-zero exit blocks the change.

## Wasm build and exact parity

Build a real OPA Wasm bundle from the production file, extract its raw
`policy.wasm`, and write a deterministic hash manifest:

```bash
./scripts/build-wasm.sh
npm ci
npm run verify:wasm
```

If no OPA binary is available, `build-wasm.sh` downloads the official OPA
1.21.0 binary into a temporary tool directory and verifies its published
SHA-256. If a binary is present, its reported version must be exactly 1.21.0;
the script will not silently use another version.

Generated files are ignored under `build/wasm/`:

```text
build/wasm/
├── policy-bundle.tar.gz   # OPA bundle containing policy.wasm
├── policy.wasm            # raw module loaded by the SDK
├── checksums.txt          # bundle and raw-module hashes
└── manifest.json          # OPA version, entrypoint, source and artifact hashes
```

`tests/parity-vectors.json` covers all three fixtures and the policy's edge
cases, including missing/null sections, scoped service wildcards, empty names,
and duplicate findings. The verifier:

* loads `policy.wasm` with `@open-policy-agent/opa-wasm` 1.10.0;
* calls the explicit `iam/guard/deny` entrypoint;
* exercises the policy's `sprintf`-generated denial messages;
* compares the normalized native OPA 1.21.0 result and Wasm result exactly;
* rejects undefined, empty, malformed, duplicate, non-string, or missing
  results as a deny rather than treating them as an allow.

The comparison is exact at the decision-set level. Rego `deny` is a set, so
messages are sorted before comparison; duplicate policy findings remain
intentionally collapsed. This is evidence over the pinned vectors, not a claim
of equivalence for inputs that were not exercised.

## Request-time PEP / PDP

The service keeps the existing request-time shape:

```bash
opa run -s policy/ &          # OPA PDP on :8181
bb service/server.clj &       # Babashka PEP on :8080
```

`/v1/check` accepts either the full input contract or the documented
single-request convenience shape. A present-but-null section is never treated
as a convenience request. Empty or incomplete convenience objects are also
rejected into explicit null sections rather than becoming a role with nil
actions/resources. The PDP response contract is deliberately strict: only a
successful JSON object with a unique string-array `result` can allow. A missing
result, malformed response, non-2xx response, or PDP exception is an explicit
`allowed: false` error decision. The PEP does not inspect the PDP's runtime
version or replace the server with the embedded module; deployments must
operate a compatible OPA PDP if they want the same compiler boundary as CI.

Run the native service tests with:

```bash
bb test
```

The tests cover normalization, valid deny/allow responses, missing and
malformed PDP results, non-2xx responses, thrown PDP errors, and the null
convenience-shape regression.

## CI and supply chain

The workflow runs these independent checks:

1. **`opa-gate`** — OPA 1.21.0 native gate plus Babashka service tests.
2. **`wasm-gate`** — pinned npm install, OPA 1.21.0 Wasm build, SDK load, and
   exact native/Wasm parity verification.
3. **`pdpa-secret-scan`** — [pdpa-sg-clj](https://github.com/nurazhardotcom/pdpa-sg-clj)
   scans this repository for Singapore PII and secrets.
4. **`supply-chain-attest`** — builds and verifies the Wasm, creates a distinct
   `identity-policy-source-*.tar.gz` source archive, and treats the OPA output
   as `policy-bundle.tar.gz` rather than calling the source archive a bundle.
   The raw Wasm, OPA bundle, manifest, and source archive are attested; the
   checksum manifest is signed with keyless Cosign and uploaded with the
   artifacts.

The npm dependency is exact-pinned in both `package.json` and
`package-lock.json`; Dependabot watches npm but ignores implicit major SDK
upgrades pending an explicit compatibility review.

## License

MIT
