#!/usr/bin/env bash
# Build the production iam.guard policy as an OPA Wasm bundle and raw module.
# The compiler version is deliberately fixed; a different opa on PATH is a
# hard failure rather than an implicit fallback.
set -euo pipefail

readonly OPA_VERSION="1.21.0"
readonly OPA_ENTRYPOINT="iam/guard/deny"
readonly ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly OPA_SOURCE="$ROOT_DIR/policy/iam_guard.rego"
OUTPUT_DIR="${WASM_OUTPUT_DIR:-$ROOT_DIR/build/wasm}"
if [[ "$OUTPUT_DIR" != /* ]]; then
	OUTPUT_DIR="$ROOT_DIR/$OUTPUT_DIR"
fi
readonly OUTPUT_DIR

readonly -A OPA_CHECKSUMS=(
	["Linux/x86_64"]="81f320f5fd4e5825e58ee3bf5edab1205b469cd72c8c78887f50bdf12ac9af86"
	["Linux/aarch64"]="3547902b17ca98ede1941322d69c1b5187de4ac714d86a0dc2b93d6d1974d38d"
	["Linux/arm64"]="3547902b17ca98ede1941322d69c1b5187de4ac714d86a0dc2b93d6d1974d38d"
	["Darwin/x86_64"]="0ceb96979d259b3ee31711a6b316a592b8ffcfdd4209cc37600ed85a6cd4a55c"
	["Darwin/arm64"]="f1e4da6467a2adb2846bb23eec6ea00d8c3a04786f9270bb11003d22dfd827a5"
)
readonly -A OPA_ASSETS=(
	["Linux/x86_64"]="opa_linux_amd64"
	["Linux/aarch64"]="opa_linux_arm64"
	["Linux/arm64"]="opa_linux_arm64"
	["Darwin/x86_64"]="opa_darwin_amd64"
	["Darwin/arm64"]="opa_darwin_arm64"
)

fail() {
	printf 'build-wasm: %s\n' "$*" >&2
	exit 1
}

[[ "$OUTPUT_DIR" == "$ROOT_DIR/build/"* ]] ||
	fail "WASM_OUTPUT_DIR must be a path below $ROOT_DIR/build/"

sha256_file() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{print $1}'
	else
		fail "sha256sum or shasum is required"
	fi
}

check_username_coherence() {
	command -v rg >/dev/null 2>&1 || fail "ripgrep is required for the username coherence check"
	if rg -n --hidden \
		--glob '!.git/**' \
		--glob '!build/**' \
		--glob '!node_modules/**' \
		'github\.com/nurazhar[^d]|gitlab\.com/nurazhardotcom' \
		"$ROOT_DIR"; then
		fail "username coherence check failed; fix the matching URL before building"
	fi
}

opa_version() {
	"$1" version 2>/dev/null | awk '$1 == "Version:" {print $2; exit}'
}

download_opa() {
	local platform key asset expected tool_dir binary tmp
	platform="$(uname -s)/$(uname -m)"
	key="$platform"
	asset="${OPA_ASSETS[$key]-}"
	expected="${OPA_CHECKSUMS[$key]-}"
	[[ -n "$asset" && -n "$expected" ]] || fail "unsupported platform: $platform"

	tool_dir="${OPA_TOOL_DIR:-${TMPDIR:-/tmp}/identity-policy-opa-$OPA_VERSION}"
	mkdir -p "$tool_dir"
	binary="$tool_dir/opa-$OPA_VERSION-${platform//\//-}"
	if [[ ! -x "$binary" ]] || [[ "$(sha256_file "$binary" 2>/dev/null || true)" != "$expected" ]]; then
		command -v curl >/dev/null 2>&1 || fail "curl is required to download OPA $OPA_VERSION"
		tmp="$binary.tmp.$$"
		trap 'rm -f "${tmp:-}"' RETURN
		curl -fsSL --retry 3 \
			"https://github.com/open-policy-agent/opa/releases/download/v$OPA_VERSION/$asset" \
			-o "$tmp"
		[[ "$(sha256_file "$tmp")" == "$expected" ]] || fail "downloaded OPA checksum mismatch"
		mv "$tmp" "$binary"
		chmod 0755 "$binary"
		trap - RETURN
	fi
	printf '%s\n' "$binary"
}

resolve_opa() {
	local candidate version
	candidate="${OPA_BIN:-}"
	if [[ -z "$candidate" ]]; then
		if command -v opa >/dev/null 2>&1; then
			candidate="$(command -v opa)"
		else
			candidate="$(download_opa)"
		fi
	elif [[ "$candidate" != */* ]]; then
		candidate="$(command -v "$candidate" || true)"
	fi
	[[ -n "$candidate" && -x "$candidate" ]] || fail "OPA binary not found (set OPA_BIN to an OPA $OPA_VERSION binary)"
	version="$(opa_version "$candidate" || true)"
	[[ "$version" == "$OPA_VERSION" ]] ||
		fail "OPA $OPA_VERSION is required; '$candidate' reports '${version:-unknown}' (OPA $OPA_VERSION was not used)"
	printf '%s\n' "$candidate"
}

check_username_coherence
OPA="$(resolve_opa)"
[[ -f "$OPA_SOURCE" ]] || fail "production policy not found: $OPA_SOURCE"

"$OPA" check --strict "$OPA_SOURCE"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
readonly BUNDLE="$OUTPUT_DIR/policy-bundle.tar.gz"
readonly RAW="$OUTPUT_DIR/policy.wasm"
readonly EXTRACT="$OUTPUT_DIR/.extract"
mkdir -p "$EXTRACT"

# Run from the repository root so the bundle records a stable relative source
# path instead of embedding the caller's absolute workspace path.
(
	cd "$ROOT_DIR"
	"$OPA" build \
		--target wasm \
		--entrypoint "$OPA_ENTRYPOINT" \
		--output "$BUNDLE" \
		policy/iam_guard.rego
)

if ! tar -tzf "$BUNDLE" | grep -E '(^|/)policy\.wasm$' >/dev/null; then
	fail "OPA bundle does not contain policy.wasm"
fi
# OPA 1.21.0 stores the bundle member as /policy.wasm.  GNU tar and bsdtar
# both normalize that leading slash when the member is requested explicitly.
tar -xzf "$BUNDLE" -C "$EXTRACT" /policy.wasm
mv "$EXTRACT/policy.wasm" "$RAW"
rm -rf "$EXTRACT"

source_sha="$(sha256_file "$OPA_SOURCE")"
bundle_sha="$(sha256_file "$BUNDLE")"
wasm_sha="$(sha256_file "$RAW")"

(
	cd "$OUTPUT_DIR"
	printf '%s  policy-bundle.tar.gz\n%s  policy.wasm\n' "$bundle_sha" "$wasm_sha" >checksums.txt
)

cat >"$OUTPUT_DIR/manifest.json" <<JSON
{
  "schema_version": 1,
  "opa_version": "$OPA_VERSION",
  "entrypoint": "$OPA_ENTRYPOINT",
  "source": "policy/iam_guard.rego",
  "source_sha256": "$source_sha",
  "artifacts": {
    "bundle": {
      "file": "policy-bundle.tar.gz",
      "sha256": "$bundle_sha"
    },
    "wasm": {
      "file": "policy.wasm",
      "sha256": "$wasm_sha"
    }
  }
}
JSON

printf 'OPA %s: wrote %s, %s, checksums.txt, and manifest.json\n' \
	"$OPA_VERSION" "$BUNDLE" "$RAW"
