#!/usr/bin/env bash
# gate.sh — local runner mirroring the CI native policy security gate.
# Exit 0 = merge allowed. Exit 1 = something failed. No exceptions, no warnings.
set -euo pipefail

readonly OPA_VERSION="1.21.0"
OPA="${OPA:-opa}"

fail() {
	printf 'gate: %s\n' "$*" >&2
	exit 1
}

version="$("$OPA" version 2>/dev/null | awk '$1 == "Version:" {print $2; exit}' || true)"
[[ "$version" == "$OPA_VERSION" ]] ||
	fail "OPA $OPA_VERSION is required; '$OPA' reports '${version:-unknown}'"

is_count() {
	[[ "$1" =~ ^[0-9]+$ ]] || fail "expected a numeric policy count, got '$1'"
}

echo "== 1/3 policy syntax =="
"$OPA" check --strict policy/
"$OPA" fmt --fail policy/ >/dev/null

echo "== 2/3 unit tests =="
"$OPA" test policy/ -v

echo "== 3/3 fixture gates =="

vuln_count=$("$OPA" eval --format raw -i fixtures/vulnerable.tfplan.json -d policy/ 'count(data.iam.guard.deny)')
is_count "$vuln_count"
if [ "$vuln_count" -ge 1 ]; then
	echo "OK   vulnerable fixture correctly denied ($vuln_count violations)"
else
	echo "FAIL vulnerable fixture passed the gate — policy is broken"
	exit 1
fi

clean_count=$("$OPA" eval --format raw -i fixtures/clean.tfplan.json -d policy/ 'count(data.iam.guard.deny)')
is_count "$clean_count"
if [ "$clean_count" -eq 0 ]; then
	echo "OK   clean fixture correctly allowed"
else
	echo "FAIL clean fixture denied ($clean_count false positives)"
	exit 1
fi

malformed_count=$("$OPA" eval --format raw -i fixtures/missing-sections.tfplan.json -d policy/ 'count(data.iam.guard.deny)')
is_count "$malformed_count"
if [ "$malformed_count" -ge 1 ]; then
	echo "OK   malformed fixture correctly denied ($malformed_count violations)"
else
	echo "FAIL malformed fixture passed the gate — fail-closed rule is broken"
	exit 1
fi

echo "GATE: PASS"
