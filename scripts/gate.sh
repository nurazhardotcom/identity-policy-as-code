#!/usr/bin/env bash
# gate.sh — local runner mirroring the CI security gate exactly.
# Exit 0 = merge allowed. Exit 1 = something failed. No exceptions, no warnings.
set -euo pipefail

OPA="${OPA:-opa}"

echo "== 1/3 policy syntax =="
"$OPA" check policy/

echo "== 2/3 unit tests =="
"$OPA" test policy/ -v

echo "== 3/3 fixture gates =="

vuln_count=$("$OPA" eval --format raw -i fixtures/vulnerable.tfplan.json -d policy/ 'count(data.iam.guard.deny)')
if [ "$vuln_count" -ge 1 ]; then
	echo "OK   vulnerable fixture correctly denied ($vuln_count violations)"
else
	echo "FAIL vulnerable fixture passed the gate — policy is broken"
	exit 1
fi

clean_count=$("$OPA" eval --format raw -i fixtures/clean.tfplan.json -d policy/ 'count(data.iam.guard.deny)')
if [ "$clean_count" -eq 0 ]; then
	echo "OK   clean fixture correctly allowed"
else
	echo "FAIL clean fixture denied ($clean_count false positives)"
	exit 1
fi

echo "GATE: PASS"
