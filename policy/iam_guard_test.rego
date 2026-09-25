package iam.guard_test

import data.iam.guard

vulnerable_input := {
	"role_permissions": [
		{"role": "legacy-admin", "actions": ["*"], "resources": ["*"]},
		{"role": "ops-oncall", "actions": ["ec2:*"], "resources": ["arn:aws:ec2:*:*:instance/*"]},
	],
	"inline_policies": [
		{"principal": "svc-backup", "attached": true},
	],
}

clean_input := {
	"role_permissions": [
		{"role": "ci-deployer", "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::build-artifacts/*"]},
	],
	"inline_policies": [
		{"principal": "svc-reporting", "attached": false},
	],
}

test_vulnerable_fixture_denied if {
	count(guard.deny) > 0 with input as vulnerable_input
}

test_clean_fixture_allowed if {
	count(guard.deny) == 0 with input as clean_input
}

test_wildcard_action_detected if {
	d := guard.deny with input as {"role_permissions": [{"role": "x", "actions": ["*"], "resources": []}], "inline_policies": []}
	count(d) == 1
}

test_wildcard_resource_detected if {
	d := guard.deny with input as {"role_permissions": [{"role": "x", "actions": ["s3:Get"], "resources": ["*"]}], "inline_policies": []}
	count(d) == 1
}

test_inline_policy_flagged if {
	d := guard.deny with input as {"role_permissions": [], "inline_policies": [{"principal": "p", "attached": true}]}
	count(d) == 1
}

test_benign_wildcard_suffix_allowed if {
	# arn:*-suffix scoping is fine; only the bare "*" resource is denied
	d := guard.deny with input as {"role_permissions": [{"role": "x", "actions": ["s3:Get"], "resources": ["arn:aws:s3:::bucket/*"]}], "inline_policies": []}
	count(d) == 0
}

test_missing_role_permissions_denied if {
	d := guard.deny with input as {"inline_policies": []}
	count(d) == 1
}

test_missing_inline_policies_denied if {
	d := guard.deny with input as {"role_permissions": []}
	count(d) == 1
}

test_empty_sections_allowed if {
	d := guard.deny with input as {"role_permissions": [], "inline_policies": []}
	count(d) == 0
}

test_null_role_permissions_denied if {
	d := guard.deny with input as {"role_permissions": null, "inline_policies": []}
	count(d) == 1
}

test_null_inline_policies_denied if {
	d := guard.deny with input as {"role_permissions": [], "inline_policies": null}
	count(d) == 1
}

# ---------------------------------------------------------------------------
# Edge cases. Each test below pins behavior that was verified empirically
# against this policy (opa eval), not an assumption.
#
# `deny` is a SET of message strings, so two findings that produce the
# identical message collapse into one entry. This is intentional: the gate
# reports distinct problems, not duplicate problem instances.
# ---------------------------------------------------------------------------

# --- Service-level action wildcards (e.g. "ec2:*") ----------------------
# KNOWN GAP: Rule 1 denies only the bare "*" action, so a service-scoped
# wildcard such as "ec2:*" is currently permitted on its own. Whether that
# should be a separate rule is an open policy decision for the repo owner;
# until then this test documents the actual, intentional current behavior so
# a future change to Rule 1 is a visible, deliberate diff.
test_service_wildcard_action_allowed_on_scoped_resource if {
	d := guard.deny with input as {"role_permissions": [{"role": "ops", "actions": ["ec2:*"], "resources": ["arn:aws:ec2:*:*:instance/*"]}], "inline_policies": []}
	count(d) == 0
}

# Defense in depth: a service wildcard combined with an unbounded resource
# scope is still blocked, by Rule 2 rather than Rule 1. Pinned to the exact
# message so the rule attribution cannot silently change.
test_service_wildcard_denied_via_unbounded_resource if {
	d := guard.deny with input as {"role_permissions": [{"role": "ops", "actions": ["ec2:*"], "resources": ["*"]}], "inline_policies": []}
	d == {"wildcard resource bound to role 'ops'"}
}

# --- Empty-string identifiers -------------------------------------------
# KNOWN GAP: neither the role nor the principal name is validated for
# emptiness. An empty name is not itself a finding; these tests pin that the
# underlying wildcard/inline violation is still caught and still names the
# offending subject, even when that subject's name is empty.
test_empty_role_name_reported_in_deny_message if {
	d := guard.deny with input as {"role_permissions": [{"role": "", "actions": ["*"], "resources": []}], "inline_policies": []}
	d == {"wildcard action granted to role ''"}
}

test_empty_principal_name_reported_in_deny_message if {
	d := guard.deny with input as {"role_permissions": [], "inline_policies": [{"principal": "", "attached": true}]}
	d == {"inline IAM policy attached to principal ''"}
}

test_empty_role_name_allowed_when_scope_is_bounded if {
	d := guard.deny with input as {"role_permissions": [{"role": "", "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::build-artifacts/*"]}], "inline_policies": []}
	count(d) == 0
}

# --- Duplicate array items ----------------------------------------------
# Identical findings collapse: `deny` is a set, so repeated identical grants
# yield exactly one message. Distinct subjects stay distinct.
test_duplicate_actions_within_role_deduplicated if {
	d := guard.deny with input as {"role_permissions": [{"role": "dup", "actions": ["*", "*"], "resources": []}], "inline_policies": []}
	count(d) == 1
}

test_duplicate_resources_within_role_deduplicated if {
	d := guard.deny with input as {"role_permissions": [{"role": "dup", "actions": ["s3:Get"], "resources": ["*", "*"]}], "inline_policies": []}
	count(d) == 1
}

test_duplicate_identical_role_entries_deduplicated if {
	d := guard.deny with input as {"role_permissions": [{"role": "dup", "actions": ["*"], "resources": []}, {"role": "dup", "actions": ["*"], "resources": []}], "inline_policies": []}
	count(d) == 1
}

test_distinct_roles_each_reported_separately if {
	d := guard.deny with input as {"role_permissions": [{"role": "a", "actions": ["*"], "resources": []}, {"role": "b", "actions": ["*"], "resources": []}], "inline_policies": []}
	count(d) == 2
}
