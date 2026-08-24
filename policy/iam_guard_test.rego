package iam.guard_test

import data.iam.guard

vulnerable_input := {
	"role_permissions": [
		{"role": "legacy-admin", "actions": ["*"], "resources": ["*"]},
		{"role": "ops-oncall", "actions": ["ec2:*"], "resources": ["arn:aws:ec2:*:*:instance/*"]}
	],
	"inline_policies": [
		{"principal": "svc-backup", "attached": true}
	]
}

clean_input := {
	"role_permissions": [
		{"role": "ci-deployer", "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::build-artifacts/*"]}
	],
	"inline_policies": [
		{"principal": "svc-reporting", "attached": false}
	]
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
