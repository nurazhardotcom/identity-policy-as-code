# iam.guard — deny-set policy over a normalized Terraform-plan input.
#
# Input contract (see fixtures/):
#   input.role_permissions[] : { role: string, actions: [string], resources: [string] }
#   input.inline_policies[]  : { principal: string, attached: bool }
#
# Both sections are required (Rule 0): an input missing either section
# is denied outright, so a truncated normalizer can never read as clean.
# An explicitly empty list is fine and means "none of that kind".
#
# Doctrine: wildcard grants and inline policies are structural IAM risks —
# they survive review cycles and expand silently. This gate makes them
# merge-blocking instead of audit-findings.

package iam.guard

# Rule 1 — no wildcard actions, ever.
deny contains msg if {
	some rp in input.role_permissions
	some action in rp.actions
	action == "*"
	msg := sprintf("wildcard action granted to role '%s'", [rp.role])
}

# Rule 2 — no unbounded resource scopes.
deny contains msg if {
	some rp in input.role_permissions
	some resource in rp.resources
	resource == "*"
	msg := sprintf("wildcard resource bound to role '%s'", [rp.role])
}

# Rule 3 — identity policies belong in version control, not bolted onto principals.
deny contains msg if {
	some ip in input.inline_policies
	ip.attached == true
	msg := sprintf("inline IAM policy attached to principal '%s'", [ip.principal])
}

# Rule 0 (fail-closed) — absent evidence is never a clean verdict.
# NOTE: plain `not input.<section>` — do NOT rewrite as
# `not is_array(input.<section>)`: type builtins return false (not
# undefined) for missing refs, which silently disables the denial.
deny contains msg if {
	not input.role_permissions
	msg := "input missing required section 'role_permissions'"
}

deny contains msg if {
	not input.inline_policies
	msg := "input missing required section 'inline_policies'"
}

# Explicit null is defined (so `not` misses it) but still not a section.
deny contains msg if {
	input.role_permissions == null
	msg := "input section 'role_permissions' is null"
}

deny contains msg if {
	input.inline_policies == null
	msg := "input section 'inline_policies' is null"
}
