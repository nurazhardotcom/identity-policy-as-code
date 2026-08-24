# iam.guard — deny-set policy over a normalized Terraform-plan input.
#
# Input contract (see fixtures/):
#   input.role_permissions[] : { role: string, actions: [string], resources: [string] }
#   input.inline_policies[]  : { principal: string, attached: bool }
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
