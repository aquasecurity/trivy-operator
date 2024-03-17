# METADATA
# title: "Manage namespace secrets"
# description: "Viewing secrets at the namespace scope can lead to escalation if another service account in that namespace has a higher privileged rolebinding or clusterrolebinding bound."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV113
#   avd_id: AVD-KSV-0113
#   severity: Medium
#   short_code: no-manage-ns-secrets
#   recommended_actions: "Manage namespace secrets are not allowed. Remove resource 'secrets' from role"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: role
package builtin.kubernetes.KSV113

import data.lib.kubernetes
import data.lib.utils

readVerbs := ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["Role"]

resourceManageSecret[input.rules[ru]] {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == "secrets"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny[res] {
	badRule := resourceManageSecret[_]
	msg := kubernetes.format(sprintf("%s '%s' shouldn't have access to manage secrets in namespace '%s'", [kubernetes.kind, kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, badRule)
}
