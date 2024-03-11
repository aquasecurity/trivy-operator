# METADATA
# title: "Do not allow attaching to shell on pods"
# description: "Check whether role permits attaching to shell on pods"
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV054
#   avd_id: AVD-KSV-0054
#   severity: HIGH
#   short_code: no-attaching-shell-pods
#   recommended_action: "Create a role which does not permit attaching to shell on pods"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV054

import data.lib.kubernetes
import data.lib.utils

readKinds := ["Role", "ClusterRole"]

attach_shell_on_pod[ruleA] {
	input.kind == readKinds[_]
	some i, j
	ruleA := input.rules[i]
	ruleB := input.rules[j]
	i < j
	ruleA.apiGroups[_] == "*"
	ruleA.resources[_] == "pods/attach"
	ruleA.verbs[_] == "create"
	ruleB.apiGroups[_] == "*"
	ruleB.resources[_] == "pods"
	ruleB.verbs[_] == "get"
}

deny[res] {
	badRule := attach_shell_on_pod[_]
	msg := "Role permits attaching to shell on pods"
	res := result.new(msg, badRule)
}
