# METADATA
# title: "Container capabilities must only include NET_BIND_SERVICE"
# description: "Containers must drop ALL capabilities, and are only permitted to add back the NET_BIND_SERVICE capability."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted
# custom:
#   id: KSV106
#   avd_id: AVD-KSV-0106
#   severity: LOW
#   short_code: drop-caps-add-bind-svc
#   recommended_action: "Set 'spec.containers[*].securityContext.capabilities.drop' to 'ALL' and only add 'NET_BIND_SERVICE' to 'spec.containers[*].securityContext.capabilities.add'."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV106

import data.lib.kubernetes
import data.lib.utils

hasDropAll(container) {
	upper(container.securityContext.capabilities.drop[_]) == "ALL"
}

containersWithoutDropAll[container] {
	container := kubernetes.containers[_]
	not hasDropAll(container)
}

containersWithDropAll[container] {
	container := kubernetes.containers[_]
	hasDropAll(container)
}

deny[res] {
	container := containersWithoutDropAll[_]
	msg := "container should drop all"
	res := result.new(msg, container)
}

deny[res] {
	container := containersWithDropAll[_]
	add := container.securityContext.capabilities.add[_]
	add != "NET_BIND_SERVICE"
	msg := "container should not add stuff"
	res := result.new(msg, container.securityContext.capabilities)
}
