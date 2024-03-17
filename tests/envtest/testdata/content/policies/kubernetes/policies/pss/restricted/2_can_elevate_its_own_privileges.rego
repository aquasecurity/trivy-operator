# METADATA
# title: "Can elevate its own privileges"
# description: "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted
# custom:
#   id: KSV001
#   avd_id: AVD-KSV-0001
#   severity: MEDIUM
#   short_code: no-self-privesc
#   recommended_action: "Set 'set containers[].securityContext.allowPrivilegeEscalation' to 'false'."
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: pod
#         - kind: replicaset
#         - kind: replicationcontroller
#         - kind: deployment
#         - kind: statefulset
#         - kind: daemonset
#         - kind: cronjob
#         - kind: job
package builtin.kubernetes.KSV001

import data.lib.kubernetes
import data.lib.utils

default checkAllowPrivilegeEscalation = false

# getNoPrivilegeEscalationContainers returns the names of all containers which have
# securityContext.allowPrivilegeEscalation set to false.
getNoPrivilegeEscalationContainers[container] {
	allContainers := kubernetes.containers[_]
	allContainers.securityContext.allowPrivilegeEscalation == false
	container := allContainers.name
}

# getPrivilegeEscalationContainers returns the names of all containers which have
# securityContext.allowPrivilegeEscalation set to true or not set.
getPrivilegeEscalationContainers[container] {
	container := kubernetes.containers[_]
	not getNoPrivilegeEscalationContainers[container.name]
}

deny[res] {
	output := getPrivilegeEscalationContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'securityContext.allowPrivilegeEscalation' to false", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
