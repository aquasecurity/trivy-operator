# METADATA
# title: "Runs as root user"
# description: "Force the running image to run as a non-root user to ensure least privileges."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted
# custom:
#   id: KSV012
#   avd_id: AVD-KSV-0012
#   severity: MEDIUM
#   short_code: no-root
#   recommended_action: "Set 'containers[].securityContext.runAsNonRoot' to true."
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
package builtin.kubernetes.KSV012

import data.lib.kubernetes
import data.lib.utils

default checkRunAsNonRoot = false

# getNonRootContainers returns the names of all containers which have
# securityContext.runAsNonRoot set to true.
getNonRootContainers[container] {
	allContainers := kubernetes.containers[_]
	allContainers.securityContext.runAsNonRoot == true
	container := allContainers.name
}

# getRootContainers returns the names of all containers which have
# securityContext.runAsNonRoot set to false or not set.
getRootContainers[container] {
	container := kubernetes.containers[_]
	not getNonRootContainers[container.name]
}

# checkRunAsNonRoot is true if securityContext.runAsNonRoot is set to false
# or if securityContext.runAsNonRoot is not set.
checkRunAsNonRootContainers {
	count(getRootContainers) > 0
}

checkRunAsNonRootPod {
	allPods := kubernetes.pods[_]
	not allPods.spec.securityContext.runAsNonRoot
}

deny[res] {
	checkRunAsNonRootPod
	output := getRootContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'securityContext.runAsNonRoot' to true", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
