# METADATA
# title: "Runs with GID <= 10000"
# description: "Force the container to run with group ID > 10000 to avoid conflicts with the host’s user table."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubesec.io/basics/containers-securitycontext-runasuser/
# custom:
#   id: KSV021
#   avd_id: AVD-KSV-0021
#   severity: LOW
#   short_code: use-high-gid
#   recommended_action: "Set 'containers[].securityContext.runAsGroup' to an integer > 10000."
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
package builtin.kubernetes.KSV021

import data.lib.kubernetes
import data.lib.utils

default failRunAsGroup = false

# getGroupIdContainers returns the names of all containers which have
# securityContext.runAsGroup less than or equal to 10000.
getGroupIdContainers[container] {
	container := kubernetes.containers[_]
	container.securityContext.runAsGroup <= 10000
}

# getGroupIdContainers returns the names of all containers which do
# not have securityContext.runAsGroup set.
getGroupIdContainers[container] {
	container := kubernetes.containers[_]
	not utils.has_key(container.securityContext, "runAsGroup")
}

# getGroupIdContainers returns the names of all containers which do
# not have securityContext set.
getGroupIdContainers[container] {
	container := kubernetes.containers[_]
	not utils.has_key(container, "securityContext")
}

deny[res] {
	output := getGroupIdContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'securityContext.runAsGroup' > 10000", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
