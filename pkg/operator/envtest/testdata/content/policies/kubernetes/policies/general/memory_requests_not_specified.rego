# METADATA
# title: "Memory requests not specified"
# description: "When containers have memory requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubesec.io/basics/containers-resources-limits-memory/
# custom:
#   id: KSV016
#   avd_id: AVD-KSV-0016
#   severity: LOW
#   short_code: no-unspecified-memory-requests
#   recommended_action: "Set 'containers[].resources.requests.memory'."
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
package builtin.kubernetes.KSV016

import data.lib.kubernetes
import data.lib.utils

default failRequestsMemory = false

# getRequestsMemoryContainers returns all containers which have set resources.requests.memory
getRequestsMemoryContainers[container] {
	container := kubernetes.containers[_]
	utils.has_key(container.resources.requests, "memory")
}

# getNoRequestsMemoryContainers returns all containers which have not set
# resources.requests.memory
getNoRequestsMemoryContainers[container] {
	container := kubernetes.containers[_]
	not getRequestsMemoryContainers[container]
}

deny[res] {
	output := getNoRequestsMemoryContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'resources.requests.memory'", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
