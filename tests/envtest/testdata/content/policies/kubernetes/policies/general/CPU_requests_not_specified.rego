# METADATA
# title: "CPU requests not specified"
# description: "When containers have resource requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-best-practices-resource-requests-and-limits
# custom:
#   id: KSV015
#   avd_id: AVD-KSV-0015
#   severity: LOW
#   short_code: no-unspecified-cpu-requests
#   recommended_action: "Set 'containers[].resources.requests.cpu'."
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
package builtin.kubernetes.KSV015

import data.lib.kubernetes
import data.lib.utils

default failRequestsCPU = false

# getRequestsCPUContainers returns all containers which have set resources.requests.cpu
getRequestsCPUContainers[container] {
	container := kubernetes.containers[_]
	utils.has_key(container.resources.requests, "cpu")
}

# getNoRequestsCPUContainers returns all containers which have not set
# resources.requests.cpu
getNoRequestsCPUContainers[container] {
	container := kubernetes.containers[_]
	not getRequestsCPUContainers[container]
}

deny[res] {
	output := getNoRequestsCPUContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'resources.requests.cpu'", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
