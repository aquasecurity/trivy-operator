# METADATA
# title: "Root file system is not read-only"
# description: "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubesec.io/basics/containers-securitycontext-readonlyrootfilesystem-true/
# custom:
#   id: KSV014
#   avd_id: AVD-KSV-0014
#   severity: HIGH
#   short_code: use-readonly-filesystem
#   recommended_action: "Change 'containers[].securityContext.readOnlyRootFilesystem' to 'true'."
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
package builtin.kubernetes.KSV014

import data.lib.kubernetes

default failReadOnlyRootFilesystem = false

# getReadOnlyRootFilesystemContainers returns all containers that have
# securityContext.readOnlyFilesystem set to true.
getReadOnlyRootFilesystemContainers[container] {
	container := kubernetes.containers[_]
	container.securityContext.readOnlyRootFilesystem == true
}

# getNotReadOnlyRootFilesystemContainers returns all containers that have
# securityContext.readOnlyRootFilesystem set to false or not set at all.
getNotReadOnlyRootFilesystemContainers[container] {
	container := kubernetes.containers[_]
	not getReadOnlyRootFilesystemContainers[container]
}

deny[res] {
	output := getNotReadOnlyRootFilesystemContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'securityContext.readOnlyRootFilesystem' to true", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
