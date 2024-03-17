# METADATA
# title: "Default security context configured"
# description: "Security context controls the allocation of security parameters for the pod/container/volume, ensuring the appropriate level of protection. Relying on default security context may expose vulnerabilities to potential attacks that rely on privileged access."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
# custom:
#   id: KSV118
#   avd_id: AVD-KSV-0118
#   severity: HIGH
#   short_code: no-default-security-context
#   recommended_action: "To enhance security, it is strongly recommended not to rely on the default security context. Instead, it is advisable to explicitly define the required security parameters (such as runAsNonRoot, capabilities, readOnlyRootFilesystem, etc.) within the security context."
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
package builtin.kubernetes.KSV118

import data.lib.kubernetes

default failCapsDefaultSecurityContext = false

#failDefaultSecurityContext is true if spec.containers.securityContext is set to the default security context
failDefaultSecurityContext {
	containers := kubernetes.containers[_]
	containers.securityContext == {}
}

# failPodDefaultSecurityContext is true if spec.securityContext is set to the default security context
failPodDefaultSecurityContext {
	pod := kubernetes.pods[_]
	pod.spec.securityContext == {}
}

deny[res] {
	output := failPodDefaultSecurityContext
	msg := kubernetes.format(sprintf("%s %s in %s namespace is using the default security context, which allows root privileges", [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, output)
}

deny[res] {
	output := failDefaultSecurityContext
	msg := kubernetes.format(sprintf("container %s in %s namespace is using the default security context", [kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, output)
}
