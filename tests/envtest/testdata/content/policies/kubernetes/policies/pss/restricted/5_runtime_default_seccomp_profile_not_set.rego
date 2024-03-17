# METADATA
# title: "Runtime/Default Seccomp profile not set"
# description: "According to pod security standard 'Seccomp', the RuntimeDefault seccomp profile must be required, or allow specific additional profiles."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted
# custom:
#   id: KSV030
#   avd_id: AVD-KSV-0030
#   severity: LOW
#   short_code: use-default-seccomp
#   recommended_action: "Set 'spec.securityContext.seccompProfile.type', 'spec.containers[*].securityContext.seccompProfile' and 'spec.initContainers[*].securityContext.seccompProfile' to 'RuntimeDefault' or undefined."
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
package builtin.kubernetes.KSV030

import data.lib.kubernetes
import data.lib.utils

getType(target) = type {
	context := getOr(target, "securityContext", {})
	profile := getOr(context, "seccompProfile", {})
	type := getOr(profile, "type", "")
}

isValidProfileType(target) {
	getType(target) == "RuntimeDefault"
}

isValidProfileType(target) {
	getType(target) == "Localhost"
}

isUndefinedProfileType(target) {
	not isDefinedProfileType(target)
}

getOr(obj, key, def) = res {
	res := obj[key]
}

getOr(obj, key, def) = res {
	not obj[key]
	res := def
}

isDefinedProfileType(target) {
	getType(target) != ""
}

getAnnotations[type] {
	annotation := kubernetes.annotations[_]
	type := annotation["seccomp.security.alpha.kubernetes.io/pod"]
}

hasAnnotations {
	count(getAnnotations) > 0
}

failSeccompAnnotation[annotation] {
	annotation := kubernetes.annotations[_]
	val := annotation["seccomp.security.alpha.kubernetes.io/pod"]
	val != "runtime/default"
}

# annotations (Kubernetes pre-v1.19)
deny[res] {
	cause := failSeccompAnnotation[_]
	msg := "seccomp.security.alpha.kubernetes.io/pod should be set to 'runtime/default'"
	res := result.new(msg, cause)
}

# (Kubernetes post-v1.19)

isDefinedOnPod {
	count(definedPods) > 0
}

definedPods[pod] {
	pod := kubernetes.pods[_]
	not isUndefinedProfileType(pod.spec)
}

# deny if container-level is undefined and pod-level is undefined
deny[res] {
	not hasAnnotations
	not isDefinedOnPod
	container := kubernetes.containers[_]
	isUndefinedProfileType(container)
	msg := "Either Pod or Container should set 'securityContext.seccompProfile.type' to 'RuntimeDefault'"
	res := result.new(msg, container)
}

# deny if container-level is bad
deny[res] {
	container := kubernetes.containers[_]
	not isUndefinedProfileType(container)
	not isValidProfileType(container)
	msg := "Container should set 'securityContext.seccompProfile.type' to 'RuntimeDefault'"
	res := result.new(msg, container)
}

# deny if pod-level is bad
deny[res] {
	pod := kubernetes.pods[_]
	not isUndefinedProfileType(pod.spec)
	not isValidProfileType(pod.spec)
	msg := "Pod should set 'securityContext.seccompProfile.type' to 'RuntimeDefault'"
	res := result.new(msg, pod.spec)
}
