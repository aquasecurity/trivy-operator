# METADATA
# title: "Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used"
# description: "The SecurityContextDeny admission controller can be used to deny pods which make use of some SecurityContext fields which could allow for privilege escalation in the cluster. This should be used where PodSecurityPolicy is not in place within the cluster."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0013
#   avd_id: AVD-KCV-0013
#   severity: LOW
#   short_code: ensure-admission-control-plugin-security-context-deny-is-set-if-pod-security-policy-is-not-used
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --enable-admission-plugins parameter to include SecurityContextDeny, unless PodSecurityPolicy is already in place."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0013

import data.lib.kubernetes

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	some i
	output := regex.find_all_string_submatch_n(`--enable-admission-plugins=([^\s]+)`, container.command[i], -1)
	not regex.match("PodSecurityPolicy", output[0][1])
	not regex.match("SecurityContextDeny", output[0][1])
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used"
	res := result.new(msg, output)
}
