# METADATA
# title: "Ensure that the admission control plugin EventRateLimit is set"
# description: "Limit the rate at which the API server accepts requests."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0010
#   avd_id: AVD-KCV-0010
#   severity: LOW
#   short_code: ensure-admission-control-plugin-event-rate-limit-is-set
#   recommended_action: "Follow the Kubernetes documentation and set the desired limits in a configuration file. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml and set the below parameters."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0010

import data.lib.kubernetes

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--enable-admission-plugins")
}

check_flag[container] {
	container := kubernetes.containers[_]
	some i
	output := regex.find_all_string_submatch_n(`--enable-admission-plugins=([^\s]+)`, container.command[i], -1)
	not regex.match("EventRateLimit", output[0][1])
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the admission control plugin EventRateLimit is set"
	res := result.new(msg, output)
}
