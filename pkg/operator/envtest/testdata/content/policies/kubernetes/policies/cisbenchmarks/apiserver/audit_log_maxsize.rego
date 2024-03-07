# METADATA
# title: "Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate"
# description: "Rotate log files on reaching 100 MB or as appropriate."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0022
#   avd_id: AVD-KCV-0022
#   severity: LOW
#   short_code: ensure-audit-log-maxsize-argument-is-set-to-100-or-as-appropriate
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --audit-log-maxsize parameter to an appropriate size in MB"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0022

import data.lib.kubernetes

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--audit-log-maxsize")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate"
	res := result.new(msg, output)
}
