# METADATA
# title: "Ensure that the --audit-log-maxage argument is set to 30 or as appropriate"
# description: "Retain the logs for at least 30 days or as appropriate."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0020
#   avd_id: AVD-KCV-0020
#   severity: LOW
#   short_code: ensure-audit-log-maxage-argument-is-set-to-30-or-as-appropriate
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --audit-log-maxage parameter to 30 or as an appropriate number of days."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0020

import data.lib.kubernetes

check_flag[container] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not kubernetes.command_has_flag(container.command, "--audit-log-maxage")
}

deny[res] {
	output := check_flag[_]
	msg := "Ensure that the --audit-log-maxage argument is set to 30 or as appropriate"
	res := result.new(msg, output)
}
