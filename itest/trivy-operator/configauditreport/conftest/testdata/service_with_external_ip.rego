package kubernetes.configaudit.service_with_external_ip

deny[res] {
	input.kind == "Service"
	count(input.spec.externalIPs) > 0
	res := {
		"msg": "Service with external IP",
		"title": "Service with external IP",
	}
}
