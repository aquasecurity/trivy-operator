package kubernetes.configaudit.run_as_root

deny[res] {
	input.kind == "ReplicaSet"
	not input.spec.template.spec.securityContext.runAsNonRoot

	res := {
		"msg": "Containers must not run as root",
		"title": "Run as root",
	}
}

deny[res] {
	input.kind == "Pod"
	not input.spec.securityContext.runAsNonRoot

	res := {
		"msg": "Containers must not run as root",
		"title": "Run as root",
	}
}

deny[res] {
	input.kind == "CronJob"
	not input.spec.jobTemplate.spec.template.spec.securityContext.runAsNonRoot

	res := {
		"msg": "Containers must not run as root",
		"title": "Run as root",
	}
}
