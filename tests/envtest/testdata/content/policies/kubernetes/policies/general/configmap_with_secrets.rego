# METADATA
# title: "ConfigMap with secrets"
# description: "Storing secrets in configMaps is unsafe."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# custom:
#   id: KSV109
#   avd_id: AVD-KSV-0109
#   severity: HIGH
#   short_code: no-secrets-in-configmap
#   recommended_action: "Remove password/secret from configMap data value."
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: configmap
package builtin.kubernetes.KSV109

import data.lib.kubernetes

# configMapSecretKeys returns ConfigMap data keys whose value looks like a
# secret assignment, e.g. "password=SuperSecret123".
configMapSecretKeys[key] {
	kubernetes.kind == "ConfigMap"
	value := kubernetes.object.data[key]
	is_string(value)
	regex.match("(?i)(password|passwd|secret|token)\\s*(=|:)", value)
}

# configMapSecretKeys also returns ConfigMap data keys that are themselves named
# after a secret, e.g. "password: SuperSecret123".
configMapSecretKeys[key] {
	kubernetes.kind == "ConfigMap"
	kubernetes.object.data[key]
	regex.match("(?i)^(password|passwd|secret|token)$", key)
}

deny[res] {
	count(configMapSecretKeys) > 0

	msg := kubernetes.format(sprintf("%s '%s' in '%s' namespace stores secrets in key(s) %v", [kubernetes.kind, kubernetes.name, kubernetes.namespace, configMapSecretKeys]))

	res := {"msg": msg}
}
