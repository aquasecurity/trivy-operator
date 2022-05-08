package trivyoperator

const (
	Banner = `Trivy-Operator is an Aqua Security open source project.
Learn about our open source work and portfolio on https://www.aquasec.com/products/open-source-projects/.
`
)

const (
	// NamespaceName the name of the namespace in which Trivy-operator stores its
	// configuration and where it runs scan jobs.
	NamespaceName = "trivy-operator"

	// ServiceAccountName the name of the service account used to provide
	// identity for scan jobs run by Trivy-operator.
	ServiceAccountName = "trivy-operator"

	// ConfigMapName the name of the ConfigMap where Trivy-operator stores its
	// configuration.
	ConfigMapName = "trivy-operator"

	// SecretName the name of the secret where Trivy-operator stores is sensitive
	// configuration.
	SecretName = "trivy-operator"

	// PoliciesConfigMapName the name of the ConfigMap used to store OPA Rego
	// policies.
	PoliciesConfigMapName = "trivy-operator-policies-config"
)

const (
	LabelResourceKind      = "trivy-operator.resource.kind"
	LabelResourceName      = "trivy-operator.resource.name"
	LabelResourceNameHash  = "trivy-operator.resource.name-hash"
	LabelResourceNamespace = "trivy-operator.resource.namespace"
	LabelContainerName     = "trivy-operator.container.name"
	LabelResourceSpecHash  = "resource-spec-hash"
	LabelPluginConfigHash  = "plugin-config-hash"

	LabelConfigAuditReportScanner   = "configAuditReport.scanner"
	LabelVulnerabilityReportScanner = "vulnerabilityReport.scanner"
	LabelKubeBenchReportScanner     = "kubeBenchReport.scanner"

	LabelK8SAppManagedBy = "app.kubernetes.io/managed-by"
	AppTrivyOperator     = "trivy-operator"
)

const (
	AnnotationContainerImages = "trivy-operator.container-images"
)
