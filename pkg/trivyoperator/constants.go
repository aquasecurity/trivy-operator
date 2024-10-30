package trivyoperator

const (
	// NamespaceName the name of the namespace in which Trivy-operator stores its
	// configuration and where it runs scan jobs.
	NamespaceName = "trivy-operator"

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
	LabelResourceKind      = "annotation.trivy-operator.resource.kind"
	LabelResourceName      = "annotation.trivy-operator.resource.name"
	LabelResourceNameHash  = "annotation.trivy-operator.resource.name-hash"
	LabelResourceNamespace = "annotation.trivy-operator.resource.namespace"
	LabelContainerName     = "annotation.trivy-operator.container.name"
	LabelResourceSpecHash  = "annotation.resource-spec-hash"
	LabelPluginConfigHash  = "plugin-config-hash"
	LabelResourceImageID   = "resource-image-id"
	LabelReusedReport      = "reused-report"
	LabelCoreComponent     = "component"
	LabelAddon             = "k8s-app"

	LabelVulnerabilityReportScanner = "vulnerabilityReport.scanner"
	LabelNodeInfoCollector          = "node-info.collector"

	LabelK8SAppManagedBy = "app.kubernetes.io/managed-by"
	AppTrivyOperator     = "trivy-operator"

	// openshift core component
	LabelOpenShiftAPIServer         = "apiserver"
	LabelOpenShiftControllerManager = "kube-controller-manager"
	LabelOpenShiftScheduler         = "scheduler"
	LabelOpenShiftEtcd              = "etcd"
	LabelKbom                       = "trivy-operator.aquasecurity.github.io/sbom-type"
)

const (
	AnnotationContainerImages = "trivy-operator.container-images"
)
