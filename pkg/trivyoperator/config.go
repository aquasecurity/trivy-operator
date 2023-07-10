package trivyoperator

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	containerimage "github.com/google/go-containerregistry/pkg/name"
	ocpappsv1 "github.com/openshift/api/apps/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
)

func NewScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = batchv1beta1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = networkingv1.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	_ = coordinationv1.AddToScheme(scheme)
	_ = apiextensionsv1.AddToScheme(scheme)
	_ = ocpappsv1.Install(scheme)
	return scheme
}

// BuildInfo holds build info such as Git revision, Git SHA-1, build datetime,
// and the name of the executable binary.
type BuildInfo struct {
	Version    string
	Commit     string
	Date       string
	Executable string
}

// Scanner represents unique, human-readable identifier of a security scanner.
type Scanner string

const (
	KeyVulnerabilityScannerEnabled       = "vulnerabilityScannerEnabled"
	KeyExposedSecretsScannerEnabled      = "exposedSecretsScannerEnabled"
	KeyGenerateSbom                      = "generateSbomEnabled"
	keyVulnerabilityReportsScanner       = "vulnerabilityReports.scanner"
	KeyVulnerabilityScansInSameNamespace = "vulnerabilityReports.scanJobsInSameNamespace"
	keyConfigAuditReportsScanner         = "configAuditReports.scanner"
	keyScanJobTolerations                = "scanJob.tolerations"
	KeyScanJobcompressLogs               = "scanJob.compressLogs"
	KeyNodeCollectorVolumes              = "nodeCollector.volumes"
	KeyNodeCollectorExcludeNodes         = "nodeCollector.excludeNodes"
	KeyNodeCollectorVolumeMounts         = "nodeCollector.volumeMounts"
	keyScanJobNodeSelector               = "scanJob.nodeSelector"
	keyScanJobAnnotations                = "scanJob.annotations"
	//nolint
	keyscanJobAutomountServiceAccountToken = "scanJob.automountServiceAccountToken"
	KeyScanJobContainerSecurityContext     = "scanJob.podTemplateContainerSecurityContext"
	keyScanJobPodSecurityContext           = "scanJob.podTemplatePodSecurityContext"
	keyScanJobPodTemplateLabels            = "scanJob.podTemplateLabels"
	KeyScanJobPodPriorityClassName         = "scanJob.podPriorityClassName"
	keyComplianceFailEntriesLimit          = "compliance.failEntriesLimit"
	keySkipResourceByLabels                = "skipResourceByLabels"
	KeyReportResourceLabels                = "report.resourceLabels"
	KeyReportRecordFailedChecksOnly        = "report.recordFailedChecksOnly"
	KeyMetricsResourceLabelsPrefix         = "metrics.resourceLabelsPrefix"
	KeyTrivyServerURL                      = "trivy.serverURL"
	KeyNodeCollectorImageRef               = "node.collector.imageRef"
	KeyNodeCollectorImagePullSecret        = "node.collector.imagePullSecret"
	KeyAdditionalReportLabels              = "report.additionalLabels"
)

// ConfigData holds Trivy-operator configuration settings as a set of key-value
// pairs.
type ConfigData map[string]string

// ConfigManager defines methods for managing ConfigData.
type ConfigManager interface {
	EnsureDefault(ctx context.Context) error
	Read(ctx context.Context) (ConfigData, error)
	Delete(ctx context.Context) error
}

// GetDefaultConfig returns the default configuration settings.
func GetDefaultConfig() ConfigData {
	return map[string]string{
		keyVulnerabilityReportsScanner:  "Trivy",
		keyConfigAuditReportsScanner:    "Trivy",
		KeyScanJobcompressLogs:          "true",
		keyComplianceFailEntriesLimit:   "10",
		KeyReportRecordFailedChecksOnly: "true",
		KeyNodeCollectorImageRef:        "ghcr.io/aquasecurity/node-collector:0.0.6",
	}
}

// Set sets a key on config data
func (c ConfigData) Set(key, value string) {
	c[key] = value
}

// CompressLogs returns if scan job output should be compressed
func (c ConfigData) CompressLogs() bool {
	return c.getBoolKey(KeyScanJobcompressLogs)
}

// VulnerabilityScannerEnabled returns if the vulnerability scanners is enabled/disablsed
func (c ConfigData) VulnerabilityScannerEnabled() bool {
	return c.getBoolKey(KeyVulnerabilityScannerEnabled)
}

// ExposedSecretsScannerEnabled returns if the vulnerability scanners is enabled/disablsed
func (c ConfigData) ExposedSecretsScannerEnabled() bool {
	return c.getBoolKey(KeyExposedSecretsScannerEnabled)
}

// GenerateSbomEnabled returns if the sbom generation is enabled
func (c ConfigData) GenerateSbomEnabled() bool {
	return c.getBoolKey(KeyGenerateSbom)
}

func (c ConfigData) getBoolKey(key string) bool {
	var ok bool
	var value string
	if value, ok = c[key]; !ok {
		return false
	}
	return value == "true"
}

func (c ConfigData) GetVulnerabilityReportsScanner() (Scanner, error) {
	var ok bool
	var value string
	if value, ok = c[keyVulnerabilityReportsScanner]; !ok {
		return "", fmt.Errorf("property %s not set", keyVulnerabilityReportsScanner)
	}
	return Scanner(value), nil
}

func (c ConfigData) VulnerabilityScanJobsInSameNamespace() bool {
	return c.getBoolKey(KeyVulnerabilityScansInSameNamespace)
}

func (c ConfigData) GetConfigAuditReportsScanner() (Scanner, error) {
	var ok bool
	var value string
	if value, ok = c[keyConfigAuditReportsScanner]; !ok {
		return "", fmt.Errorf("property %s not set", keyConfigAuditReportsScanner)
	}
	return Scanner(value), nil
}

func (c ConfigData) GetScanJobTolerations() ([]corev1.Toleration, error) {
	var scanJobTolerations []corev1.Toleration
	if c[keyScanJobTolerations] == "" {
		return scanJobTolerations, nil
	}
	err := json.Unmarshal([]byte(c[keyScanJobTolerations]), &scanJobTolerations)

	return scanJobTolerations, err
}

func (c ConfigData) GetNodeCollectorImagePullsecret() []corev1.LocalObjectReference {
	imagePullSecrets := make([]corev1.LocalObjectReference, 0)
	imagePullSecretValue := c[KeyNodeCollectorImagePullSecret]
	if c[KeyNodeCollectorImagePullSecret] != "" {
		imagePullSecrets = append(imagePullSecrets, corev1.LocalObjectReference{Name: imagePullSecretValue})
	}
	return imagePullSecrets
}

func (c ConfigData) GetNodeCollectorVolumes() ([]corev1.Volume, error) {
	var volumes []corev1.Volume
	if c[KeyNodeCollectorVolumes] == "" {
		return volumes, nil
	}
	err := json.Unmarshal([]byte(c[KeyNodeCollectorVolumes]), &volumes)
	return volumes, err
}
func (c ConfigData) GetGetNodeCollectorVolumeMounts() ([]corev1.VolumeMount, error) {
	var volumesMount []corev1.VolumeMount
	if c[KeyNodeCollectorVolumeMounts] == "" {
		return volumesMount, nil
	}
	err := json.Unmarshal([]byte(c[KeyNodeCollectorVolumeMounts]), &volumesMount)
	return volumesMount, err
}

func (c ConfigData) GetScanJobNodeSelector() (map[string]string, error) {
	scanJobNodeSelector := make(map[string]string, 0)
	if c[keyScanJobNodeSelector] == "" {
		return scanJobNodeSelector, nil
	}

	if err := json.Unmarshal([]byte(c[keyScanJobNodeSelector]), &scanJobNodeSelector); err != nil {
		return scanJobNodeSelector, fmt.Errorf("failed to parse incorrect job template nodeSelector %s: %w", c[keyScanJobNodeSelector], err)
	}

	return scanJobNodeSelector, nil
}

func (c ConfigData) GetScanJobPodSecurityContext() (*corev1.PodSecurityContext, error) {
	if c[keyScanJobPodSecurityContext] == "" {
		return nil, nil
	}

	scanJobPodSecurityContext := &corev1.PodSecurityContext{}
	err := json.Unmarshal([]byte(c[keyScanJobPodSecurityContext]), scanJobPodSecurityContext)
	if err != nil {
		return nil, fmt.Errorf("failed parsing incorrectly formatted custom scan pod template securityContext: %s", c[keyScanJobPodSecurityContext])
	}

	return scanJobPodSecurityContext, nil
}

func (c ConfigData) GetScanJobContainerSecurityContext() (*corev1.SecurityContext, error) {
	if c[KeyScanJobContainerSecurityContext] == "" {
		return nil, nil
	}

	scanJobContainerSecurityContext := &corev1.SecurityContext{}
	err := json.Unmarshal([]byte(c[KeyScanJobContainerSecurityContext]), scanJobContainerSecurityContext)
	if err != nil {
		return nil, fmt.Errorf("failed parsing incorrectly formatted custom scan container template securityContext: %s", c[KeyScanJobContainerSecurityContext])
	}

	return scanJobContainerSecurityContext, nil
}

func (c ConfigData) GetScanJobAutomountServiceAccountToken() bool {
	return c.getBoolKey(keyscanJobAutomountServiceAccountToken)
}

func (c ConfigData) GetScanJobAnnotations() (map[string]string, error) {
	scanJobAnnotationsStr, found := c[keyScanJobAnnotations]
	if !found || strings.TrimSpace(scanJobAnnotationsStr) == "" {
		return map[string]string{}, nil
	}

	scanJobAnnotationsMap := map[string]string{}
	for _, annotation := range strings.Split(scanJobAnnotationsStr, ",") {
		sepByEqual := strings.Split(annotation, "=")
		if len(sepByEqual) != 2 {
			return map[string]string{}, fmt.Errorf("failed parsing incorrectly formatted custom scan job annotations: %s", scanJobAnnotationsStr)
		}
		key, value := sepByEqual[0], sepByEqual[1]
		scanJobAnnotationsMap[key] = value
	}

	return scanJobAnnotationsMap, nil
}

func (c ConfigData) GetNodeCollectorExcludeNodes() (map[string]string, error) {
	nodeCollectorExcludeNodesStr, found := c[KeyNodeCollectorExcludeNodes]
	if !found || strings.TrimSpace(nodeCollectorExcludeNodesStr) == "" {
		return map[string]string{}, nil
	}

	nodeCollectorExcludeNodesMap := map[string]string{}
	for _, excludeNode := range strings.Split(nodeCollectorExcludeNodesStr, ",") {
		sepByEqual := strings.Split(excludeNode, "=")
		if len(sepByEqual) != 2 {
			return map[string]string{}, fmt.Errorf("failed parsing incorrectly formatted exclude nodes values: %s", nodeCollectorExcludeNodesStr)
		}
		key, value := sepByEqual[0], sepByEqual[1]
		nodeCollectorExcludeNodesMap[key] = value
	}
	return nodeCollectorExcludeNodesMap, nil
}

func (c ConfigData) GetScanJobPodTemplateLabels() (labels.Set, error) {
	scanJobPodTemplateLabelsStr, found := c[keyScanJobPodTemplateLabels]
	if !found || strings.TrimSpace(scanJobPodTemplateLabelsStr) == "" {
		return labels.Set{}, nil
	}

	scanJobPodTemplateLabelsMap := map[string]string{}
	labelParts := strings.Split(strings.TrimSuffix(scanJobPodTemplateLabelsStr, ","), ",")
	for _, annotation := range labelParts {
		sepByEqual := strings.Split(annotation, "=")
		if len(sepByEqual) != 2 {
			return labels.Set{}, fmt.Errorf("failed parsing incorrectly formatted custom scan pod template labels: %s", scanJobPodTemplateLabelsStr)
		}
		key, value := sepByEqual[0], sepByEqual[1]
		scanJobPodTemplateLabelsMap[key] = value
	}

	return scanJobPodTemplateLabelsMap, nil
}

func (c ConfigData) GetScanJobPodPriorityClassName() (string, error) {
	priorityClassName, found := c[KeyScanJobPodPriorityClassName]

	if !found || priorityClassName == "" {
		return "", nil
	}
	return priorityClassName, nil
}

func (c ConfigData) GetAdditionalReportLabels() (labels.Set, error) {
	additionalReportLabelsStr, found := c[KeyAdditionalReportLabels]
	if !found || strings.TrimSpace(additionalReportLabelsStr) == "" {
		return labels.Set{}, nil
	}

	additionalReportLabelsMap := map[string]string{}
	for _, annotation := range strings.Split(additionalReportLabelsStr, ",") {
		sepByEqual := strings.Split(annotation, "=")
		if len(sepByEqual) != 2 {
			return labels.Set{}, fmt.Errorf("failed parsing incorrectly formatted custom report labels: %s", additionalReportLabelsStr)
		}
		key, value := sepByEqual[0], sepByEqual[1]
		additionalReportLabelsMap[key] = value
	}

	return additionalReportLabelsMap, nil
}

func (c ConfigData) GetReportResourceLabels() []string {
	resourceLabelsStr, found := c[KeyReportResourceLabels]
	if !found || strings.TrimSpace(resourceLabelsStr) == "" {
		return []string{}
	}

	return strings.Split(resourceLabelsStr, ",")
}

func (c ConfigData) GetSkipResourceByLabels() []string {
	scanSkipResourceLabels, found := c[keySkipResourceByLabels]
	if !found || strings.TrimSpace(scanSkipResourceLabels) == "" {
		return []string{}
	}

	return strings.Split(scanSkipResourceLabels, ",")
}

func (c ConfigData) GetMetricsResourceLabelsPrefix() string {
	return c[KeyMetricsResourceLabelsPrefix]
}

func (c ConfigData) ReportRecordFailedChecksOnly() bool {
	return c.getBoolKey(KeyReportRecordFailedChecksOnly)
}

func (c ConfigData) NodeCollectorImageRef() string {
	return c[KeyNodeCollectorImageRef]
}

func (c ConfigData) GeTrivyServerURL() string {
	return c[KeyTrivyServerURL]
}
func (c ConfigData) GetRequiredData(key string) (string, error) {
	var ok bool
	var value string
	if value, ok = c[key]; !ok {
		return "", fmt.Errorf("property %s not set", key)
	}
	return value, nil
}

// GetVersionFromImageRef returns the image identifier for the specified image
// reference.
func GetVersionFromImageRef(imageRef string) (string, error) {
	ref, err := containerimage.ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("parsing reference: %w", err)
	}

	var version string
	switch t := ref.(type) {
	case containerimage.Tag:
		version = t.TagStr()
	case containerimage.Digest:
		version = t.DigestStr()
	}

	return version, nil
}

func (c ConfigData) ComplianceFailEntriesLimit() int {
	const defaultValue = 10
	var value string
	var ok bool
	if value, ok = c[keyComplianceFailEntriesLimit]; !ok {
		return defaultValue
	}
	intVal, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return intVal
}

// NewConfigManager constructs a new ConfigManager that is using kubernetes.Interface
// to manage ConfigData backed by the ConfigMap stored in the specified namespace.
func NewConfigManager(client kubernetes.Interface, namespace string) ConfigManager {
	return &configManager{
		client:    client,
		namespace: namespace,
	}
}

type configManager struct {
	client    kubernetes.Interface
	namespace string
}

func (c *configManager) EnsureDefault(ctx context.Context) error {
	_, err := c.client.CoreV1().ConfigMaps(c.namespace).Get(ctx, ConfigMapName, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed getting configmap: %s: %w", ConfigMapName, err)
		}
		_, err = c.client.CoreV1().ConfigMaps(c.namespace).Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: c.namespace,
				Name:      ConfigMapName,
				Labels: labels.Set{
					LabelK8SAppManagedBy: "trivy-operator",
				},
			},
			Data: GetDefaultConfig(),
		}, metav1.CreateOptions{})

		if err != nil {
			return fmt.Errorf("failed creating configmap: %s: %w", ConfigMapName, err)
		}
	}

	_, err = c.client.CoreV1().ConfigMaps(c.namespace).Get(ctx, PoliciesConfigMapName, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed getting configmap: %s: %w", PoliciesConfigMapName, err)
		}
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: c.namespace,
			Name:      SecretName,
			Labels: labels.Set{
				LabelK8SAppManagedBy: "trivy-operator",
			},
		},
	}
	_, err = c.client.CoreV1().Secrets(c.namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	return nil
}

func (c *configManager) Read(ctx context.Context) (ConfigData, error) {
	cm, err := c.client.CoreV1().ConfigMaps(c.namespace).Get(ctx, ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	secret, err := c.client.CoreV1().Secrets(c.namespace).Get(ctx, SecretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	var data = make(map[string]string)

	for k, v := range cm.Data {
		data[k] = v
	}

	for k, v := range secret.Data {
		data[k] = string(v)
	}

	return data, nil
}

func (c *configManager) Delete(ctx context.Context) error {
	err := c.client.CoreV1().ConfigMaps(c.namespace).Delete(ctx, ConfigMapName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	err = c.client.CoreV1().ConfigMaps(c.namespace).Delete(ctx, GetPluginConfigMapName("Trivy"), metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	err = c.client.CoreV1().Secrets(c.namespace).Delete(ctx, SecretName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

// LinuxNodeAffinity constructs a new Affinity resource with linux supported nodes.
func LinuxNodeAffinity() *corev1.Affinity {
	return &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{
								Key:      "kubernetes.io/os",
								Operator: corev1.NodeSelectorOpIn,
								Values:   []string{"linux"},
							},
						},
					},
				}}}}
}
