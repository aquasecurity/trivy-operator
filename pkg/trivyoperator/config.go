package trivyoperator

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	embedded "github.com/aquasecurity/trivy-operator"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/google/go-containerregistry/pkg/name"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
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
	_ = policyv1beta1.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	_ = coordinationv1.AddToScheme(scheme)
	_ = apiextensionsv1.AddToScheme(scheme)
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
	keyVulnerabilityReportsScanner       = "vulnerabilityReports.scanner"
	KeyVulnerabilityScansInSameNamespace = "vulnerabilityReports.scanJobsInSameNamespace"
	keyConfigAuditReportsScanner         = "configAuditReports.scanner"
	keyKubeBenchImageRef                 = "kube-bench.imageRef"
	keyKubeHunterImageRef                = "kube-hunter.imageRef"
	keyKubeHunterQuick                   = "kube-hunter.quick"
	keyScanJobTolerations                = "scanJob.tolerations"
	keyScanJobAnnotations                = "scanJob.annotations"
	keyScanJobPodTemplateLabels          = "scanJob.podTemplateLabels"
	keyComplianceFailEntriesLimit        = "compliance.failEntriesLimit"
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
		keyVulnerabilityReportsScanner: "Trivy",
		keyConfigAuditReportsScanner:   "Polaris",

		"kube-bench.imageRef":         "docker.io/aquasec/kube-bench:v0.6.6",
		"kube-hunter.imageRef":        "docker.io/aquasec/kube-hunter:0.6.5",
		"kube-hunter.quick":           "false",
		"compliance.failEntriesLimit": "10",
	}
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
	var ok bool
	var value string
	if value, ok = c[KeyVulnerabilityScansInSameNamespace]; !ok {
		return false
	}
	return value == "true"
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

func (c ConfigData) GetScanJobPodTemplateLabels() (labels.Set, error) {
	scanJobPodTemplateLabelsStr, found := c[keyScanJobPodTemplateLabels]
	if !found || strings.TrimSpace(scanJobPodTemplateLabelsStr) == "" {
		return labels.Set{}, nil
	}

	scanJobPodTemplateLabelsMap := map[string]string{}
	for _, annotation := range strings.Split(scanJobPodTemplateLabelsStr, ",") {
		sepByEqual := strings.Split(annotation, "=")
		if len(sepByEqual) != 2 {
			return labels.Set{}, fmt.Errorf("failed parsing incorrectly formatted custom scan pod template labels: %s", scanJobPodTemplateLabelsStr)
		}
		key, value := sepByEqual[0], sepByEqual[1]
		scanJobPodTemplateLabelsMap[key] = value
	}

	return scanJobPodTemplateLabelsMap, nil
}

func (c ConfigData) GetKubeBenchImageRef() (string, error) {
	return c.GetRequiredData(keyKubeBenchImageRef)
}

func (c ConfigData) GetKubeHunterImageRef() (string, error) {
	return c.GetRequiredData(keyKubeHunterImageRef)
}

func (c ConfigData) GetKubeHunterQuick() (bool, error) {
	val, ok := c[keyKubeHunterQuick]
	if !ok {
		return false, nil
	}
	if val != "false" && val != "true" {
		return false, fmt.Errorf("property kube-hunter.quick must be either \"false\" or \"true\", got %q", val)
	}
	return val == "true", nil
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
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("parsing reference: %w", err)
	}

	var version string
	switch t := ref.(type) {
	case name.Tag:
		version = t.TagStr()
	case name.Digest:
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
		policyCM, err := embedded.PoliciesConfigMap()
		if err != nil {
			return fmt.Errorf("failed getting embedded policies: %w", err)
		}
		policyCM.Namespace = c.namespace
		_, err = c.client.CoreV1().ConfigMaps(c.namespace).Create(ctx, &policyCM, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed creating configmap: %s: %w", PoliciesConfigMapName, err)
		}
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: c.namespace,
			Name:      SecretName,
			Labels: labels.Set{
				LabelK8SAppManagedBy: "trivyoperator",
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
	err = c.client.CoreV1().ConfigMaps(c.namespace).Delete(ctx, GetPluginConfigMapName("Polaris"), metav1.DeleteOptions{})
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
