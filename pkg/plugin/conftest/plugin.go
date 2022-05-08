package conftest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

const (
	// Plugin the name of this plugin.
	Plugin = "Conftest"
)

const (
	containerName        = "conftest"
	workloadKey          = "trivyoperator.workload.yaml"
	defaultCheckCategory = "Security"
)

const (
	keyImageRef                = "conftest.imageRef"
	keyResourcesRequestsCPU    = "conftest.resources.requests.cpu"
	keyResourcesRequestsMemory = "conftest.resources.requests.memory"
	keyResourcesLimitsCPU      = "conftest.resources.limits.cpu"
	keyResourcesLimitsMemory   = "conftest.resources.limits.memory"
	keyPrefixPolicy            = "conftest.policy."
	keyPrefixLibrary           = "conftest.library."
	keySuffixKinds             = ".kinds"
	keySuffixRego              = ".rego"
)

const (
	kindAny      = "*"
	kindWorkload = "Workload"
)

// Config defines configuration params for this plugin.
type Config struct {
	trivyoperator.PluginConfig
}

// GetImageRef returns upstream Conftest container image reference.
func (c Config) GetImageRef() (string, error) {
	return c.GetRequiredData(keyImageRef)
}

func (c Config) GetLibraries() map[string]string {
	libs := make(map[string]string)
	for key, value := range c.Data {
		if !strings.HasPrefix(key, keyPrefixLibrary) {
			continue
		}
		if !strings.HasSuffix(key, keySuffixRego) {
			continue
		}
		libs[key] = value
	}
	return libs
}

func (c Config) GetPoliciesByKind(kind string) (map[string]string, error) {
	policies := make(map[string]string)
	for key, value := range c.Data {
		if strings.HasSuffix(key, keySuffixRego) && strings.HasPrefix(key, keyPrefixPolicy) {
			// Check if kinds were defined for this policy
			kindsKey := strings.TrimSuffix(key, keySuffixRego) + keySuffixKinds
			if _, ok := c.Data[kindsKey]; !ok {
				return nil, fmt.Errorf("kinds not defined for policy: %s", key)
			}
		}

		if !strings.HasSuffix(key, keySuffixKinds) {
			continue
		}
		for _, k := range strings.Split(value, ",") {
			if k == kindWorkload && !kube.IsWorkload(kind) {
				continue
			}
			if k != kindAny && k != kindWorkload && k != kind {
				continue
			}

			policyKey := strings.TrimSuffix(key, keySuffixKinds) + keySuffixRego
			var ok bool

			policies[policyKey], ok = c.Data[policyKey]
			if !ok {
				return nil, fmt.Errorf("expected policy not found: %s", policyKey)
			}
		}
	}
	return policies, nil
}

// GetResourceRequirements constructs ResourceRequirements from the Config.
func (c Config) GetResourceRequirements() (corev1.ResourceRequirements, error) {
	requirements := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{},
		Limits:   corev1.ResourceList{},
	}

	err := c.setResourceLimit(keyResourcesRequestsCPU, &requirements.Requests, corev1.ResourceCPU)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesRequestsMemory, &requirements.Requests, corev1.ResourceMemory)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesLimitsCPU, &requirements.Limits, corev1.ResourceCPU)
	if err != nil {
		return requirements, err
	}

	err = c.setResourceLimit(keyResourcesLimitsMemory, &requirements.Limits, corev1.ResourceMemory)
	if err != nil {
		return requirements, err
	}

	return requirements, nil
}

func (c Config) setResourceLimit(configKey string, k8sResourceList *corev1.ResourceList, k8sResourceName corev1.ResourceName) error {
	if value, found := c.Data[configKey]; found {
		quantity, err := resource.ParseQuantity(value)
		if err != nil {
			return fmt.Errorf("parsing resource definition %s: %s %w", configKey, value, err)
		}

		(*k8sResourceList)[k8sResourceName] = quantity
	}
	return nil
}

type plugin struct {
	idGenerator ext.IDGenerator
	clock       ext.Clock
}

// NewPlugin constructs a new configauditreport.Plugin, which is using
// the upstream Conftest container image to audit K8s workloads.
func NewPlugin(idGenerator ext.IDGenerator, clock ext.Clock) configauditreport.Plugin {
	return &plugin{
		idGenerator: idGenerator,
		clock:       clock,
	}
}

var (
	supportedKinds = []kube.Kind{
		kube.KindPod,
		kube.KindDeployment,
		kube.KindReplicaSet,
		kube.KindReplicationController,
		kube.KindStatefulSet,
		kube.KindDaemonSet,
		kube.KindCronJob,
		kube.KindJob,
		kube.KindService,
		kube.KindConfigMap,
		kube.KindRole,
		kube.KindRoleBinding,

		kube.KindClusterRole,
		kube.KindClusterRoleBindings,
		kube.KindCustomResourceDefinition,
	}
)

func (p *plugin) SupportedKinds() []kube.Kind {
	return supportedKinds
}

// IsApplicable returns true if there is at least one policy applicable to the specified object kind, false otherwise.
func (p *plugin) IsApplicable(ctx trivyoperator.PluginContext, obj client.Object) (bool, string, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return false, "", err
	}
	if obj.GetObjectKind().GroupVersionKind().Kind == "" {
		return false, "", errors.New("object kind must not be nil")
	}
	policies, err := config.GetPoliciesByKind(obj.GetObjectKind().GroupVersionKind().Kind)
	if err != nil {
		return false, "", err
	}
	if len(policies) == 0 {
		return false, fmt.Sprintf("no Rego policies found for kind %s", obj.GetObjectKind().GroupVersionKind().Kind), nil
	}
	return true, "", nil
}

func (p *plugin) Init(ctx trivyoperator.PluginContext) error {
	return ctx.EnsureConfig(trivyoperator.PluginConfig{
		Data: map[string]string{
			keyImageRef:                "openpolicyagent/conftest:v0.30.0",
			keyResourcesRequestsCPU:    "50m",
			keyResourcesRequestsMemory: "50M",
			keyResourcesLimitsCPU:      "300m",
			keyResourcesLimitsMemory:   "300M",
		},
	})
}

func (p *plugin) ConfigHash(ctx trivyoperator.PluginContext, kind kube.Kind) (string, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return "", err
	}
	modules, err := p.modulesByKind(config, string(kind))
	if err != nil {
		return "", err
	}
	return kube.ComputeHash(modules), nil
}

func (p *plugin) GetScanJobSpec(ctx trivyoperator.PluginContext, obj client.Object) (corev1.PodSpec, []*corev1.Secret, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return corev1.PodSpec{}, nil, fmt.Errorf("constructing config from plugin context: %w", err)
	}
	imageRef, err := config.GetImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, fmt.Errorf("getting image ref: %w", err)
	}

	modules, err := p.modulesByKind(config, obj.GetObjectKind().GroupVersionKind().Kind)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	var volumeMounts []corev1.VolumeMount
	var volumeItems []corev1.KeyToPath

	secretName := configauditreport.GetScanJobName(obj) + "-volume"
	secretData := make(map[string]string)

	for module, script := range modules {
		moduleName := strings.TrimPrefix(module, keyPrefixPolicy)
		moduleName = strings.TrimPrefix(moduleName, keyPrefixLibrary)

		// Copy policies so even if the trivyoperator-conftest-config ConfigMap has changed
		// before the scan Job is run, it won't fail with references to non-existent config key error.
		secretData[module] = script

		volumeItems = append(volumeItems, corev1.KeyToPath{
			Key:  module,
			Path: moduleName,
		})

		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      secretName,
			MountPath: "/project/policy/" + moduleName,
			SubPath:   moduleName,
			ReadOnly:  true,
		})
	}

	workloadAsYAML, err := yaml.Marshal(obj)
	if err != nil {
		return corev1.PodSpec{}, nil, fmt.Errorf("marshalling workload: %w", err)
	}

	secretData[workloadKey] = string(workloadAsYAML)

	volumeItems = append(volumeItems, corev1.KeyToPath{
		Key:  workloadKey,
		Path: "workload.yaml",
	})

	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      secretName,
		MountPath: "/project/workload.yaml",
		SubPath:   "workload.yaml",
		ReadOnly:  true,
	})
	requirements, err := config.GetResourceRequirements()
	if err != nil {
		return corev1.PodSpec{}, nil, fmt.Errorf("getting resource requirements: %w", err)
	}
	return corev1.PodSpec{
			ServiceAccountName:           ctx.GetServiceAccountName(),
			AutomountServiceAccountToken: pointer.BoolPtr(false),
			RestartPolicy:                corev1.RestartPolicyNever,
			Affinity:                     trivyoperator.LinuxNodeAffinity(),
			Volumes: []corev1.Volume{
				{
					Name: secretName,
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: secretName,
							Items:      volumeItems,
						},
					},
				},
			},
			Containers: []corev1.Container{
				{
					Name:                     containerName,
					Image:                    imageRef,
					ImagePullPolicy:          corev1.PullIfNotPresent,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Resources:                requirements,
					VolumeMounts:             volumeMounts,
					Command: []string{
						"sh",
					},
					// TODO Follow up with Conftest maintainers to allow returning 0 exit code in case of failures
					Args: []string{
						"-c",
						"conftest test --no-fail --output json --all-namespaces --policy /project/policy /project/workload.yaml",
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged:               pointer.BoolPtr(false),
						AllowPrivilegeEscalation: pointer.BoolPtr(false),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"all"},
						},
						ReadOnlyRootFilesystem: pointer.BoolPtr(true),
					},
				},
			},
			SecurityContext: &corev1.PodSecurityContext{},
		}, []*corev1.Secret{{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: ctx.GetNamespace(),
			},
			StringData: secretData,
		}}, nil
}

func (p *plugin) modulesByKind(config Config, kind string) (map[string]string, error) {
	modules, err := config.GetPoliciesByKind(kind)
	if err != nil {
		return nil, err
	}
	for key, value := range config.GetLibraries() {
		modules[key] = value
	}
	return modules, nil
}

func (p *plugin) GetContainerName() string {
	return containerName
}

func (p *plugin) ParseConfigAuditReportData(ctx trivyoperator.PluginContext, logsReader io.ReadCloser) (v1alpha1.ConfigAuditReportData, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return v1alpha1.ConfigAuditReportData{}, fmt.Errorf("constructing config from plugin context: %w", err)
	}
	var checkResults []CheckResult
	err = json.NewDecoder(logsReader).Decode(&checkResults)

	checks := make([]v1alpha1.Check, 0)
	var lowCount, criticalCount int

	for _, cr := range checkResults {

		for _, warning := range cr.Warnings {
			checks = append(checks, v1alpha1.Check{
				ID:       p.getPolicyTitleFromResult(warning),
				Severity: v1alpha1.SeverityLow,
				Messages: []string{warning.Message},
				Category: defaultCheckCategory,
				Success:  false,
			})
			lowCount++
		}

		for _, failure := range cr.Failures {
			checks = append(checks, v1alpha1.Check{
				ID:       p.getPolicyTitleFromResult(failure),
				Severity: v1alpha1.SeverityCritical,
				Messages: []string{failure.Message},
				Category: defaultCheckCategory,
				Success:  false,
			})
			criticalCount++
		}
	}

	imageRef, err := config.GetImageRef()
	if err != nil {
		return v1alpha1.ConfigAuditReportData{}, fmt.Errorf("getting image ref: %w", err)
	}

	version, err := trivyoperator.GetVersionFromImageRef(imageRef)
	if err != nil {
		return v1alpha1.ConfigAuditReportData{}, fmt.Errorf("getting version from image ref: %w", err)
	}

	return v1alpha1.ConfigAuditReportData{
		UpdateTimestamp: metav1.NewTime(p.clock.Now()),
		Scanner: v1alpha1.Scanner{
			Name:    "Conftest",
			Vendor:  "Open Policy Agent",
			Version: version,
		},
		Summary: v1alpha1.ConfigAuditSummary{
			CriticalCount: criticalCount,
			LowCount:      lowCount,
		},
		Checks: checks,
		// TODO Deprecate PodChecks and ContainerChecks in 0.12+
		PodChecks:       checks,
		ContainerChecks: map[string][]v1alpha1.Check{},
	}, nil
}

func (p *plugin) getPolicyTitleFromResult(result Result) string {
	// we check 1st if id exist
	if value, ok := result.Metadata["id"]; ok {
		return value.(string)
	}
	// if no id found it fall back to title
	if value, ok := result.Metadata["title"]; ok {
		return value.(string)
	}
	// Fallback to a unique identifier
	return p.idGenerator.GenerateID()
}

func (p *plugin) newConfigFrom(ctx trivyoperator.PluginContext) (Config, error) {
	pluginConfig, err := ctx.GetConfig()
	if err != nil {
		return Config{}, fmt.Errorf("getting config: %w", err)
	}
	return Config{PluginConfig: pluginConfig}, nil
}
