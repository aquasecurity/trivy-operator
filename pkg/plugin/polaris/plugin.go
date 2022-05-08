package polaris

import (
	"encoding/json"
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
)

const (
	// Plugin the name of this plugin.
	Plugin = "Polaris"
)

const (
	polarisContainerName = "polaris"
	configVolume         = "config"
)

const (
	keyImageRef                = "polaris.imageRef"
	keyConfigYaml              = "polaris.config.yaml"
	keyResourcesRequestsCPU    = "polaris.resources.requests.cpu"
	keyResourcesRequestsMemory = "polaris.resources.requests.memory"
	keyResourcesLimitsCPU      = "polaris.resources.limits.cpu"
	keyResourcesLimitsMemory   = "polaris.resources.limits.memory"
)

const (
	// DefaultConfigYAML the default Polaris config YAML as string literal.
	DefaultConfigYAML = `checks:
  # reliability
  multipleReplicasForDeployment: ignore
  priorityClassNotSet: ignore
  # resources
  cpuRequestsMissing: warning
  cpuLimitsMissing: warning
  memoryRequestsMissing: warning
  memoryLimitsMissing: warning
  # images
  tagNotSpecified: danger
  pullPolicyNotAlways: ignore
  # healthChecks
  readinessProbeMissing: warning
  livenessProbeMissing: warning
  # networking
  hostNetworkSet: warning
  hostPortSet: warning
  # security
  hostIPCSet: danger
  hostPIDSet: danger
  notReadOnlyRootFilesystem: warning
  privilegeEscalationAllowed: danger
  runAsRootAllowed: warning
  runAsPrivileged: danger
  dangerousCapabilities: danger
  insecureCapabilities: warning
exemptions:
  - controllerNames:
    - kube-apiserver
    - kube-proxy
    - kube-scheduler
    - etcd-manager-events
    - kube-controller-manager
    - kube-dns
    - etcd-manager-main
    rules:
    - hostPortSet
    - hostNetworkSet
    - readinessProbeMissing
    - livenessProbeMissing
    - cpuRequestsMissing
    - cpuLimitsMissing
    - memoryRequestsMissing
    - memoryLimitsMissing
    - runAsRootAllowed
    - runAsPrivileged
    - notReadOnlyRootFilesystem
    - hostPIDSet
  - controllerNames:
    - kube-flannel-ds
    rules:
    - notReadOnlyRootFilesystem
    - runAsRootAllowed
    - notReadOnlyRootFilesystem
    - readinessProbeMissing
    - livenessProbeMissing
    - cpuLimitsMissing
  - controllerNames:
    - cert-manager
    rules:
    - notReadOnlyRootFilesystem
    - runAsRootAllowed
    - readinessProbeMissing
    - livenessProbeMissing
  - controllerNames:
    - cluster-autoscaler
    rules:
    - notReadOnlyRootFilesystem
    - runAsRootAllowed
    - readinessProbeMissing
  - controllerNames:
    - vpa
    rules:
    - runAsRootAllowed
    - readinessProbeMissing
    - livenessProbeMissing
    - notReadOnlyRootFilesystem
  - controllerNames:
    - datadog
    rules:
    - runAsRootAllowed
    - readinessProbeMissing
    - livenessProbeMissing
    - notReadOnlyRootFilesystem
  - controllerNames:
    - nginx-ingress-controller
    rules:
    - privilegeEscalationAllowed
    - insecureCapabilities
    - runAsRootAllowed
  - controllerNames:
    - dns-controller
    - datadog-datadog
    - kube-flannel-ds
    - kube2iam
    - aws-iam-authenticator
    - datadog
    - kube2iam
    rules:
    - hostNetworkSet
  - controllerNames:
    - aws-iam-authenticator
    - aws-cluster-autoscaler
    - kube-state-metrics
    - dns-controller
    - external-dns
    - dnsmasq
    - autoscaler
    - kubernetes-dashboard
    - install-cni
    - kube2iam
    rules:
    - readinessProbeMissing
    - livenessProbeMissing
  - controllerNames:
    - aws-iam-authenticator
    - nginx-ingress-default-backend
    - aws-cluster-autoscaler
    - kube-state-metrics
    - dns-controller
    - external-dns
    - kubedns
    - dnsmasq
    - autoscaler
    - tiller
    - kube2iam
    rules:
    - runAsRootAllowed
  - controllerNames:
    - aws-iam-authenticator
    - nginx-ingress-controller
    - nginx-ingress-default-backend
    - aws-cluster-autoscaler
    - kube-state-metrics
    - dns-controller
    - external-dns
    - kubedns
    - dnsmasq
    - autoscaler
    - tiller
    - kube2iam
    rules:
    - notReadOnlyRootFilesystem
  - controllerNames:
    - cert-manager
    - dns-controller
    - kubedns
    - dnsmasq
    - autoscaler
    - insights-agent-goldilocks-vpa-install
    - datadog
    rules:
    - cpuRequestsMissing
    - cpuLimitsMissing
    - memoryRequestsMissing
    - memoryLimitsMissing
  - controllerNames:
    - kube2iam
    - kube-flannel-ds
    rules:
    - runAsPrivileged
  - controllerNames:
    - kube-hunter
    rules:
    - hostPIDSet
  - controllerNames:
    - polaris
    - kube-hunter
    - goldilocks
    - insights-agent-goldilocks-vpa-install
    rules:
    - notReadOnlyRootFilesystem
  - controllerNames:
    - insights-agent-goldilocks-controller
    rules:
    - livenessProbeMissing
    - readinessProbeMissing
  - controllerNames:
    - insights-agent-goldilocks-vpa-install
    - kube-hunter
    rules:
    - runAsRootAllowed
`
)

// Config defines configuration params for this plugin.
type Config struct {
	trivyoperator.PluginConfig
}

// GetImageRef returns upstream Polaris container image reference.
func (c Config) GetImageRef() (string, error) {
	return c.GetRequiredData(keyImageRef)
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
	clock ext.Clock
}

// NewPlugin constructs a new configauditreport.Plugin, which is using an
// upstream Polaris container image to audit configuration of Kubernetes workloads.
func NewPlugin(clock ext.Clock) configauditreport.Plugin {
	return &plugin{
		clock: clock,
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
	}
)

func (p *plugin) SupportedKinds() []kube.Kind {
	return supportedKinds
}

func (p *plugin) IsApplicable(_ trivyoperator.PluginContext, _ client.Object) (bool, string, error) {
	return true, "", nil
}

// Init ensures the default Config required by this plugin.
func (p *plugin) Init(ctx trivyoperator.PluginContext) error {
	return ctx.EnsureConfig(trivyoperator.PluginConfig{
		Data: map[string]string{
			keyImageRef:                "quay.io/fairwinds/polaris:4.2",
			keyConfigYaml:              DefaultConfigYAML,
			keyResourcesRequestsCPU:    "50m",
			keyResourcesRequestsMemory: "50M",
			keyResourcesLimitsCPU:      "300m",
			keyResourcesLimitsMemory:   "300M",
		},
	})
}

func (p *plugin) ConfigHash(ctx trivyoperator.PluginContext, _ kube.Kind) (string, error) {
	cm, err := ctx.GetConfig()
	if err != nil {
		return "", err
	}
	data := make(map[string]string)
	for key, value := range cm.Data {
		if strings.HasPrefix(key, "polaris.resources.") {
			continue
		}
		data[key] = value
	}
	return kube.ComputeHash(data), nil
}

func (p *plugin) newConfigFrom(ctx trivyoperator.PluginContext) (Config, error) {
	pluginConfig, err := ctx.GetConfig()
	if err != nil {
		return Config{}, fmt.Errorf("getting config: %w", err)
	}
	return Config{PluginConfig: pluginConfig}, nil
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
	requirements, err := config.GetResourceRequirements()
	if err != nil {
		return corev1.PodSpec{}, nil, fmt.Errorf("getting resource requirements: %w", err)
	}
	sourceName := p.sourceNameFrom(obj)

	return corev1.PodSpec{
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.BoolPtr(true),
		RestartPolicy:                corev1.RestartPolicyNever,
		Affinity:                     trivyoperator.LinuxNodeAffinity(),
		Volumes: []corev1.Volume{
			{
				Name: configVolume,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyoperator.GetPluginConfigMapName(ctx.GetName()),
						},
					},
				},
			},
		},
		Containers: []corev1.Container{
			{
				Name:                     polarisContainerName,
				Image:                    imageRef,
				ImagePullPolicy:          corev1.PullIfNotPresent,
				TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
				Resources:                requirements,
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      configVolume,
						MountPath: "/etc/trivyoperator",
					},
				},
				Command: []string{"sh"},
				Args: []string{
					"-c",
					"polaris audit --log-level error --config /etc/trivyoperator/polaris.config.yaml --resource " + sourceName + " 2> /dev/null",
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
	}, nil, nil
}

func (p *plugin) GetContainerName() string {
	return polarisContainerName
}

func (p *plugin) ParseConfigAuditReportData(ctx trivyoperator.PluginContext, logsReader io.ReadCloser) (v1alpha1.ConfigAuditReportData, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return v1alpha1.ConfigAuditReportData{}, fmt.Errorf("constructing config from plugin context: %w", err)
	}
	var report Report
	err = json.NewDecoder(logsReader).Decode(&report)
	if err != nil {
		return v1alpha1.ConfigAuditReportData{}, err
	}

	var checks []v1alpha1.Check
	var podChecks []v1alpha1.Check
	containerNameToChecks := make(map[string][]v1alpha1.Check)

	if len(report.Results) != 1 {
		return v1alpha1.ConfigAuditReportData{}, fmt.Errorf("unexpected report results count, got: %d, want: %d", len(report.Results), 1)
	}
	for _, pr := range report.Results[0].PodResult.Results {
		severity, err := v1alpha1.StringToSeverity(pr.Severity)
		if err != nil {
			return v1alpha1.ConfigAuditReportData{}, err
		}
		check := v1alpha1.Check{
			ID:       pr.ID,
			Messages: []string{pr.Message},
			Success:  pr.Success,
			Severity: severity,
			Category: pr.Category,
		}
		checks = append(checks, check)
		podChecks = append(podChecks, check)
	}

	for _, cr := range report.Results[0].PodResult.ContainerResults {
		var containerChecks []v1alpha1.Check
		for _, crr := range cr.Results {
			severity, err := v1alpha1.StringToSeverity(crr.Severity)
			if err != nil {
				return v1alpha1.ConfigAuditReportData{}, err
			}
			containerChecks = append(containerChecks, v1alpha1.Check{
				ID:       crr.ID,
				Messages: []string{crr.Message},
				Success:  crr.Success,
				Severity: severity,
				Category: crr.Category,
				Scope: &v1alpha1.CheckScope{
					Type:  "Container",
					Value: cr.Name,
				},
			})

		}
		checks = append(checks, containerChecks...)
		containerNameToChecks[cr.Name] = containerChecks
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
		Scanner: v1alpha1.Scanner{
			Name:    "Polaris",
			Vendor:  "Fairwinds Ops",
			Version: version,
		},
		Summary:         p.configAuditSummaryFrom(podChecks, containerNameToChecks),
		UpdateTimestamp: metav1.NewTime(p.clock.Now()),
		Checks:          checks,
		// TODO Deprecate PodChecks and ContainerChecks in 0.12+
		PodChecks:       podChecks,
		ContainerChecks: containerNameToChecks,
	}, nil
}

func (p *plugin) sourceNameFrom(obj client.Object) string {
	gvk := obj.GetObjectKind().GroupVersionKind()
	group := gvk.Group
	if len(group) > 0 {
		group = "." + group
	}
	return fmt.Sprintf("%s/%s%s/%s/%s",
		obj.GetNamespace(),
		gvk.Kind,
		group,
		gvk.Version,
		obj.GetName(),
	)
}

func (p *plugin) configAuditSummaryFrom(podChecks []v1alpha1.Check, containerChecks map[string][]v1alpha1.Check) v1alpha1.ConfigAuditSummary {
	var summary v1alpha1.ConfigAuditSummary
	for _, c := range podChecks {
		if c.Success {
			continue
		}
		switch c.Severity {
		case v1alpha1.SeverityCritical:
			summary.CriticalCount++
		case v1alpha1.SeverityLow:
			summary.LowCount++
		}
	}
	for _, checks := range containerChecks {
		for _, c := range checks {
			if c.Success {
				continue
			}
			switch c.Severity {
			case v1alpha1.SeverityCritical:
				summary.CriticalCount++
			case v1alpha1.SeverityLow:
				summary.LowCount++
			}
		}
	}
	return summary
}
