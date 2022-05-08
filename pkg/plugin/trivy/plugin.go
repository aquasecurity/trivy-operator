package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/docker"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
	"github.com/google/go-containerregistry/pkg/name"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Plugin the name of this plugin.
	Plugin = "Trivy"
)

const (
	keyTrivyImageRef               = "trivy.imageRef"
	keyTrivyMode                   = "trivy.mode"
	keyTrivyCommand                = "trivy.command"
	keyTrivySeverity               = "trivy.severity"
	keyTrivyIgnoreUnfixed          = "trivy.ignoreUnfixed"
	keyTrivyTimeout                = "trivy.timeout"
	keyTrivyIgnoreFile             = "trivy.ignoreFile"
	keyTrivyInsecureRegistryPrefix = "trivy.insecureRegistry."
	keyTrivyNonSslRegistryPrefix   = "trivy.nonSslRegistry."
	keyTrivyMirrorPrefix           = "trivy.registry.mirror."
	keyTrivyHTTPProxy              = "trivy.httpProxy"
	keyTrivyHTTPSProxy             = "trivy.httpsProxy"
	keyTrivyNoProxy                = "trivy.noProxy"
	keyTrivyGitHubToken            = "trivy.githubToken"
	keyTrivySkipFiles              = "trivy.skipFiles"
	keyTrivySkipDirs               = "trivy.skipDirs"
	keyTrivyDBRepository           = "trivy.dbRepository"

	keyTrivyServerURL           = "trivy.serverURL"
	keyTrivyServerTokenHeader   = "trivy.serverTokenHeader"
	keyTrivyServerInsecure      = "trivy.serverInsecure"
	keyTrivyServerToken         = "trivy.serverToken"
	keyTrivyServerCustomHeaders = "trivy.serverCustomHeaders"

	keyResourcesRequestsCPU    = "trivy.resources.requests.cpu"
	keyResourcesRequestsMemory = "trivy.resources.requests.memory"
	keyResourcesLimitsCPU      = "trivy.resources.limits.cpu"
	keyResourcesLimitsMemory   = "trivy.resources.limits.memory"
)

const defaultDBRepository = "ghcr.io/aquasecurity/trivy-db"

// Mode in which Trivy client operates.
type Mode string

const (
	Standalone   Mode = "Standalone"
	ClientServer Mode = "ClientServer"
)

// Command to scan image or filesystem.
type Command string

const (
	Filesystem Command = "filesystem"
	Image      Command = "image"
)

// Config defines configuration params for this plugin.
type Config struct {
	trivyoperator.PluginConfig
}

// GetImageRef returns upstream Trivy container image reference.
func (c Config) GetImageRef() (string, error) {
	return c.GetRequiredData(keyTrivyImageRef)
}

func (c Config) GetMode() (Mode, error) {
	var ok bool
	var value string
	if value, ok = c.Data[keyTrivyMode]; !ok {
		return "", fmt.Errorf("property %s not set", keyTrivyMode)
	}

	switch Mode(value) {
	case Standalone:
		return Standalone, nil
	case ClientServer:
		return ClientServer, nil
	}

	return "", fmt.Errorf("invalid value (%s) of %s; allowed values (%s, %s)",
		value, keyTrivyMode, Standalone, ClientServer)
}

func (c Config) GetCommand() (Command, error) {
	var ok bool
	var value string
	if value, ok = c.Data[keyTrivyCommand]; !ok {
		// for backward compatibility, fallback to ImageScan
		return Image, nil
	}
	switch Command(value) {
	case Image:
		return Image, nil
	case Filesystem:
		return Filesystem, nil
	}
	return "", fmt.Errorf("invalid value (%s) of %s; allowed values (%s, %s)",
		value, keyTrivyCommand, Image, Filesystem)
}

func (c Config) GetServerURL() (string, error) {
	return c.GetRequiredData(keyTrivyServerURL)
}

func (c Config) GetServerInsecure() bool {
	_, ok := c.Data[keyTrivyServerInsecure]
	return ok
}

func (c Config) IgnoreFileExists() bool {
	_, ok := c.Data[keyTrivyIgnoreFile]
	return ok
}

func (c Config) IgnoreUnfixed() bool {
	_, ok := c.Data[keyTrivyIgnoreUnfixed]
	return ok
}

func (c Config) GetInsecureRegistries() map[string]bool {
	insecureRegistries := make(map[string]bool)
	for key, val := range c.Data {
		if strings.HasPrefix(key, keyTrivyInsecureRegistryPrefix) {
			insecureRegistries[val] = true
		}
	}

	return insecureRegistries
}

func (c Config) GetNonSSLRegistries() map[string]bool {
	nonSSLRegistries := make(map[string]bool)
	for key, val := range c.Data {
		if strings.HasPrefix(key, keyTrivyNonSslRegistryPrefix) {
			nonSSLRegistries[val] = true
		}
	}

	return nonSSLRegistries
}

func (c Config) GetMirrors() map[string]string {
	res := make(map[string]string)
	for registryKey, mirror := range c.Data {
		if !strings.HasPrefix(registryKey, keyTrivyMirrorPrefix) {
			continue
		}
		res[strings.TrimPrefix(registryKey, keyTrivyMirrorPrefix)] = mirror
	}
	return res
}

// GetResourceRequirements creates ResourceRequirements from the Config.
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

func (c Config) GetDBRepository() (string, error) {
	return c.GetRequiredData(keyTrivyDBRepository)
}

type plugin struct {
	clock          ext.Clock
	idGenerator    ext.IDGenerator
	objectResolver *kube.ObjectResolver
}

// NewPlugin constructs a new vulnerabilityreport.Plugin, which is using an
// upstream Trivy container image to scan Kubernetes workloads.
//
// The plugin supports Image and Filesystem commands. The Filesystem command may
// be used to scan workload images cached on cluster nodes by scheduling
// scan jobs on a particular node.
//
// The Image command supports both Standalone and ClientServer modes depending
// on the settings returned by Config.GetMode. The ClientServer mode is usually
// more performant, however it requires a Trivy server accessible at the
// configurable Config.GetServerURL.
func NewPlugin(clock ext.Clock, idGenerator ext.IDGenerator, client client.Client) vulnerabilityreport.Plugin {
	return &plugin{
		clock:          clock,
		idGenerator:    idGenerator,
		objectResolver: &kube.ObjectResolver{Client: client},
	}
}

// Init ensures the default Config required by this plugin.
func (p *plugin) Init(ctx trivyoperator.PluginContext) error {
	return ctx.EnsureConfig(trivyoperator.PluginConfig{
		Data: map[string]string{
			keyTrivyImageRef:     "docker.io/aquasec/trivy:0.25.2",
			keyTrivySeverity:     "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
			keyTrivyMode:         string(Standalone),
			keyTrivyTimeout:      "5m0s",
			keyTrivyDBRepository: defaultDBRepository,

			keyResourcesRequestsCPU:    "100m",
			keyResourcesRequestsMemory: "100M",
			keyResourcesLimitsCPU:      "500m",
			keyResourcesLimitsMemory:   "500M",
		},
	})
}

func (p *plugin) GetScanJobSpec(ctx trivyoperator.PluginContext, workload client.Object, credentials map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	mode, err := config.GetMode()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	command, err := config.GetCommand()

	if command == Image {
		switch mode {
		case Standalone:
			return p.getPodSpecForStandaloneMode(ctx, config, workload, credentials)
		case ClientServer:
			return p.getPodSpecForClientServerMode(ctx, config, workload, credentials)
		default:
			return corev1.PodSpec{}, nil, fmt.Errorf("unrecognized trivy mode %q for command %q", mode, command)
		}
	}

	if command == Filesystem {
		switch mode {
		case Standalone:
			return p.getPodSpecForStandaloneFSMode(ctx, config, workload)
		default:
			return corev1.PodSpec{}, nil, fmt.Errorf("unrecognized trivy mode %q for command %q", mode, command)
		}
	}

	return corev1.PodSpec{}, nil, fmt.Errorf("unrecognized trivy command %q", command)
}

func (p *plugin) newSecretWithAggregateImagePullCredentials(obj client.Object, spec corev1.PodSpec, credentials map[string]docker.Auth) *corev1.Secret {
	containerImages := kube.GetContainerImagesFromPodSpec(spec)
	secretData := kube.AggregateImagePullSecretsData(containerImages, credentials)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: vulnerabilityreport.RegistryCredentialsSecretName(obj),
		},
		Data: secretData,
	}
}

const (
	tmpVolumeName               = "tmp"
	ignoreFileVolumeName        = "ignorefile"
	FsSharedVolumeName          = "trivyoperator"
	SharedVolumeLocationOfTrivy = "/var/trivyoperator/trivy"
)

// In the Standalone mode there is the init container responsible for
// downloading the latest Trivy DB file from GitHub and storing it to the
// emptyDir volume shared with main containers. In other words, the init
// container runs the following Trivy command:
//
//     trivy --cache-dir /tmp/trivy/.cache image --download-db-only
//
// The number of main containers correspond to the number of containers
// defined for the scanned workload. Each container runs the Trivy image scan
// command and skips the database download:
//
//     trivy --cache-dir /tmp/trivy/.cache image --skip-update \
//       --format json <container image>
func (p *plugin) getPodSpecForStandaloneMode(ctx trivyoperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	var secret *corev1.Secret
	var secrets []*corev1.Secret

	spec, err := kube.GetPodSpec(workload)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	if len(credentials) > 0 {
		secret = p.newSecretWithAggregateImagePullCredentials(workload, spec, credentials)
		secrets = append(secrets, secret)
	}

	trivyImageRef, err := config.GetImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	trivyConfigName := trivyoperator.GetPluginConfigMapName(Plugin)

	dbRepository, err := config.GetDBRepository()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	requirements, err := config.GetResourceRequirements()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	initContainer := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    trivyImageRef,
		ImagePullPolicy:          corev1.PullIfNotPresent,
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Env: []corev1.EnvVar{
			{
				Name: "HTTP_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyHTTPProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "HTTPS_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyHTTPSProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "NO_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyNoProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "GITHUB_TOKEN",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyGitHubToken,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
		},
		Command: []string{
			"trivy",
		},
		Args: []string{
			"--cache-dir",
			"/tmp/trivy/.cache",
			"image",
			"--download-db-only",
			"--db-repository",
			dbRepository,
		},
		Resources: requirements,
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      tmpVolumeName,
				MountPath: "/tmp",
				ReadOnly:  false,
			},
		},
	}

	var containers []corev1.Container

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      tmpVolumeName,
			ReadOnly:  false,
			MountPath: "/tmp",
		},
	}
	volumes := []corev1.Volume{
		{
			Name: tmpVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumDefault,
				},
			},
		},
	}

	if config.IgnoreFileExists() {
		volumes = append(volumes, corev1.Volume{
			Name: ignoreFileVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: trivyConfigName,
					},
					Items: []corev1.KeyToPath{
						{
							Key:  keyTrivyIgnoreFile,
							Path: ".trivyignore",
						},
					},
				},
			},
		})

		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      ignoreFileVolumeName,
			MountPath: "/etc/trivy/.trivyignore",
			SubPath:   ".trivyignore",
		})
	}

	for _, c := range spec.Containers {

		env := []corev1.EnvVar{
			{
				Name: "TRIVY_SEVERITY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivySeverity,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_IGNORE_UNFIXED",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyIgnoreUnfixed,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_TIMEOUT",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyTimeout,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_SKIP_FILES",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivySkipFiles,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_SKIP_DIRS",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivySkipDirs,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "HTTP_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyHTTPProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "HTTPS_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyHTTPSProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "NO_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyNoProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
		}

		if config.IgnoreFileExists() {
			env = append(env, corev1.EnvVar{
				Name:  "TRIVY_IGNOREFILE",
				Value: "/etc/trivy/.trivyignore",
			})
		}

		if _, ok := credentials[c.Name]; ok && secret != nil {
			registryUsernameKey := fmt.Sprintf("%s.username", c.Name)
			registryPasswordKey := fmt.Sprintf("%s.password", c.Name)

			env = append(env, corev1.EnvVar{
				Name: "TRIVY_USERNAME",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secret.Name,
						},
						Key: registryUsernameKey,
					},
				},
			}, corev1.EnvVar{
				Name: "TRIVY_PASSWORD",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secret.Name,
						},
						Key: registryPasswordKey,
					},
				},
			})
		}

		env, err = p.appendTrivyInsecureEnv(config, c.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		env, err = p.appendTrivyNonSSLEnv(config, c.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		resourceRequirements, err := config.GetResourceRequirements()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		optionalMirroredImage, err := GetMirroredImage(c.Image, config.GetMirrors())
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		containers = append(containers, corev1.Container{
			Name:                     c.Name,
			Image:                    trivyImageRef,
			ImagePullPolicy:          corev1.PullIfNotPresent,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command: []string{
				"trivy",
			},
			Args: []string{
				"--cache-dir",
				"/tmp/trivy/.cache",
				"--quiet",
				"image",
				"--skip-update",
				"--format",
				"json",
				optionalMirroredImage,
			},
			Resources:    resourceRequirements,
			VolumeMounts: volumeMounts,
			SecurityContext: &corev1.SecurityContext{
				Privileged:               pointer.BoolPtr(false),
				AllowPrivilegeEscalation: pointer.BoolPtr(false),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"all"},
				},
				ReadOnlyRootFilesystem: pointer.BoolPtr(true),
			},
		})
	}

	return corev1.PodSpec{
		Affinity:                     trivyoperator.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.BoolPtr(false),
		Volumes:                      volumes,
		InitContainers:               []corev1.Container{initContainer},
		Containers:                   containers,
		SecurityContext:              &corev1.PodSecurityContext{},
	}, secrets, nil
}

// In the ClientServer mode the number of containers of the pod created by the
// scan job equals the number of containers defined for the scanned workload.
// Each container runs Trivy image scan command and refers to Trivy server URL
// returned by Config.GetServerURL:
//
//     trivy client --remote <server URL> \
//       --format json <container image>
func (p *plugin) getPodSpecForClientServerMode(ctx trivyoperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth) (corev1.PodSpec, []*corev1.Secret, error) {
	var secret *corev1.Secret
	var secrets []*corev1.Secret
	var volumeMounts []corev1.VolumeMount
	var volumes []corev1.Volume

	spec, err := kube.GetPodSpec(workload)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	trivyImageRef, err := config.GetImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	trivyServerURL, err := config.GetServerURL()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	if len(credentials) > 0 {
		secret = p.newSecretWithAggregateImagePullCredentials(workload, spec, credentials)
		secrets = append(secrets, secret)
	}

	var containers []corev1.Container

	trivyConfigName := trivyoperator.GetPluginConfigMapName(Plugin)

	for _, container := range spec.Containers {

		env := []corev1.EnvVar{
			{
				Name: "HTTP_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyHTTPProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "HTTPS_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyHTTPSProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "NO_PROXY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyNoProxy,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_SEVERITY",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivySeverity,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_IGNORE_UNFIXED",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyIgnoreUnfixed,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_TIMEOUT",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyTimeout,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_SKIP_FILES",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivySkipFiles,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_SKIP_DIRS",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivySkipDirs,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_TOKEN_HEADER",
				ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyServerTokenHeader,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_TOKEN",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyServerToken,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
			{
				Name: "TRIVY_CUSTOM_HEADERS",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyServerCustomHeaders,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
		}

		if _, ok := credentials[container.Name]; ok && secret != nil {
			registryUsernameKey := fmt.Sprintf("%s.username", container.Name)
			registryPasswordKey := fmt.Sprintf("%s.password", container.Name)

			env = append(env, corev1.EnvVar{
				Name: "TRIVY_USERNAME",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secret.Name,
						},
						Key: registryUsernameKey,
					},
				},
			}, corev1.EnvVar{
				Name: "TRIVY_PASSWORD",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secret.Name,
						},
						Key: registryPasswordKey,
					},
				},
			})
		}

		env, err = p.appendTrivyInsecureEnv(config, container.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		env, err = p.appendTrivyNonSSLEnv(config, container.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		if config.GetServerInsecure() {
			env = append(env, corev1.EnvVar{
				Name:  "TRIVY_INSECURE",
				Value: "true",
			})
		}

		if config.IgnoreFileExists() {
			volumes = []corev1.Volume{
				{
					Name: ignoreFileVolumeName,
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: trivyConfigName,
							},
							Items: []corev1.KeyToPath{
								{
									Key:  keyTrivyIgnoreFile,
									Path: ".trivyignore",
								},
							},
						},
					},
				},
			}

			volumeMounts = []corev1.VolumeMount{
				{
					Name:      ignoreFileVolumeName,
					MountPath: "/etc/trivy/.trivyignore",
					SubPath:   ".trivyignore",
				},
			}

			env = append(env, corev1.EnvVar{
				Name:  "TRIVY_IGNOREFILE",
				Value: "/etc/trivy/.trivyignore",
			})
		}

		requirements, err := config.GetResourceRequirements()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		optionalMirroredImage, err := GetMirroredImage(container.Image, config.GetMirrors())
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		containers = append(containers, corev1.Container{
			Name:                     container.Name,
			Image:                    trivyImageRef,
			ImagePullPolicy:          corev1.PullIfNotPresent,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command: []string{
				"trivy",
			},
			Args: []string{
				"--quiet",
				"client",
				"--format",
				"json",
				"--remote",
				trivyServerURL,
				optionalMirroredImage,
			},
			VolumeMounts: volumeMounts,
			Resources:    requirements,
		})
	}

	return corev1.PodSpec{
		Affinity:                     trivyoperator.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.BoolPtr(false),
		Containers:                   containers,
		Volumes:                      volumes,
	}, secrets, nil
}

//FileSystem scan option with standalone mode.
//The only difference is that instead of scanning the resource by name,
//We scanning the resource place on a specific file system location using the following command.
//
//     trivy --quiet fs  --format json --ignore-unfixed  file/system/location
//
func (p *plugin) getPodSpecForStandaloneFSMode(ctx trivyoperator.PluginContext, config Config,
	workload client.Object) (corev1.PodSpec, []*corev1.Secret, error) {
	var secrets []*corev1.Secret
	spec, err := kube.GetPodSpec(workload)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	pullPolicy := corev1.PullIfNotPresent
	// nodeName to schedule scan job explicitly on specific node.
	var nodeName string
	if !ctx.GetTrivyOperatorConfig().VulnerabilityScanJobsInSameNamespace() {
		// get nodeName from running pods.
		nodeName, err = p.objectResolver.GetNodeName(context.Background(), workload)
		if err != nil {
			return corev1.PodSpec{}, nil, fmt.Errorf("failed resolving node name for workload %q: %w",
				workload.GetNamespace()+"/"+workload.GetName(), err)
		}
		pullPolicy = corev1.PullNever
	}

	trivyImageRef, err := config.GetImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	trivyConfigName := trivyoperator.GetPluginConfigMapName(Plugin)

	dbRepository, err := config.GetDBRepository()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	requirements, err := config.GetResourceRequirements()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      FsSharedVolumeName,
			ReadOnly:  false,
			MountPath: "/var/trivyoperator",
		},
	}

	initContainerCopyBinary := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    trivyImageRef,
		ImagePullPolicy:          corev1.PullIfNotPresent,
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Command: []string{
			"cp",
			"-v",
			"/usr/local/bin/trivy",
			SharedVolumeLocationOfTrivy,
		},
		Resources:    requirements,
		VolumeMounts: volumeMounts,
	}

	initContainerDB := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    trivyImageRef,
		ImagePullPolicy:          corev1.PullIfNotPresent,
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Env: []corev1.EnvVar{
			constructEnvVarSourceFromConfigMap("HTTP_PROXY", trivyConfigName, keyTrivyHTTPProxy),
			constructEnvVarSourceFromConfigMap("HTTPS_PROXY", trivyConfigName, keyTrivyHTTPSProxy),
			constructEnvVarSourceFromConfigMap("NO_PROXY", trivyConfigName, keyTrivyNoProxy),
			{
				Name: "GITHUB_TOKEN",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: trivyConfigName,
						},
						Key:      keyTrivyGitHubToken,
						Optional: pointer.BoolPtr(true),
					},
				},
			},
		},
		Command: []string{
			"trivy",
		},
		Args: []string{
			"--download-db-only",
			"--cache-dir",
			"/var/trivyoperator/trivy-db",
			"--db-repository",
			dbRepository,
		},
		Resources:    requirements,
		VolumeMounts: volumeMounts,
	}

	var containers []corev1.Container

	volumes := []corev1.Volume{
		{
			Name: FsSharedVolumeName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumDefault,
				},
			},
		},
	}

	//TODO Move this to function and refactor the code to use it
	if config.IgnoreFileExists() {
		volumes = append(volumes, corev1.Volume{
			Name: ignoreFileVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: trivyConfigName,
					},
					Items: []corev1.KeyToPath{
						{
							Key:  keyTrivyIgnoreFile,
							Path: ".trivyignore",
						},
					},
				},
			},
		})

		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      ignoreFileVolumeName,
			MountPath: "/tmp/trivy/.trivyignore",
			SubPath:   ".trivyignore",
		})
	}

	for _, c := range spec.Containers {

		env := []corev1.EnvVar{
			constructEnvVarSourceFromConfigMap("TRIVY_SEVERITY", trivyConfigName, keyTrivySeverity),
			constructEnvVarSourceFromConfigMap("TRIVY_SKIP_FILES", trivyConfigName, keyTrivySkipFiles),
			constructEnvVarSourceFromConfigMap("TRIVY_SKIP_DIRS", trivyConfigName, keyTrivySkipDirs),
			constructEnvVarSourceFromConfigMap("HTTP_PROXY", trivyConfigName, keyTrivyHTTPProxy),
			constructEnvVarSourceFromConfigMap("HTTPS_PROXY", trivyConfigName, keyTrivyHTTPSProxy),
			constructEnvVarSourceFromConfigMap("NO_PROXY", trivyConfigName, keyTrivyNoProxy),
		}
		if config.IgnoreFileExists() {
			env = append(env, corev1.EnvVar{
				Name:  "TRIVY_IGNOREFILE",
				Value: "/tmp/trivy/.trivyignore",
			})
		}
		if config.IgnoreUnfixed() {
			env = append(env, constructEnvVarSourceFromConfigMap("TRIVY_IGNORE_UNFIXED",
				trivyConfigName, keyTrivyIgnoreUnfixed))
		}

		env, err = p.appendTrivyInsecureEnv(config, c.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		resourceRequirements, err := config.GetResourceRequirements()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		containers = append(containers, corev1.Container{
			Name:                     c.Name,
			Image:                    c.Image,
			ImagePullPolicy:          pullPolicy,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command: []string{
				SharedVolumeLocationOfTrivy,
			},
			Args: []string{
				"--skip-update",
				"--cache-dir",
				"/var/trivyoperator/trivy-db",
				"--quiet",
				"fs",
				"--format",
				"json",
				"/",
			},
			Resources:    resourceRequirements,
			VolumeMounts: volumeMounts,
			// Todo review security Context which is better for trivy fs scan
			SecurityContext: &corev1.SecurityContext{
				Privileged:               pointer.BoolPtr(false),
				AllowPrivilegeEscalation: pointer.BoolPtr(false),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"all"},
				},
				ReadOnlyRootFilesystem: pointer.BoolPtr(true),
				// Currently Trivy needs to run as root user to scan filesystem, So we will run fs scan job with root user.
				RunAsUser: pointer.Int64(0),
			},
		})
	}

	podSpec := corev1.PodSpec{
		Affinity:                     trivyoperator.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: pointer.BoolPtr(false),
		Volumes:                      volumes,
		InitContainers:               []corev1.Container{initContainerCopyBinary, initContainerDB},
		Containers:                   containers,
		SecurityContext:              &corev1.PodSecurityContext{},
	}

	if !ctx.GetTrivyOperatorConfig().VulnerabilityScanJobsInSameNamespace() {
		// schedule scan job explicitly on specific node.
		podSpec.NodeName = nodeName
	}

	return podSpec, secrets, nil
}

func (p *plugin) appendTrivyInsecureEnv(config Config, image string, env []corev1.EnvVar) ([]corev1.EnvVar, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, err
	}

	insecureRegistries := config.GetInsecureRegistries()
	if insecureRegistries[ref.Context().RegistryStr()] {
		env = append(env, corev1.EnvVar{
			Name:  "TRIVY_INSECURE",
			Value: "true",
		})
	}

	return env, nil
}

func (p *plugin) appendTrivyNonSSLEnv(config Config, image string, env []corev1.EnvVar) ([]corev1.EnvVar, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return nil, err
	}

	nonSSLRegistries := config.GetNonSSLRegistries()
	if nonSSLRegistries[ref.Context().RegistryStr()] {
		env = append(env, corev1.EnvVar{
			Name:  "TRIVY_NON_SSL",
			Value: "true",
		})
	}

	return env, nil
}

func (p *plugin) ParseVulnerabilityReportData(ctx trivyoperator.PluginContext, imageRef string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityReportData, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return v1alpha1.VulnerabilityReportData{}, err
	}
	var reports ScanReport
	err = json.NewDecoder(logsReader).Decode(&reports)
	if err != nil {
		return v1alpha1.VulnerabilityReportData{}, err
	}
	vulnerabilities := make([]v1alpha1.Vulnerability, 0)

	for _, report := range reports.Results {
		for _, sr := range report.Vulnerabilities {
			vulnerabilities = append(vulnerabilities, v1alpha1.Vulnerability{
				VulnerabilityID:  sr.VulnerabilityID,
				Resource:         sr.PkgName,
				InstalledVersion: sr.InstalledVersion,
				FixedVersion:     sr.FixedVersion,
				Severity:         sr.Severity,
				Title:            sr.Title,
				PrimaryLink:      sr.PrimaryURL,
				Links:            []string{},
				Score:            GetScoreFromCVSS(sr.Cvss),
			})
		}
	}

	registry, artifact, err := p.parseImageRef(imageRef)
	if err != nil {
		return v1alpha1.VulnerabilityReportData{}, err
	}

	trivyImageRef, err := config.GetImageRef()
	if err != nil {
		return v1alpha1.VulnerabilityReportData{}, err
	}

	version, err := trivyoperator.GetVersionFromImageRef(trivyImageRef)
	if err != nil {
		return v1alpha1.VulnerabilityReportData{}, err
	}

	return v1alpha1.VulnerabilityReportData{
		UpdateTimestamp: metav1.NewTime(p.clock.Now()),
		Scanner: v1alpha1.Scanner{
			Name:    "Trivy",
			Vendor:  "Aqua Security",
			Version: version,
		},
		Registry:        registry,
		Artifact:        artifact,
		Summary:         p.toSummary(vulnerabilities),
		Vulnerabilities: vulnerabilities,
	}, nil
}

func (p *plugin) newConfigFrom(ctx trivyoperator.PluginContext) (Config, error) {
	pluginConfig, err := ctx.GetConfig()
	if err != nil {
		return Config{}, err
	}
	return Config{PluginConfig: pluginConfig}, nil
}

func (p *plugin) toSummary(vulnerabilities []v1alpha1.Vulnerability) v1alpha1.VulnerabilitySummary {
	var vs v1alpha1.VulnerabilitySummary
	for _, v := range vulnerabilities {
		switch v.Severity {
		case v1alpha1.SeverityCritical:
			vs.CriticalCount++
		case v1alpha1.SeverityHigh:
			vs.HighCount++
		case v1alpha1.SeverityMedium:
			vs.MediumCount++
		case v1alpha1.SeverityLow:
			vs.LowCount++
		default:
			vs.UnknownCount++
		}
	}
	return vs
}

func (p *plugin) parseImageRef(imageRef string) (v1alpha1.Registry, v1alpha1.Artifact, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return v1alpha1.Registry{}, v1alpha1.Artifact{}, err
	}
	registry := v1alpha1.Registry{
		Server: ref.Context().RegistryStr(),
	}
	artifact := v1alpha1.Artifact{
		Repository: ref.Context().RepositoryStr(),
	}
	switch t := ref.(type) {
	case name.Tag:
		artifact.Tag = t.TagStr()
	case name.Digest:
		artifact.Digest = t.DigestStr()
	}
	return registry, artifact, nil
}

func GetScoreFromCVSS(CVSSs map[string]*CVSS) *float64 {
	var nvdScore, vendorScore *float64

	for name, cvss := range CVSSs {
		if name == "nvd" {
			nvdScore = cvss.V3Score
		} else {
			vendorScore = cvss.V3Score
		}
	}

	if vendorScore != nil {
		return vendorScore
	}

	return nvdScore
}

func GetMirroredImage(image string, mirrors map[string]string) (string, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return "", err
	}
	mirroredImage := ref.Name()
	for k, v := range mirrors {
		if strings.HasPrefix(mirroredImage, k) {
			mirroredImage = strings.Replace(mirroredImage, k, v, 1)
			return mirroredImage, nil
		}
	}
	// If nothing is mirrored, we can simply use the input image.
	return image, nil
}

func constructEnvVarSourceFromConfigMap(envName, configName, configKey string) (res corev1.EnvVar) {
	res = corev1.EnvVar{
		Name: envName,
		ValueFrom: &corev1.EnvVarSource{
			ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: configName,
				},
				Key:      configKey,
				Optional: pointer.BoolPtr(true),
			},
		},
	}
	return
}
