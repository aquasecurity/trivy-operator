package trivy

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/pointer"

	"github.com/aquasecurity/trivy-operator/pkg/docker"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	containerimage "github.com/google/go-containerregistry/pkg/name"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	GCPCR_Inage_Regex  = `^(gcr\.io.*|^([a-zA-Z0-9-]+)-*-*.docker.pkg.dev.*)`
	AWSECR_Image_Regex = "^\\d+\\.dkr\\.ecr\\.(\\w+-\\w+-\\d+)\\.amazonaws\\.com\\/"
	// SkipDirsAnnotation annotation  example: trivy-operator.aquasecurity.github.io/skip-dirs: "/tmp,/home"
	SkipDirsAnnotation = "trivy-operator.aquasecurity.github.io/skip-dirs"
	// SkipFilesAnnotation example: trivy-operator.aquasecurity.github.io/skip-files: "/src/Gemfile.lock,/examplebinary"
	SkipFilesAnnotation = "trivy-operator.aquasecurity.github.io/skip-files"
)

const (
	Standalone   Mode = "Standalone"
	ClientServer Mode = "ClientServer"
)

const (
	Filesystem Command = "filesystem"
	Image      Command = "image"
	Rootfs     Command = "rootfs"
)

// Mode in which Trivy client operates.
type Mode string

// Command to scan image or filesystem.
type Command string

type GetPodSpecFunc func(ctx trivyoperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext, p *plugin) (corev1.PodSpec, []*corev1.Secret, error)

type PodSpecMgr interface {
	GetPodSpec(ctx trivyoperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext, p *plugin) (corev1.PodSpec, []*corev1.Secret, error)
}

func NewPodSpecMgr(ctx trivyoperator.PluginContext) (PodSpecMgr, error) {
	pluginConfig, err := ctx.GetConfig()
	if err != nil {
		return nil, err
	}
	config := Config{PluginConfig: pluginConfig}

	mode, err := config.GetMode()
	if err != nil {
		return nil, err
	}
	command, err := config.GetCommand()
	if err != nil {
		return nil, err
	}

	if command == Image {
		switch mode {
		case Standalone:
			return &ImageJobSpecMgr{
				getPodSpecFunc: GetPodSpecForStandaloneMode,
			}, nil
		case ClientServer:
			return &ImageJobSpecMgr{
				getPodSpecFunc: GetPodSpecForClientServerMode,
			}, nil
		default:
		}
	}

	if command == Filesystem || command == Rootfs {
		switch mode {
		case Standalone:
			return &ImageJobSpecMgr{
				getPodSpecFunc: GetPodSpecForStandaloneFSMode,
			}, nil
		case ClientServer:
			return &ImageJobSpecMgr{
				getPodSpecFunc: GetPodSpecForClientServerFSMode,
			}, nil
		}
	}
	return nil, fmt.Errorf("unrecognized trivy mode %q for command %q", mode, command)
}

func imageConfigSecretScanner(tc trivyoperator.ConfigData) []string {
	if tc.ExposedSecretsScannerEnabled() {
		return []string{"--image-config-scanners", "secret"}
	}
	return []string{}
}

func appendTrivyInsecureEnv(config Config, image string, env []corev1.EnvVar) ([]corev1.EnvVar, error) {
	ref, err := containerimage.ParseReference(image)
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

func getScanResultVolume() corev1.Volume {
	return corev1.Volume{
		Name: scanResultVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumDefault,
			},
		},
	}
}

func getScanResultVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      scanResultVolumeName,
		ReadOnly:  false,
		MountPath: "/tmp/scan",
	}
}

func ConfigWorkloadAnnotationEnvVars(workload client.Object, annotation string, envVarName string, trivyConfigName string, configKey string) corev1.EnvVar {
	if value, ok := workload.GetAnnotations()[annotation]; ok {
		return corev1.EnvVar{
			Name:  envVarName,
			Value: value,
		}
	}
	return constructEnvVarSourceFromConfigMap(envVarName, trivyConfigName, configKey)
}

func getPkgList(ctx trivyoperator.PluginContext) string {
	c := ctx.GetTrivyOperatorConfig()
	if c.GenerateSbomEnabled() {
		return "--list-all-pkgs"
	}
	return ""
}

func getSecurityChecks(ctx trivyoperator.PluginContext) string {
	securityChecks := make([]string, 0)

	c := ctx.GetTrivyOperatorConfig()
	if c.VulnerabilityScannerEnabled() {
		securityChecks = append(securityChecks, "vuln")
	}

	if c.ExposedSecretsScannerEnabled() {
		securityChecks = append(securityChecks, "secret")
	}

	return strings.Join(securityChecks, ",")
}

func getContainers(spec corev1.PodSpec) []corev1.Container {
	containers := append(spec.Containers, spec.InitContainers...)

	// ephemeral container are not the same type as Containers/InitContainers,
	// then we add it in a different loop
	for _, c := range spec.EphemeralContainers {
		containers = append(containers, corev1.Container(c.EphemeralContainerCommon))
	}

	return containers
}

func constructEnvVarSourceFromSecret(envName, secretName, secretKey string) (res corev1.EnvVar) {
	res = corev1.EnvVar{
		Name: envName,
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: secretName,
				},
				Key:      secretKey,
				Optional: pointer.Bool(true),
			},
		},
	}
	return
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
				Optional: pointer.Bool(true),
			},
		},
	}
	return
}
