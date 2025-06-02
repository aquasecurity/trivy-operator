package trivy

import (
	"encoding/json"
	"fmt"
	"strings"

	containerimage "github.com/google/go-containerregistry/pkg/name"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/docker"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

const (
	GCPCR_Image_Regex  = `^(us\.|eu\.|asia\.)?gcr\.io.*|^([a-zA-Z0-9-]+)-*-*.docker\.pkg\.dev.*`
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

type GetPodSpecFunc func(ctx trivyoperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext, p *plugin, clusterSboms map[string]v1alpha1.SbomReportData) (corev1.PodSpec, []*corev1.Secret, error)

type PodSpecMgr interface {
	GetPodSpec(ctx trivyoperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext, p *plugin, clusterSboms map[string]v1alpha1.SbomReportData) (corev1.PodSpec, []*corev1.Secret, error)
}

func NewPodSpecMgr(config Config) PodSpecMgr {
	mode := config.GetMode()
	command := config.GetCommand()
	if command == Image {
		switch mode {
		case Standalone:
			return &ImageJobSpecMgr{
				getPodSpecFunc: GetPodSpecForStandaloneMode,
			}
		case ClientServer:
			return &ImageJobSpecMgr{
				getPodSpecFunc: GetPodSpecForClientServerMode,
			}
		default:
			return &ImageJobSpecMgr{
				getPodSpecFunc: GetPodSpecForStandaloneMode,
			}
		}
	}

	if command == Filesystem || command == Rootfs {
		switch mode {
		case Standalone:
			return &ImageJobSpecMgr{
				getPodSpecFunc: GetPodSpecForStandaloneFSMode,
			}
		case ClientServer:
			return &ImageJobSpecMgr{
				getPodSpecFunc: GetPodSpecForClientServerFSMode,
			}
		default:
			return &ImageJobSpecMgr{
				getPodSpecFunc: GetPodSpecForStandaloneFSMode,
			}
		}
	}
	return &ImageJobSpecMgr{
		getPodSpecFunc: GetPodSpecForStandaloneMode,
	}
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

func ConfigWorkloadAnnotationEnvVars(workload client.Object, annotation, envVarName, trivyConfigName, configKey string) corev1.EnvVar {
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
	containers := spec.Containers
	containers = append(containers, spec.InitContainers...)

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
				Optional: ptr.To[bool](true),
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
				Optional: ptr.To[bool](true),
			},
		},
	}
	return
}

func getAutomountServiceAccountToken(ctx trivyoperator.PluginContext) bool {
	return ctx.GetTrivyOperatorConfig().GetScanJobAutomountServiceAccountToken()
}

func getConfig(ctx trivyoperator.PluginContext) (Config, error) {
	pluginConfig, err := ctx.GetConfig()
	if err != nil {
		return Config{}, err
	}
	return Config{PluginConfig: pluginConfig}, nil
}

// CreateSbomDataAsSecret creates a secret with the BOM data
func CreateSbomDataAsSecret(bom v1alpha1.BOM, secretName string) (corev1.Secret, error) {
	bomByte, err := json.Marshal(bom)
	if err != nil {
		return corev1.Secret{}, err
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
		},
		Data: map[string][]byte{
			"bom": bomByte,
		},
	}
	return secret, nil
}

// CreateVolumeSbomFiles creates a volume and volume mount for the sbom data
func CreateVolumeSbomFiles(volumeMounts *[]corev1.VolumeMount, volumes *[]corev1.Volume, secretName *string, fileName, mountPath, cname string) {
	vname := fmt.Sprintf("sbomvol-%s", cname)
	sbomMount := corev1.VolumeMount{
		Name:      vname,
		MountPath: mountPath,
		ReadOnly:  true,
	}
	sbomVolume := corev1.Volume{
		Name: vname,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: *secretName,
				Items: []corev1.KeyToPath{
					{
						Key:  "bom",
						Path: fileName,
					},
				},
			},
		},
	}
	*volumes = append(*volumes, sbomVolume)
	*volumeMounts = append(*volumeMounts, sbomMount)
}
