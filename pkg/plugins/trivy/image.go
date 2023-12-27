package trivy

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/docker"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
	containerimage "github.com/google/go-containerregistry/pkg/name"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ImageJobSpecMgr struct {
	getPodSpecFunc GetPodSpecFunc
}

func NewImageJobSpecMgr() PodSpecMgr {
	return &ImageJobSpecMgr{}
}

func (j *ImageJobSpecMgr) GetPodSpec(ctx trivyoperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext, p *plugin, clusterSboms map[string]v1alpha1.SbomReportData) (corev1.PodSpec, []*corev1.Secret, error) {
	return j.getPodSpecFunc(ctx, config, workload, credentials, securityContext, p, clusterSboms)
}

// In the Standalone mode there is the init container responsible for
// downloading the latest Trivy DB file from GitHub and storing it to the
// emptyDir volume shared with main containers. In other words, the init
// container runs the following Trivy command:
//
//	trivy --cache-dir /tmp/trivy/.cache image --download-db-only
//
// The number of main containers correspond to the number of containers
// defined for the scanned workload. Each container runs the Trivy image scan
// command and skips the database download:
//
//	trivy --cache-dir /tmp/trivy/.cache image --skip-update \
//	  --format json <container image>
func GetPodSpecForStandaloneMode(ctx trivyoperator.PluginContext,
	config Config,
	workload client.Object,
	credentials map[string]docker.Auth,
	securityContext *corev1.SecurityContext,
	p *plugin,
	clusterSboms map[string]v1alpha1.SbomReportData) (corev1.PodSpec, []*corev1.Secret, error) {
	var secret *corev1.Secret
	var secrets []*corev1.Secret
	var containersSpec []corev1.Container

	spec, err := kube.GetPodSpec(workload)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	for _, c := range getContainers(spec) {
		optionalMirroredImage, err := GetMirroredImage(c.Image, config.GetMirrors())
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		c.Image = optionalMirroredImage
		containersSpec = append(containersSpec, c)
	}

	containerImages := kube.GetContainerImagesFromContainersList(containersSpec)
	containersCredentials, err := kube.MapContainerNamesToDockerAuths(containerImages, credentials)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	if len(containersCredentials) > 0 {
		secret = p.newSecretWithAggregateImagePullCredentials(workload, containerImages, containersCredentials)
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

	cacheDir := config.GetImageScanCacheDir()

	initContainer := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    trivyImageRef,
		ImagePullPolicy:          corev1.PullPolicy(config.GetImagePullPolicy()),
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Env:                      initContainerEnvVar(trivyConfigName, config),
		Command: []string{
			"trivy",
		},
		Args: []string{
			"--cache-dir",
			cacheDir,
			"image",
			"--download-db-only",
			"--db-repository",
			dbRepository,
		},
		Resources:       requirements,
		SecurityContext: securityContext,
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
	volumeMounts = append(volumeMounts, getScanResultVolumeMount())
	volumes = append(volumes, getScanResultVolume())

	if volume, volumeMount := config.GenerateIgnoreFileVolumeIfAvailable(trivyConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateIgnorePolicyVolumeIfAvailable(trivyConfigName, workload); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateSslCertDirVolumeIfAvailable(trivyConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}

	for _, c := range containersSpec {
		env := []corev1.EnvVar{
			constructEnvVarSourceFromConfigMap("TRIVY_SEVERITY", trivyConfigName, KeyTrivySeverity),
			constructEnvVarSourceFromConfigMap("TRIVY_IGNORE_UNFIXED", trivyConfigName, keyTrivyIgnoreUnfixed),
			constructEnvVarSourceFromConfigMap("TRIVY_OFFLINE_SCAN", trivyConfigName, keyTrivyOfflineScan),
			constructEnvVarSourceFromConfigMap("TRIVY_JAVA_DB_REPOSITORY", trivyConfigName, keyTrivyJavaDBRepository),
			constructEnvVarSourceFromConfigMap("TRIVY_TIMEOUT", trivyConfigName, keyTrivyTimeout),
			ConfigWorkloadAnnotationEnvVars(workload, SkipFilesAnnotation, "TRIVY_SKIP_FILES", trivyConfigName, keyTrivySkipFiles),
			ConfigWorkloadAnnotationEnvVars(workload, SkipDirsAnnotation, "TRIVY_SKIP_DIRS", trivyConfigName, keyTrivySkipDirs),
			constructEnvVarSourceFromConfigMap("HTTP_PROXY", trivyConfigName, keyTrivyHTTPProxy),
			constructEnvVarSourceFromConfigMap("HTTPS_PROXY", trivyConfigName, keyTrivyHTTPSProxy),
			constructEnvVarSourceFromConfigMap("NO_PROXY", trivyConfigName, keyTrivyNoProxy),
		}

		if len(config.GetSslCertDir()) > 0 {
			env = append(env, corev1.EnvVar{
				Name:  "SSL_CERT_DIR",
				Value: SslCertDir,
			})
		}
		if config.IgnoreFileExists() {
			env = append(env, corev1.EnvVar{
				Name:  "TRIVY_IGNOREFILE",
				Value: ignoreFileMountPath,
			})
		}
		if config.FindIgnorePolicyKey(workload) != "" {
			env = append(env, corev1.EnvVar{
				Name:  "TRIVY_IGNORE_POLICY",
				Value: ignorePolicyMountPath,
			})
		}

		region := CheckAwsEcrPrivateRegistry(c.Image)
		if region != "" {
			env = append(env, corev1.EnvVar{
				Name:  "AWS_REGION",
				Value: region,
			})
		}
		if config.GetDBRepositoryInsecure() {
			env = append(env, corev1.EnvVar{
				Name:  "TRIVY_INSECURE",
				Value: "true",
			})
		}
		gcrImage := checkGcpCrOrPivateRegistry(c.Image)
		if _, ok := containersCredentials[c.Name]; ok && secret != nil {
			registryUsernameKey := fmt.Sprintf("%s.username", c.Name)
			registryPasswordKey := fmt.Sprintf("%s.password", c.Name)
			secretName := secret.Name
			if gcrImage {
				createEnvandVolumeForGcr(&env, &volumeMounts, &volumes, &registryPasswordKey, &secretName)
			} else {
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

		}

		env, err = appendTrivyInsecureEnv(config, c.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		env, err = appendTrivyNonSSLEnv(config, c.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		resourceRequirements, err := config.GetResourceRequirements()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		imageRef, err := containerimage.ParseReference(c.Image)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		resultFileName := getUniqueScanResultFileName(c.Name)
		cmd, args := getCommandAndArgs(ctx, Standalone, imageRef.String(), "", resultFileName)
		if len(clusterSboms) > 0 { // trivy sbom ...
			if sbomreportData, ok := clusterSboms[c.Name]; ok {
				secretName := fmt.Sprintf("sbom-%s", c.Name)
				secret, err := CreateSbomDataAsSecret(sbomreportData.Bom, secretName)
				if err != nil {
					return corev1.PodSpec{}, nil, err
				}
				secrets = append(secrets, &secret)
				fileName := fmt.Sprintf("%s.json", secretName)
				CreateVolumeSbomFiles(&volumeMounts, &volumes, &secretName, fileName)
				cmd, args = GetSbomScanCommandAndArgs(ctx, Standalone, fmt.Sprintf("/sbom/%s", fileName), "", resultFileName)
			}
		}
		containers = append(containers, corev1.Container{
			Name:                     c.Name,
			Image:                    trivyImageRef,
			ImagePullPolicy:          corev1.PullPolicy(config.GetImagePullPolicy()),
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command:                  cmd,
			Args:                     args,
			Resources:                resourceRequirements,
			SecurityContext:          securityContext,
			VolumeMounts:             volumeMounts,
		})
	}

	return corev1.PodSpec{
		Affinity:                     trivyoperator.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: ptr.To[bool](getAutomountServiceAccountToken(ctx)),
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
//	trivy image --server <server URL> \
//	  --format json <container image>
func GetPodSpecForClientServerMode(ctx trivyoperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext, p *plugin, clusterSboms map[string]v1alpha1.SbomReportData) (corev1.PodSpec, []*corev1.Secret, error) {
	var secret *corev1.Secret
	var secrets []*corev1.Secret
	var containersSpec []corev1.Container
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

	for _, c := range getContainers(spec) {
		optionalMirroredImage, err := GetMirroredImage(c.Image, config.GetMirrors())
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		c.Image = optionalMirroredImage
		containersSpec = append(containersSpec, c)
	}

	containerImages := kube.GetContainerImagesFromContainersList(containersSpec)
	containersCredentials, err := kube.MapContainerNamesToDockerAuths(containerImages, credentials)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	if len(containersCredentials) > 0 {
		secret = p.newSecretWithAggregateImagePullCredentials(workload, containerImages, containersCredentials)
		secrets = append(secrets, secret)
	}

	var containers []corev1.Container

	trivyConfigName := trivyoperator.GetPluginConfigMapName(Plugin)
	// add tmp volume mount
	volumeMounts := []corev1.VolumeMount{
		{
			Name:      tmpVolumeName,
			ReadOnly:  false,
			MountPath: "/tmp",
		},
	}

	// add tmp volume
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

	volumeMounts = append(volumeMounts, getScanResultVolumeMount())
	volumes = append(volumes, getScanResultVolume())

	if volume, volumeMount := config.GenerateIgnoreFileVolumeIfAvailable(trivyConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateIgnorePolicyVolumeIfAvailable(trivyConfigName, workload); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}

	if volume, volumeMount := config.GenerateSslCertDirVolumeIfAvailable(trivyConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}

	for _, container := range containersSpec {
		env := []corev1.EnvVar{
			constructEnvVarSourceFromConfigMap("HTTP_PROXY", trivyConfigName, keyTrivyHTTPProxy),
			constructEnvVarSourceFromConfigMap("HTTPS_PROXY", trivyConfigName, keyTrivyHTTPSProxy),
			constructEnvVarSourceFromConfigMap("NO_PROXY", trivyConfigName, keyTrivyNoProxy),
			constructEnvVarSourceFromConfigMap("TRIVY_SEVERITY", trivyConfigName, KeyTrivySeverity),
			constructEnvVarSourceFromConfigMap("TRIVY_IGNORE_UNFIXED", trivyConfigName, keyTrivyIgnoreUnfixed),
			constructEnvVarSourceFromConfigMap("TRIVY_OFFLINE_SCAN", trivyConfigName, keyTrivyOfflineScan),
			constructEnvVarSourceFromConfigMap("TRIVY_JAVA_DB_REPOSITORY", trivyConfigName, keyTrivyJavaDBRepository),
			constructEnvVarSourceFromConfigMap("TRIVY_TIMEOUT", trivyConfigName, keyTrivyTimeout),
			ConfigWorkloadAnnotationEnvVars(workload, SkipFilesAnnotation, "TRIVY_SKIP_FILES", trivyConfigName, keyTrivySkipFiles),
			ConfigWorkloadAnnotationEnvVars(workload, SkipDirsAnnotation, "TRIVY_SKIP_DIRS", trivyConfigName, keyTrivySkipDirs),
			constructEnvVarSourceFromConfigMap("TRIVY_TOKEN_HEADER", trivyConfigName, keyTrivyServerTokenHeader),
			constructEnvVarSourceFromSecret("TRIVY_TOKEN", trivyConfigName, keyTrivyServerToken),
			constructEnvVarSourceFromSecret("TRIVY_CUSTOM_HEADERS", trivyConfigName, keyTrivyServerCustomHeaders),
		}
		if len(config.GetSslCertDir()) > 0 {
			env = append(env, corev1.EnvVar{
				Name:  "SSL_CERT_DIR",
				Value: SslCertDir,
			})
		}
		if config.IgnoreFileExists() {
			env = append(env, corev1.EnvVar{
				Name:  "TRIVY_IGNOREFILE",
				Value: ignoreFileMountPath,
			})
		}
		if config.FindIgnorePolicyKey(workload) != "" {
			env = append(env, corev1.EnvVar{
				Name:  "TRIVY_IGNORE_POLICY",
				Value: ignorePolicyMountPath,
			})
		}
		// fmt.Sprintf("sbom-%s.json", imageName),
		//createVolumeSbomFiles(&volumeMounts, &volumes, &registryServiceAccountAuthKey, &secret.Name)

		region := CheckAwsEcrPrivateRegistry(container.Image)
		if region != "" {
			env = append(env, corev1.EnvVar{
				Name:  "AWS_REGION",
				Value: region,
			})
		}

		if auth, ok := containersCredentials[container.Name]; ok && secret != nil {
			if checkGcpCrOrPivateRegistry(container.Image) && auth.Username == "_json_key" {
				registryServiceAccountAuthKey := fmt.Sprintf("%s.password", container.Name)
				createEnvandVolumeForGcr(&env, &volumeMounts, &volumes, &registryServiceAccountAuthKey, &secret.Name)
			} else {
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
		}

		env, err = appendTrivyInsecureEnv(config, container.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		env, err = appendTrivyNonSSLEnv(config, container.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		if config.GetServerInsecure() {
			env = append(env, corev1.EnvVar{
				Name:  "TRIVY_INSECURE",
				Value: "true",
			})
		}
		if config.GetDBRepositoryInsecure() {
			env = append(env, corev1.EnvVar{
				Name:  "TRIVY_INSECURE",
				Value: "true",
			})
		}
		requirements, err := config.GetResourceRequirements()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		encodedTrivyServerURL, err := url.Parse(trivyServerURL)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		imageRef, err := containerimage.ParseReference(container.Image)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		resultFileName := getUniqueScanResultFileName(container.Name)
		cmd, args := getCommandAndArgs(ctx, ClientServer, imageRef.String(), encodedTrivyServerURL.String(), resultFileName)
		if len(clusterSboms) > 0 { // trivy sbom ...
			if sbomreportData, ok := clusterSboms[container.Name]; ok {
				secretName := fmt.Sprintf("sbom-%s", container.Name)
				secret, err := CreateSbomDataAsSecret(sbomreportData.Bom, secretName)
				if err != nil {
					return corev1.PodSpec{}, nil, err
				}
				secrets = append(secrets, &secret)
				fileName := fmt.Sprintf("%s.json", secretName)
				CreateVolumeSbomFiles(&volumeMounts, &volumes, &secretName, fileName)
				cmd, args = GetSbomScanCommandAndArgs(ctx, ClientServer, fmt.Sprintf("/sbom/%s", fileName), "", resultFileName)
			}
		}
		containers = append(containers, corev1.Container{
			Name:                     container.Name,
			Image:                    trivyImageRef,
			ImagePullPolicy:          corev1.PullPolicy(config.GetImagePullPolicy()),
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command:                  cmd,
			Args:                     args,
			Resources:                requirements,
			SecurityContext:          securityContext,
			VolumeMounts:             volumeMounts,
		})
	}

	return corev1.PodSpec{
		Affinity:                     trivyoperator.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: ptr.To[bool](getAutomountServiceAccountToken(ctx)),
		Containers:                   containers,
		Volumes:                      volumes,
	}, secrets, nil
}

func initContainerEnvVar(trivyConfigName string, config Config) []corev1.EnvVar {
	envs := []corev1.EnvVar{
		constructEnvVarSourceFromConfigMap("HTTP_PROXY", trivyConfigName, keyTrivyHTTPProxy),
		constructEnvVarSourceFromConfigMap("HTTPS_PROXY", trivyConfigName, keyTrivyHTTPSProxy),
		constructEnvVarSourceFromConfigMap("NO_PROXY", trivyConfigName, keyTrivyNoProxy),
		constructEnvVarSourceFromSecret("GITHUB_TOKEN", trivyConfigName, keyTrivyGitHubToken),
	}
	if config.TrivyDBRepositoryCredentialsSet() {
		envs = append(envs, []corev1.EnvVar{
			constructEnvVarSourceFromSecret("TRIVY_USERNAME", trivyConfigName, keyTrivyDBRepositoryUsername),
			constructEnvVarSourceFromSecret("TRIVY_PASSWORD", trivyConfigName, keyTrivyDBRepositoryPassword),
		}...)
	}

	if config.GetDBRepositoryInsecure() {
		envs = append(envs, corev1.EnvVar{
			Name:  "TRIVY_INSECURE",
			Value: "true",
		})
	}
	return envs
}

func getCommandAndArgs(ctx trivyoperator.PluginContext, mode Mode, imageRef string, trivyServerURL string, resultFileName string) ([]string, []string) {
	command := []string{
		"trivy",
	}
	trivyConfig := ctx.GetTrivyOperatorConfig()
	compressLogs := trivyConfig.CompressLogs()
	c, err := getConfig(ctx)
	if err != nil {
		return []string{}, []string{}
	}
	slow := Slow(c)
	skipJavaDBUpdate := SkipJavaDBUpdate(c)
	cacheDir := c.GetImageScanCacheDir()
	vulnTypeArgs := vulnTypeFilter(ctx)
	scanners := Scanners(c)
	var vulnTypeFlag string
	if len(vulnTypeArgs) == 2 {
		vulnTypeFlag = fmt.Sprintf("%s %s ", vulnTypeArgs[0], vulnTypeArgs[1])
	}
	imcs := imageConfigSecretScanner(trivyConfig)
	var imageconfigSecretScannerFlag string
	if len(imcs) == 2 {
		imageconfigSecretScannerFlag = fmt.Sprintf("%s %s ", imcs[0], imcs[1])
	}
	var skipUpdate string
	if c.GetClientServerSkipUpdate() && mode == ClientServer {
		skipUpdate = SkipDBUpdate(c)
	} else if mode != ClientServer {
		skipUpdate = SkipDBUpdate(c)
	}
	if !compressLogs {
		args := []string{
			"--cache-dir",
			cacheDir,
			"--quiet",
			"image",
			scanners,
			getSecurityChecks(ctx),
			"--format",
			"json",
		}
		if len(trivyServerURL) > 0 {
			args = append(args, []string{"--server", trivyServerURL}...)
		}
		args = append(args, imageRef)

		if len(slow) > 0 {
			args = append(args, slow)
		}
		if len(vulnTypeArgs) > 0 {
			args = append(args, vulnTypeArgs...)
		}
		if len(imcs) > 0 {
			args = append(args, imcs...)
		}
		pkgList := getPkgList(ctx)
		if len(pkgList) > 0 {
			args = append(args, pkgList)
		}
		if len(skipUpdate) > 0 {
			args = append(args, skipUpdate)
		}
		if len(skipJavaDBUpdate) > 0 {
			args = append(args, skipJavaDBUpdate)
		}

		return command, args
	}
	var serverUrlParms string
	if mode == ClientServer {
		serverUrlParms = fmt.Sprintf("--server '%s' ", trivyServerURL)
	}
	return []string{"/bin/sh"}, []string{"-c", fmt.Sprintf(`trivy image %s '%s' %s %s %s %s %s %s --cache-dir %s --quiet %s --format json %s> /tmp/scan/%s &&  bzip2 -c /tmp/scan/%s | base64`, slow, imageRef, scanners, getSecurityChecks(ctx), imageconfigSecretScannerFlag, vulnTypeFlag, skipUpdate, skipJavaDBUpdate, cacheDir, getPkgList(ctx), serverUrlParms, resultFileName, resultFileName)}
}

func GetSbomScanCommandAndArgs(ctx trivyoperator.PluginContext, mode Mode, sbomFile string, trivyServerURL string, resultFileName string) ([]string, []string) {
	command := []string{
		"trivy",
	}
	trivyConfig := ctx.GetTrivyOperatorConfig()
	compressLogs := trivyConfig.CompressLogs()
	c, err := getConfig(ctx)
	if err != nil {
		return []string{}, []string{}
	}
	slow := Slow(c)
	vulnTypeArgs := vulnTypeFilter(ctx)
	var vulnTypeFlag string
	if len(vulnTypeArgs) == 2 {
		vulnTypeFlag = fmt.Sprintf("%s %s ", vulnTypeArgs[0], vulnTypeArgs[1])
	}

	var skipUpdate string
	if c.GetClientServerSkipUpdate() && mode == ClientServer {
		skipUpdate = SkipDBUpdate(c)
	} else if mode != ClientServer {
		skipUpdate = SkipDBUpdate(c)
	}
	if !compressLogs {
		args := []string{
			"--cache-dir",
			"/tmp/trivy/.cache",
			"--quiet",
			"sbom",
			"--format",
			"json",
		}

		if len(trivyServerURL) > 0 {
			args = append(args, []string{"--server", trivyServerURL}...)
		}
		args = append(args, sbomFile)
		if len(slow) > 0 {
			args = append(args, slow)
		}
		if len(vulnTypeArgs) > 0 {
			args = append(args, vulnTypeArgs...)
		}
		if len(skipUpdate) > 0 {
			args = append(args, skipUpdate)
		}
		return command, args
	}
	var serverUrlParms string
	if mode == ClientServer {
		serverUrlParms = fmt.Sprintf("--server '%s' ", trivyServerURL)
	}
	return []string{"/bin/sh"}, []string{"-c", fmt.Sprintf(`trivy sbom %s %s %s %s  --cache-dir /tmp/trivy/.cache --quiet --format json %s> /tmp/scan/%s &&  bzip2 -c /tmp/scan/%s | base64`, slow, sbomFile, vulnTypeFlag, skipUpdate, serverUrlParms, resultFileName, resultFileName)}
}

func vulnTypeFilter(ctx trivyoperator.PluginContext) []string {
	config, err := getConfig(ctx)
	if err != nil {
		return []string{}
	}
	vulnType := config.GetVulnType()
	if len(vulnType) == 0 {
		return []string{}
	}
	return []string{"--vuln-type", vulnType}
}

func appendTrivyNonSSLEnv(config Config, image string, env []corev1.EnvVar) ([]corev1.EnvVar, error) {
	ref, err := containerimage.ParseReference(image)
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

func createEnvandVolumeForGcr(env *[]corev1.EnvVar, volumeMounts *[]corev1.VolumeMount, volumes *[]corev1.Volume, registryPasswordKey *string, secretName *string) {
	*env = append(*env, corev1.EnvVar{
		Name:  "TRIVY_USERNAME",
		Value: "",
	})
	*env = append(*env, corev1.EnvVar{
		Name:  "GOOGLE_APPLICATION_CREDENTIALS",
		Value: "/cred/credential.json",
	})
	googlecredMount := corev1.VolumeMount{
		Name:      "gcrvol",
		MountPath: "/cred",
		ReadOnly:  true,
	}
	googlecredVolume := corev1.Volume{
		Name: "gcrvol",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: *secretName,
				Items: []corev1.KeyToPath{
					{
						Key:  *registryPasswordKey,
						Path: "credential.json",
					},
				},
			},
		},
	}
	*volumes = append(*volumes, googlecredVolume)
	*volumeMounts = append(*volumeMounts, googlecredMount)
}

func checkGcpCrOrPivateRegistry(imageUrl string) bool {
	imageRegex := regexp.MustCompile(GCPCR_Inage_Regex)
	return imageRegex.MatchString(imageUrl)
}

func getUniqueScanResultFileName(name string) string {
	return fmt.Sprintf("result_%s.json", name)
}

func CheckAwsEcrPrivateRegistry(ImageUrl string) string {
	if len(regexp.MustCompile(AWSECR_Image_Regex).FindAllStringSubmatch(ImageUrl, -1)) != 0 {
		return regexp.MustCompile(AWSECR_Image_Regex).FindAllStringSubmatch(ImageUrl, -1)[0][1]
	}
	return ""
}

func GetMirroredImage(image string, mirrors map[string]string) (string, error) {
	ref, err := containerimage.ParseReference(image)
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

func (p *plugin) newSecretWithAggregateImagePullCredentials(obj client.Object, containerImages kube.ContainerImages, credentials map[string]docker.Auth) *corev1.Secret {
	secretData := kube.AggregateImagePullSecretsData(containerImages, credentials)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: vulnerabilityreport.RegistryCredentialsSecretName(obj),
		},
		Data: secretData,
	}
}
