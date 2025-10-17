package trivy

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	containerimage "github.com/google/go-containerregistry/pkg/name"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/docker"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
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

// GetPodSpec creates a PodSpec for the Trivy image scan job.
//
// The number of main containers correspond to the number of containers
// defined for the scanned workload. Each container runs the Trivy image scan
// command and skips the database download.
//
//	trivy --cache-dir /tmp/trivy/.cache image --skip-update \
//	  --format json <container image>
//
// In the Standalone mode there is the init container responsible for
// downloading the latest Trivy DB file from GitHub and storing it to the
// emptyDir volume shared with main containers. In other words, the init
// container runs the following Trivy command:
//
//	trivy --cache-dir /tmp/trivy/.cache image --download-db-only
//
// In the ClientServer each container runs Trivy image scan command and refers to Trivy server URL
// returned by Config.GetServerURL:
//
//		trivy image --server <server URL> \
//		  --format json <container image>
//
//	 Also there is the init container responsible for downloading the latest Trivy Java DB for both modes
//
//		trivy --cache-dir /tmp/trivy/.cache image --download-java-db-only
func GetPodSpecForImageScan(ctx trivyoperator.PluginContext,
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

	cacheDir := config.GetImageScanCacheDir()
	args := []string{
		"--cache-dir",
		cacheDir,
		"image",
	}

	trivyConfigName := trivyoperator.GetPluginConfigMapName(Plugin)

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
	if volume, volumeMount := config.GenerateSslCertDirVolumeIfAvailable(trivyConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}

	if volume, volumeMount := config.GenerateConfigFileVolumeIfAvailable(trivyConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
		args = append(args, "--config", configFileMountPath)
	}

	var initContainers []corev1.Container

	trivyImageRef, err := config.GetImageRef()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	resourceRequirements, err := config.GetResourceRequirements()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	dockerConfigPath := ""

	if config.TrivyDBRepositoryCredentialsSet() {
		dockerConfigPath = "/docker-config/"

		dockerConfigVolumeMount := []corev1.VolumeMount{
			{
				Name:      dockerConfigVolumeName,
				ReadOnly:  false,
				MountPath: dockerConfigPath,
			},
		}
		dockerConfigVolume := []corev1.Volume{
			{
				Name: dockerConfigVolumeName,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{
						Medium: corev1.StorageMediumDefault,
					},
				},
			},
		}
		volumes = append(volumes, dockerConfigVolume...)
		volumeMounts = append(volumeMounts, dockerConfigVolumeMount...)

		dbRepository, err := config.GetDBRepository()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		javaDbRegistry, err := containerimage.ParseReference(dbRepository)
		if err != nil {
			return corev1.PodSpec{}, nil, fmt.Errorf("failed to parse db registry image: %w", err)
		}

		initContainers = append(initContainers, corev1.Container{
			Name:                     p.idGenerator.GenerateID(),
			Image:                    trivyImageRef,
			ImagePullPolicy:          corev1.PullPolicy(config.GetImagePullPolicy()),
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      initContainerEnvVar(trivyConfigName, config, dockerConfigPath),
			Command: []string{
				"trivy",
			},
			Args:            []string{"registry", "login", javaDbRegistry.Context().Registry.Name()}, // TRIVY_USERNAME and TRIVY_PASSWORD are set up in initContainerEnvVar()
			Resources:       resourceRequirements,
			SecurityContext: securityContext,
			VolumeMounts:    volumeMounts,
		})
	}

	mode := config.GetMode()

	if mode == Standalone {
		// prepare Trivy DB
		dbRepository, err := config.GetDBRepository()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		initContainers = append(initContainers, corev1.Container{
			Name:                     p.idGenerator.GenerateID(),
			Image:                    trivyImageRef,
			ImagePullPolicy:          corev1.PullPolicy(config.GetImagePullPolicy()),
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      initContainerEnvVar(trivyConfigName, config, dockerConfigPath),
			Command: []string{
				"trivy",
			},
			Args:            append(args, "--download-db-only", "--db-repository", dbRepository),
			Resources:       resourceRequirements,
			SecurityContext: securityContext,
			VolumeMounts:    volumeMounts,
		})
	}

	additionalVolumes, additionalVolumeMounts := getAdditionalVolumes(&config, trivyConfigName, workload)
	volumes = append(volumes, additionalVolumes...)
	volumeMounts = append(volumeMounts, additionalVolumeMounts...)

	trivyServerURL := ""
	if mode == ClientServer {
		sourceTrivyServerURL, err := config.GetServerURL()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		parsedTrivyServerURL, err := url.Parse(sourceTrivyServerURL)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		trivyServerURL = parsedTrivyServerURL.String()
	}

	containers := make([]corev1.Container, 0)

	for _, c := range containersSpec {
		if ExcludeImage(ctx.GetTrivyOperatorConfig().ExcludeImages(), c.Image) {
			continue
		}
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
		if dockerConfigPath != "" {
			env = append(env, corev1.EnvVar{
				Name:  "DOCKER_CONFIG",
				Value: dockerConfigPath,
			})
		}
		if mode == ClientServer {
			env = append(env,
				constructEnvVarSourceFromConfigMap("TRIVY_TOKEN_HEADER", trivyConfigName, keyTrivyServerTokenHeader),
				constructEnvVarSourceFromSecret("TRIVY_TOKEN", trivyConfigName, keyTrivyServerToken),
				constructEnvVarSourceFromSecret("TRIVY_CUSTOM_HEADERS", trivyConfigName, keyTrivyServerCustomHeaders),
			)
			if config.GetServerInsecure() {
				env = append(env, corev1.EnvVar{
					Name:  "TRIVY_INSECURE",
					Value: "true",
				})
			}
		}
		if config.GetSslCertDir() != "" {
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
		if config.GetDBRepositoryInsecure() {
			env = append(env, corev1.EnvVar{
				Name:  "TRIVY_INSECURE",
				Value: "true",
			})
		}

		region := CheckAwsEcrPrivateRegistry(c.Image)
		if region != "" {
			env = append(env, corev1.EnvVar{
				Name:  "AWS_REGION",
				Value: region,
			})
		}

		if _, ok := containersCredentials[c.Name]; ok && secret != nil {
			registryUsernameKey := fmt.Sprintf("%s.username", c.Name)
			registryPasswordKey := fmt.Sprintf("%s.password", c.Name)
			if CheckGcpCrOrPrivateRegistry(c.Image) &&
				ctx.GetTrivyOperatorConfig().GetScanJobUseGCRServiceAccount() {
				createEnvandVolumeForGcr(&env, &volumeMounts, &volumes, &registryPasswordKey, &secret.Name)
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

		imageRef, err := containerimage.ParseReference(c.Image)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		resultFileName := getUniqueScanResultFileName(c.Name)
		cmd, args := getCommandAndArgs(ctx, mode, imageRef.String(), trivyServerURL, resultFileName)
		if len(clusterSboms) > 0 { // trivy sbom ...
			if sbomreportData, ok := clusterSboms[c.Name]; ok {
				secretName := fmt.Sprintf("sbom-%s", c.Name)
				secret, err := CreateSbomDataAsSecret(sbomreportData.Bom, secretName)
				if err != nil {
					return corev1.PodSpec{}, nil, err
				}
				secrets = append(secrets, &secret)
				fileName := fmt.Sprintf("%s.json", secretName)
				mountPath := fmt.Sprintf("/sbom-%s", c.Name)
				CreateVolumeSbomFiles(&volumeMounts, &volumes, &secretName, fileName, mountPath, c.Name)
				cmd, args = GetSbomScanCommandAndArgs(ctx, mode, fmt.Sprintf("%s/%s", mountPath, fileName), trivyServerURL, resultFileName)
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
		Containers:                   containers,
		Volumes:                      volumes,
		InitContainers:               initContainers,
		SecurityContext:              &corev1.PodSecurityContext{},
	}, secrets, nil
}

func getAdditionalVolumes(config *Config, trivyConfigName string, workload client.Object) ([]corev1.Volume, []corev1.VolumeMount) {
	volumeMounts := []corev1.VolumeMount{getScanResultVolumeMount()}
	volumes := []corev1.Volume{getScanResultVolume()}

	if volume, volumeMount := config.GenerateIgnoreFileVolumeIfAvailable(trivyConfigName); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	if volume, volumeMount := config.GenerateIgnorePolicyVolumeIfAvailable(trivyConfigName, workload); volume != nil && volumeMount != nil {
		volumes = append(volumes, *volume)
		volumeMounts = append(volumeMounts, *volumeMount)
	}
	return volumes, volumeMounts
}

func initContainerEnvVar(trivyConfigName string, config Config, dockerConfigPath string) []corev1.EnvVar {
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
	if dockerConfigPath != "" {
		envs = append(envs, corev1.EnvVar{
			Name:  "DOCKER_CONFIG",
			Value: dockerConfigPath,
		})
	}
	return envs
}

func getCommandAndArgs(ctx trivyoperator.PluginContext, mode Mode, imageRef, trivyServerURL, resultFileName string) ([]string, []string) {
	trivyOperatorConfig := ctx.GetTrivyOperatorConfig()
	trivyConfig, err := getConfig(ctx)

	if err != nil {
		return []string{}, []string{}
	}

	// Arguments first.
	args := []string{
		"image",
		imageRef,
	}

	// Options in alphabetic order.
	cacheDir := trivyConfig.GetImageScanCacheDir()
	args = append(args, "--cache-dir", cacheDir, "--format", "json")

	imcs := imageConfigSecretScanner(trivyOperatorConfig)
	if len(imcs) > 0 {
		args = append(args, imcs...)
	}

	sbomSources := trivyConfig.GetSbomSources()
	if sbomSources != "" {
		args = append(args, []string{"--sbom-sources", sbomSources}...)
	}

	scanners := Scanners(trivyConfig)
	args = append(args, scanners, getSecurityChecks(ctx))

	if trivyServerURL != "" {
		args = append(args, []string{"--server", trivyServerURL}...)
	}

	var skipUpdate string
	if trivyConfig.GetClientServerSkipUpdate() && mode == ClientServer {
		skipUpdate = SkipDBUpdate(trivyConfig)
	} else if mode != ClientServer {
		skipUpdate = SkipDBUpdate(trivyConfig)
	}
	if skipUpdate != "" {
		args = append(args, skipUpdate)
	}

	skipJavaDBUpdate := SkipJavaDBUpdate(trivyConfig)
	if skipJavaDBUpdate != "" {
		args = append(args, skipJavaDBUpdate)
	}

	slow := Slow(trivyConfig)
	if slow != "" {
		args = append(args, slow)
	}

	vulnTypeArgs := vulnTypeFilter(ctx)
	if len(vulnTypeArgs) > 0 {
		args = append(args, vulnTypeArgs...)
	}

	pkgList := getPkgList(ctx)
	if pkgList != "" {
		args = append(args, pkgList)
	}

	if trivyConfig.ConfigFileExists() {
		args = append(args, "--config", configFileMountPath)
	}

	// Add command to args as it is now need to pipe output to compress.
	args = append([]string{"trivy"}, args...)
	args = append(args,
		"--output",
		fmt.Sprintf("/tmp/scan/%s 2>/tmp/scan/%s.log", resultFileName, resultFileName),
	)

	if trivyOperatorConfig.CompressLogs() {
		// Add compress arguments.
		args = append(args,
			fmt.Sprintf(`&& bzip2 -c /tmp/scan/%s | base64`, resultFileName),
		)
	} else {
		args = append(args,
			fmt.Sprintf(`&& cat /tmp/scan/%s`, resultFileName),
		)
	}

	return []string{"/bin/sh"}, append([]string{"-c"}, strings.Join(args, " "))
}

func GetSbomScanCommandAndArgs(ctx trivyoperator.PluginContext, mode Mode, sbomFile, trivyServerURL, resultFileName string) ([]string, []string) {
	trivyConfig := ctx.GetTrivyOperatorConfig()
	compressLogs := trivyConfig.CompressLogs()
	c, err := getConfig(ctx)
	if err != nil {
		return []string{}, []string{}
	}
	slow := Slow(c)

	var skipUpdate string
	if c.GetClientServerSkipUpdate() && mode == ClientServer {
		skipUpdate = SkipDBUpdate(c)
	} else if mode != ClientServer {
		skipUpdate = SkipDBUpdate(c)
	}
	args := []string{
		"trivy",
		"--cache-dir",
		"/tmp/trivy/.cache",
		"sbom",
		"--format",
		"json",
	}
	if mode == ClientServer && trivyServerURL != "" {
		args = append(args, "--server", trivyServerURL)
	}

	args = append(args, sbomFile)

	if slow != "" {
		args = append(args, slow)
	}

	vulnTypeArgs := vulnTypeFilter(ctx)
	if len(vulnTypeArgs) > 0 {
		args = append(args, vulnTypeArgs...)
	}

	if skipUpdate != "" {
		args = append(args, skipUpdate)
	}
	outputFile := fmt.Sprintf("/tmp/scan/%s", resultFileName)

	args = append(args, "--output", outputFile, fmt.Sprintf("2>/tmp/scan/%s.log", resultFileName))

	if compressLogs {
		args = append(args, fmt.Sprintf("&& bzip2 -c %s | base64", outputFile))
	} else {
		args = append(args, fmt.Sprintf("&& cat %s", outputFile))
	}
	return []string{"/bin/sh"}, append([]string{"-c"}, strings.Join(args, " "))
}

func vulnTypeFilter(ctx trivyoperator.PluginContext) []string {
	config, err := getConfig(ctx)
	if err != nil {
		return []string{}
	}
	vulnType := config.GetVulnType()
	if vulnType == "" {
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

func createEnvandVolumeForGcr(env *[]corev1.EnvVar, volumeMounts *[]corev1.VolumeMount, volumes *[]corev1.Volume, registryPasswordKey, secretName *string) {
	*env = append(*env,
		corev1.EnvVar{
			Name:  "TRIVY_USERNAME",
			Value: "",
		},
		corev1.EnvVar{
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

func CheckGcpCrOrPrivateRegistry(imageUrl string) bool {
	imageRegex := regexp.MustCompile(GCPCR_Image_Regex)
	return imageRegex.MatchString(imageUrl)
}

func getUniqueScanResultFileName(name string) string {
	return fmt.Sprintf("result_%s.json", name)
}

func CheckAwsEcrPrivateRegistry(imageURL string) string {
	if len(regexp.MustCompile(AWSECR_Image_Regex).FindAllStringSubmatch(imageURL, -1)) != 0 {
		return regexp.MustCompile(AWSECR_Image_Regex).FindAllStringSubmatch(imageURL, -1)[0][1]
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
			Labels: map[string]string{
				trivyoperator.LabelK8SAppManagedBy: trivyoperator.AppTrivyOperator,
			},
		},
		Data: secretData,
	}
}
