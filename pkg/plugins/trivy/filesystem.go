package trivy

import (
	"context"
	"fmt"
	"net/url"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/docker"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type FileSystemJobSpecMgr struct {
	getPodSpecFunc GetPodSpecFunc
}

func NewFileSystemJobSpecMgr() PodSpecMgr {
	return &FileSystemJobSpecMgr{}
}

func (j *FileSystemJobSpecMgr) GetPodSpec(ctx trivyoperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext, p *plugin, clusterSboms map[string]v1alpha1.SbomReportData) (corev1.PodSpec, []*corev1.Secret, error) {
	return j.getPodSpecFunc(ctx, config, workload, credentials, securityContext, p, clusterSboms)
}

// FileSystem scan option with standalone mode.
// The only difference is that instead of scanning the resource by name,
// We are scanning the resource place on a specific file system location using the following command.
//
//	trivy --quiet fs  --format json --ignore-unfixed  file/system/location
func GetPodSpecForStandaloneFSMode(ctx trivyoperator.PluginContext, config Config, workload client.Object, _ map[string]docker.Auth, securityContext *corev1.SecurityContext, p *plugin, clusterSboms map[string]v1alpha1.SbomReportData) (corev1.PodSpec, []*corev1.Secret, error) {
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

	cacheDir := config.GetFilesystemScanCacheDir()

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      FsSharedVolumeName,
			ReadOnly:  false,
			MountPath: "/var/trivyoperator",
		},
		{
			Name:      tmpVolumeName,
			MountPath: "/tmp",
			ReadOnly:  false,
		},
	}

	initContainerCopyBinary := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    trivyImageRef,
		ImagePullPolicy:          corev1.PullPolicy(config.GetImagePullPolicy()),
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Command: []string{
			"cp",
			"-v",
			"/usr/local/bin/trivy",
			SharedVolumeLocationOfTrivy,
		},
		Resources:       requirements,
		SecurityContext: securityContext,
		VolumeMounts:    volumeMounts,
	}

	initContainerDB := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    trivyImageRef,
		ImagePullPolicy:          corev1.PullPolicy(config.GetImagePullPolicy()),
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Env:                      initContainerFSEnvVar(trivyConfigName, config),
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
		VolumeMounts:    volumeMounts,
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

	for _, c := range getContainers(spec) {
		env := []corev1.EnvVar{
			constructEnvVarSourceFromConfigMap("TRIVY_SEVERITY", trivyConfigName, KeyTrivySeverity),
			ConfigWorkloadAnnotationEnvVars(workload, SkipFilesAnnotation, "TRIVY_SKIP_FILES", trivyConfigName, keyTrivySkipFiles),
			ConfigWorkloadAnnotationEnvVars(workload, SkipDirsAnnotation, "TRIVY_SKIP_DIRS", trivyConfigName, keyTrivySkipDirs),
			constructEnvVarSourceFromConfigMap("HTTP_PROXY", trivyConfigName, keyTrivyHTTPProxy),
			constructEnvVarSourceFromConfigMap("TRIVY_TIMEOUT", trivyConfigName, keyTrivyTimeout),
			constructEnvVarSourceFromConfigMap("HTTPS_PROXY", trivyConfigName, keyTrivyHTTPSProxy),
			constructEnvVarSourceFromConfigMap("NO_PROXY", trivyConfigName, keyTrivyNoProxy),
			constructEnvVarSourceFromConfigMap("TRIVY_JAVA_DB_REPOSITORY", trivyConfigName, keyTrivyJavaDBRepository),
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
		if config.IgnoreUnfixed() {
			env = append(env, constructEnvVarSourceFromConfigMap("TRIVY_IGNORE_UNFIXED",
				trivyConfigName, keyTrivyIgnoreUnfixed))
		}
		if config.GetDBRepositoryInsecure() {
			env = append(env, corev1.EnvVar{
				Name:  "TRIVY_INSECURE",
				Value: "true",
			})
		}

		if config.OfflineScan() {
			env = append(env, constructEnvVarSourceFromConfigMap("TRIVY_OFFLINE_SCAN",
				trivyConfigName, keyTrivyOfflineScan))
		}

		env, err = appendTrivyInsecureEnv(config, c.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		resourceRequirements, err := config.GetResourceRequirements()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		config, err := getConfig(ctx)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		command := config.GetCommand()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		fscommand := []string{SharedVolumeLocationOfTrivy}
		args := GetFSScanningArgs(ctx, command, Standalone, "")
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
				fscommand, args = GetSbomFSScanningArgs(ctx, Standalone, "", fmt.Sprintf("/sbom/%s", fileName))
			}
		}
		containers = append(containers, corev1.Container{
			Name:                     c.Name,
			Image:                    c.Image,
			ImagePullPolicy:          pullPolicy,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command:                  fscommand,
			Args:                     args,
			Resources:                resourceRequirements,
			SecurityContext:          securityContext,
			VolumeMounts:             volumeMounts,
		})
	}

	podSpec := corev1.PodSpec{
		Affinity:                     trivyoperator.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: ptr.To[bool](getAutomountServiceAccountToken(ctx)),
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

// FileSystem scan option with ClientServer mode.
// The only difference is that instead of scanning the resource by name,
// We scanning the resource place on a specific file system location using the following command.
//
//	trivy --quiet fs  --server TRIVY_SERVER  --format json --ignore-unfixed  file/system/location
func GetPodSpecForClientServerFSMode(ctx trivyoperator.PluginContext, config Config, workload client.Object, _ map[string]docker.Auth, securityContext *corev1.SecurityContext, p *plugin, clusterSboms map[string]v1alpha1.SbomReportData) (corev1.PodSpec, []*corev1.Secret, error) {
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

	trivyServerURL, err := config.GetServerURL()
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	encodedTrivyServerURL, err := url.Parse(trivyServerURL)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}

	trivyConfigName := trivyoperator.GetPluginConfigMapName(Plugin)

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
		{
			Name:      tmpVolumeName,
			MountPath: "/tmp",
			ReadOnly:  false,
		},
	}

	initContainerCopyBinary := corev1.Container{
		Name:                     p.idGenerator.GenerateID(),
		Image:                    trivyImageRef,
		ImagePullPolicy:          corev1.PullPolicy(config.GetImagePullPolicy()),
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		Command: []string{
			"cp",
			"-v",
			"/usr/local/bin/trivy",
			SharedVolumeLocationOfTrivy,
		},
		Resources:       requirements,
		SecurityContext: securityContext,
		VolumeMounts:    volumeMounts,
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

	for _, c := range getContainers(spec) {
		env := []corev1.EnvVar{
			constructEnvVarSourceFromConfigMap("TRIVY_SEVERITY", trivyConfigName, KeyTrivySeverity),
			ConfigWorkloadAnnotationEnvVars(workload, SkipFilesAnnotation, "TRIVY_SKIP_FILES", trivyConfigName, keyTrivySkipFiles),
			ConfigWorkloadAnnotationEnvVars(workload, SkipDirsAnnotation, "TRIVY_SKIP_DIRS", trivyConfigName, keyTrivySkipDirs),
			constructEnvVarSourceFromConfigMap("HTTP_PROXY", trivyConfigName, keyTrivyHTTPProxy),
			constructEnvVarSourceFromConfigMap("TRIVY_TIMEOUT", trivyConfigName, keyTrivyTimeout),
			constructEnvVarSourceFromConfigMap("HTTPS_PROXY", trivyConfigName, keyTrivyHTTPSProxy),
			constructEnvVarSourceFromConfigMap("NO_PROXY", trivyConfigName, keyTrivyNoProxy),
			constructEnvVarSourceFromConfigMap("TRIVY_TOKEN_HEADER", trivyConfigName, keyTrivyServerTokenHeader),
			constructEnvVarSourceFromSecret("TRIVY_TOKEN", trivyConfigName, keyTrivyServerToken),
			constructEnvVarSourceFromSecret("TRIVY_CUSTOM_HEADERS", trivyConfigName, keyTrivyServerCustomHeaders),
			constructEnvVarSourceFromConfigMap("TRIVY_JAVA_DB_REPOSITORY", trivyConfigName, keyTrivyJavaDBRepository),
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
		if config.IgnoreUnfixed() {
			env = append(env, constructEnvVarSourceFromConfigMap("TRIVY_IGNORE_UNFIXED",
				trivyConfigName, keyTrivyIgnoreUnfixed))
		}

		if config.OfflineScan() {
			env = append(env, constructEnvVarSourceFromConfigMap("TRIVY_OFFLINE_SCAN",
				trivyConfigName, keyTrivyOfflineScan))
		}

		env, err = appendTrivyInsecureEnv(config, c.Image, env)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		if config.GetServerInsecure() {
			env = append(env, corev1.EnvVar{
				Name:  "TRIVY_INSECURE",
				Value: "true",
			})
		}

		resourceRequirements, err := config.GetResourceRequirements()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		config, err := getConfig(ctx)
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}
		command := config.GetCommand()
		if err != nil {
			return corev1.PodSpec{}, nil, err
		}

		fscommand := []string{SharedVolumeLocationOfTrivy}
		args := GetFSScanningArgs(ctx, command, ClientServer, encodedTrivyServerURL.String())
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
				fscommand, args = GetSbomFSScanningArgs(ctx, ClientServer, encodedTrivyServerURL.String(), fmt.Sprintf("/sbom/%s", fileName))
			}
		}
		containers = append(containers, corev1.Container{
			Name:                     c.Name,
			Image:                    c.Image,
			ImagePullPolicy:          pullPolicy,
			TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			Env:                      env,
			Command:                  fscommand,
			Args:                     args,
			Resources:                resourceRequirements,
			SecurityContext:          securityContext,
			VolumeMounts:             volumeMounts,
		})
	}

	podSpec := corev1.PodSpec{
		Affinity:                     trivyoperator.LinuxNodeAffinity(),
		RestartPolicy:                corev1.RestartPolicyNever,
		ServiceAccountName:           ctx.GetServiceAccountName(),
		AutomountServiceAccountToken: ptr.To[bool](getAutomountServiceAccountToken(ctx)),
		Volumes:                      volumes,
		InitContainers:               []corev1.Container{initContainerCopyBinary},
		Containers:                   containers,
		SecurityContext:              &corev1.PodSecurityContext{},
	}

	if !ctx.GetTrivyOperatorConfig().VulnerabilityScanJobsInSameNamespace() {
		// schedule scan job explicitly on specific node.
		podSpec.NodeName = nodeName
	}

	return podSpec, secrets, nil
}

func GetFSScanningArgs(ctx trivyoperator.PluginContext, command Command, mode Mode, trivyServerURL string) []string {
	c, err := getConfig(ctx)
	if err != nil {
		return []string{}
	}
	scanners := Scanners(c)
	imcs := imageConfigSecretScanner(c.Data)
	skipUpdate := SkipDBUpdate(c)
	cacheDir := c.GetFilesystemScanCacheDir()
	args := []string{
		"--cache-dir",
		cacheDir,
		"--quiet",
		string(command),
		scanners,
		getSecurityChecks(ctx),
		skipUpdate,
		"--format",
		"json",
		"/",
	}
	if len(imcs) > 0 {
		args = append(args, imcs...)
	}
	if mode == ClientServer {
		args = append(args, "--server", trivyServerURL)
	}
	slow := Slow(c)
	if len(slow) > 0 {
		args = append(args, slow)
	}

	if c.GetIncludeDevDeps() && command == Filesystem {
		args = append(args, "--include-dev-deps")
	}

	pkgList := getPkgList(ctx)
	if len(pkgList) > 0 {
		args = append(args, pkgList)
	}
	return args
}

func GetSbomFSScanningArgs(ctx trivyoperator.PluginContext, mode Mode, trivyServerURL string, sbomFile string) ([]string, []string) {
	command := []string{
		SharedVolumeLocationOfTrivy,
	}
	c, err := getConfig(ctx)
	if err != nil {
		return []string{}, []string{}
	}
	skipUpdate := SkipDBUpdate(c)
	cacheDir := c.GetFilesystemScanCacheDir()
	args := []string{
		"--cache-dir",
		cacheDir,
		"--quiet",
		"sbom",
		"--format",
		"json",
		skipUpdate,
		sbomFile,
	}

	if mode == ClientServer {
		args = append(args, "--server", trivyServerURL)
	}
	slow := Slow(c)
	if len(slow) > 0 {
		args = append(args, slow)
	}
	return command, args
}

func initContainerFSEnvVar(trivyConfigName string, config Config) []corev1.EnvVar {
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
