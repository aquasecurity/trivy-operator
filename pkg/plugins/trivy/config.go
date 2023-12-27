package trivy

import (
	"fmt"

	"path/filepath"

	"strconv"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/utils"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"

	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	keyTrivyImageRepository = "trivy.repository"
	keyTrivyImageTag        = "trivy.tag"
	//nolint:gosec
	keyTrivyImagePullSecret                     = "trivy.imagePullSecret"
	keyTrivyImagePullPolicy                     = "trivy.imagePullPolicy"
	keyTrivyMode                                = "trivy.mode"
	keyTrivyAdditionalVulnerabilityReportFields = "trivy.additionalVulnerabilityReportFields"
	keyTrivyCommand                             = "trivy.command"
	KeyTrivySeverity                            = "trivy.severity"
	keyTrivySlow                                = "trivy.slow"
	keyTrivyVulnType                            = "trivy.vulnType"
	keyTrivyIgnoreUnfixed                       = "trivy.ignoreUnfixed"
	keyTrivyOfflineScan                         = "trivy.offlineScan"
	keyTrivyTimeout                             = "trivy.timeout"
	keyTrivyIgnoreFile                          = "trivy.ignoreFile"
	keyTrivyIgnorePolicy                        = "trivy.ignorePolicy"
	keyTrivyInsecureRegistryPrefix              = "trivy.insecureRegistry."
	keyTrivyNonSslRegistryPrefix                = "trivy.nonSslRegistry."
	keyTrivyMirrorPrefix                        = "trivy.registry.mirror."
	keyTrivyHTTPProxy                           = "trivy.httpProxy"
	keyTrivyHTTPSProxy                          = "trivy.httpsProxy"
	keyTrivyNoProxy                             = "trivy.noProxy"
	keyTrivySslCertDir                          = "trivy.sslCertDir"
	keyIncludeDevDeps                           = "trivy.includeDevDeps"
	// nolint:gosec // This is not a secret, but a configuration value.
	keyTrivyGitHubToken          = "trivy.githubToken"
	keyTrivySkipFiles            = "trivy.skipFiles"
	keyTrivySkipDirs             = "trivy.skipDirs"
	keyTrivyDBRepository         = "trivy.dbRepository"
	keyTrivyDBRepositoryUsername = "trivy.dbRepositoryUsername"
	keyTrivyDBRepositoryPassword = "trivy.dbRepositoryPassword" // #nosec G101
	keyTrivyJavaDBRepository     = "trivy.javaDbRepository"
	keyTrivyDBRepositoryInsecure = "trivy.dbRepositoryInsecure"

	keyTrivyUseBuiltinRegoPolicies    = "trivy.useBuiltinRegoPolicies"
	keyTrivySupportedConfigAuditKinds = "trivy.supportedConfigAuditKinds"

	keyTrivyServerURL              = "trivy.serverURL"
	keyTrivyClientServerSkipUpdate = "trivy.clientServerSkipUpdate"
	keyTrivySkipJavaDBUpdate       = "trivy.skipJavaDBUpdate"
	keyTrivyImageScanCacheDir      = "trivy.imageScanCacheDir"
	keyTrivyFilesystemScanCacheDir = "trivy.filesystemScanCacheDir"
	// nolint:gosec // This is not a secret, but a configuration value.
	keyTrivyServerTokenHeader = "trivy.serverTokenHeader"
	keyTrivyServerInsecure    = "trivy.serverInsecure"
	// nolint:gosec // This is not a secret, but a configuration value.
	keyTrivyServerToken         = "trivy.serverToken"
	keyTrivyServerCustomHeaders = "trivy.serverCustomHeaders"

	keyResourcesRequestsCPU             = "trivy.resources.requests.cpu"
	keyResourcesRequestsMemory          = "trivy.resources.requests.memory"
	keyResourcesLimitsCPU               = "trivy.resources.limits.cpu"
	keyResourcesLimitsMemory            = "trivy.resources.limits.memory"
	keyResourcesRequestEphemeralStorage = "trivy.resources.requests.ephemeral-storage"
	keyResourcesLimitEphemeralStorage   = "trivy.resources.limits.ephemeral-storage"
)

// Config defines configuration params for this plugin.
type Config struct {
	trivyoperator.PluginConfig
}

func (c Config) GetAdditionalVulnerabilityReportFields() vulnerabilityreport.AdditionalFields {
	addFields := vulnerabilityreport.AdditionalFields{}

	fields, ok := c.Data[keyTrivyAdditionalVulnerabilityReportFields]
	if !ok {
		return addFields
	}
	for _, field := range strings.Split(fields, ",") {
		switch strings.TrimSpace(field) {
		case "Description":
			addFields.Description = true
		case "Links":
			addFields.Links = true
		case "CVSS":
			addFields.CVSS = true
		case "Target":
			addFields.Target = true
		case "Class":
			addFields.Class = true
		case "PackageType":
			addFields.PackageType = true
		case "PackagePath":
			addFields.PkgPath = true
		}
	}
	return addFields
}

// GetImageRef returns upstream Trivy container image reference.
func (c Config) GetImageRef() (string, error) {
	repository, err := c.GetRequiredData(keyTrivyImageRepository)
	if err != nil {
		return "", err
	}
	tag, err := c.GetImageTag()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:%s", repository, tag), nil
}

// GetImageTag returns upstream Trivy container image tag.
func (c Config) GetImageTag() (string, error) {
	tag, err := c.GetRequiredData(keyTrivyImageTag)
	if err != nil {
		return "", err
	}
	return tag, nil
}

func (c Config) GetImagePullSecret() []corev1.LocalObjectReference {
	ips, ok := c.Data[keyTrivyImagePullSecret]
	if !ok {
		return []corev1.LocalObjectReference{}
	}
	return []corev1.LocalObjectReference{{Name: ips}}
}

func (c Config) GetImagePullPolicy() string {
	ipp, ok := c.Data[keyTrivyImagePullPolicy]
	if !ok {
		return "IfNotPresent"
	}
	return ipp
}

func (c Config) GetMode() Mode {
	var ok bool
	var value string
	if value, ok = c.Data[keyTrivyMode]; !ok {
		return Standalone
	}

	switch Mode(value) {
	case Standalone:
		return Standalone
	case ClientServer:
		return ClientServer
	}
	return Standalone
}

func (c Config) GetCommand() Command {
	var ok bool
	var value string
	if value, ok = c.Data[keyTrivyCommand]; !ok {
		// for backward compatibility, fallback to ImageScan
		return Image
	}
	switch Command(value) {
	case Image:
		return Image
	case Filesystem:
		return Filesystem
	case Rootfs:
		return Rootfs
	}
	return Image
}

func (c Config) GetServerURL() (string, error) {
	return c.GetRequiredData(keyTrivyServerURL)
}

func (c Config) GetClientServerSkipUpdate() bool {
	val, ok := c.Data[keyTrivyClientServerSkipUpdate]
	if !ok {
		return false
	}
	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return false
	}
	return boolVal
}

func (c Config) GetIncludeDevDeps() bool {
	val, ok := c.Data[keyIncludeDevDeps]
	if !ok {
		return false
	}
	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return false
	}
	return boolVal
}

func (c Config) GetSkipJavaDBUpdate() bool {
	val, ok := c.Data[keyTrivySkipJavaDBUpdate]
	if !ok {
		return false
	}
	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return false
	}
	return boolVal
}

func (c Config) TrivyDBRepositoryCredentialsSet() bool {
	_, userOk := c.Data[keyTrivyDBRepositoryUsername]
	_, passOk := c.Data[keyTrivyDBRepositoryPassword]
	return userOk && passOk
}

func (c Config) GetImageScanCacheDir() string {
	val, ok := c.Data[keyTrivyImageScanCacheDir]
	if !ok || val == "" {
		return "/tmp/trivy/.cache"
	}
	return val
}

func (c Config) GetFilesystemScanCacheDir() string {
	val, ok := c.Data[keyTrivyFilesystemScanCacheDir]
	if !ok || val == "" {
		return "/var/trivyoperator/trivy-db"
	}
	return val
}

func (c Config) GetServerInsecure() bool {
	_, ok := c.Data[keyTrivyServerInsecure]
	return ok
}

func (c Config) GetDBRepositoryInsecure() bool {
	val, ok := c.Data[keyTrivyDBRepositoryInsecure]
	if !ok {
		return false
	}
	boolVal, _ := strconv.ParseBool(val)
	return boolVal
}
func (c Config) GetUseBuiltinRegoPolicies() bool {
	val, ok := c.Data[keyTrivyUseBuiltinRegoPolicies]
	if !ok {
		return true
	}
	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return true
	}
	return boolVal
}
func (c Config) GetSslCertDir() string {
	val, ok := c.Data[keyTrivySslCertDir]
	if !ok {
		return ""
	}
	return val
}

func (c Config) GetSeverity() string {
	val, ok := c.Data[KeyTrivySeverity]
	if !ok {
		return ""
	}
	return val
}

func (c Config) GetSlow() bool {
	val, ok := c.Data[keyTrivySlow]
	if !ok {
		return true
	}
	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return true
	}
	return boolVal
}

func (c Config) GetVulnType() string {
	val, ok := c.Data[keyTrivyVulnType]
	if !ok {
		return ""
	}
	trimmedVulnType := strings.TrimSpace(val)
	if !(trimmedVulnType == "os" || trimmedVulnType == "library") {
		return ""
	}
	return trimmedVulnType
}

func (c Config) GetSupportedConfigAuditKinds() []string {
	val, ok := c.Data[keyTrivySupportedConfigAuditKinds]
	if !ok {
		return utils.MapKinds(strings.Split(SupportedConfigAuditKinds, ","))
	}
	return utils.MapKinds(strings.Split(val, ","))
}

func (c Config) IgnoreFileExists() bool {
	_, ok := c.Data[keyTrivyIgnoreFile]
	return ok
}

func (c Config) FindIgnorePolicyKey(workload client.Object) string {
	keysByPrecedence := []string{
		keyTrivyIgnorePolicy + "." + workload.GetNamespace() + "." + workload.GetName(),
		keyTrivyIgnorePolicy + "." + workload.GetNamespace(),
		keyTrivyIgnorePolicy,
	}
	for _, key := range keysByPrecedence {
		for key2 := range c.Data {
			if key2 == keyTrivyIgnorePolicy || strings.HasPrefix(key2, keyTrivyIgnorePolicy) {
				tempKey := key2
				if key2 != keyTrivyIgnorePolicy {
					// replace dot with astrix for regex matching
					tempKey = fmt.Sprintf("%s%s", keyTrivyIgnorePolicy, strings.ReplaceAll(tempKey[len(keyTrivyIgnorePolicy):], ".", "*"))
				}
				matched, err := filepath.Match(tempKey, key)
				if err == nil && matched {
					return key2
				}
			}
		}
	}
	return ""
}

func (c Config) GenerateIgnoreFileVolumeIfAvailable(trivyConfigName string) (*corev1.Volume, *corev1.VolumeMount) {
	if !c.IgnoreFileExists() {
		return nil, nil
	}
	volume := corev1.Volume{
		Name: ignoreFileVolumeName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: trivyConfigName,
				},
				Items: []corev1.KeyToPath{
					{
						Key:  keyTrivyIgnoreFile,
						Path: ignoreFileName,
					},
				},
			},
		},
	}
	volumeMount := corev1.VolumeMount{
		Name:      ignoreFileVolumeName,
		MountPath: ignoreFileMountPath,
		SubPath:   ignoreFileName,
	}
	return &volume, &volumeMount
}

func (c Config) GenerateSslCertDirVolumeIfAvailable(trivyConfigName string) (*corev1.Volume, *corev1.VolumeMount) {
	var sslCertDirHost string
	if sslCertDirHost = c.GetSslCertDir(); len(sslCertDirHost) == 0 {
		return nil, nil
	}
	volume := corev1.Volume{
		Name: sslCertDirVolumeName,
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: sslCertDirHost,
			},
		},
	}
	volumeMount := corev1.VolumeMount{
		Name:      sslCertDirVolumeName,
		MountPath: SslCertDir,
		ReadOnly:  true,
	}
	return &volume, &volumeMount
}

func (c Config) GenerateIgnorePolicyVolumeIfAvailable(trivyConfigName string, workload client.Object) (*corev1.Volume, *corev1.VolumeMount) {
	ignorePolicyKey := c.FindIgnorePolicyKey(workload)
	if ignorePolicyKey == "" {
		return nil, nil
	}
	volume := corev1.Volume{
		Name: ignorePolicyVolumeName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: trivyConfigName,
				},
				Items: []corev1.KeyToPath{
					{
						Key:  c.FindIgnorePolicyKey(workload),
						Path: ignorePolicyName,
					},
				},
			},
		},
	}
	volumeMounts := corev1.VolumeMount{
		Name:      ignorePolicyVolumeName,
		MountPath: ignorePolicyMountPath,
		SubPath:   ignorePolicyName,
	}
	return &volume, &volumeMounts
}

func (c Config) IgnoreUnfixed() bool {
	_, ok := c.Data[keyTrivyIgnoreUnfixed]
	return ok
}

func (c Config) OfflineScan() bool {
	_, ok := c.Data[keyTrivyOfflineScan]
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

	err = c.setResourceLimit(keyResourcesRequestEphemeralStorage, &requirements.Requests, corev1.ResourceEphemeralStorage)
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

	err = c.setResourceLimit(keyResourcesLimitEphemeralStorage, &requirements.Limits, corev1.ResourceEphemeralStorage)
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
