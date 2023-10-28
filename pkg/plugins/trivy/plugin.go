package trivy

import (
	"encoding/json"
	"fmt"
	"io"

	"regexp"

	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-operator/pkg/utils"
	fg "github.com/aquasecurity/trivy/pkg/flag"
	tr "github.com/aquasecurity/trivy/pkg/report"
	ty "github.com/aquasecurity/trivy/pkg/types"
	containerimage "github.com/google/go-containerregistry/pkg/name"

	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/docker"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Plugin the name of this plugin.
	Plugin = "Trivy"
)

const (
	GCPCR_Inage_Regex         = `^(gcr\.io.*|^([a-zA-Z0-9-]+)-*-*.docker.pkg.dev.*)`
	AWSECR_Image_Regex        = "^\\d+\\.dkr\\.ecr\\.(\\w+-\\w+-\\d+)\\.amazonaws\\.com\\/"
	SupportedConfigAuditKinds = "Workload,Service,Role,ClusterRole,NetworkPolicy,Ingress,LimitRange,ResourceQuota"
	// SkipDirsAnnotation annotation  example: trivy-operator.aquasecurity.github.io/skip-dirs: "/tmp,/home"
	SkipDirsAnnotation = "trivy-operator.aquasecurity.github.io/skip-dirs"
	// SkipFilesAnnotation example: trivy-operator.aquasecurity.github.io/skip-files: "/src/Gemfile.lock,/examplebinary"
	SkipFilesAnnotation = "trivy-operator.aquasecurity.github.io/skip-files"
)

const (
	DefaultImageRepository  = "ghcr.io/aquasecurity/trivy"
	DefaultDBRepository     = "ghcr.io/aquasecurity/trivy-db"
	DefaultJavaDBRepository = "ghcr.io/aquasecurity/trivy-java-db"
	DefaultSeverity         = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
)

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
	Rootfs     Command = "rootfs"
)

type AdditionalFields struct {
	Description bool
	Links       bool
	CVSS        bool
	Target      bool
	Class       bool
	PackageType bool
	PkgPath     bool
}

type plugin struct {
	clock          ext.Clock
	idGenerator    ext.IDGenerator
	objectResolver *kube.ObjectResolver
	podSpecMgr     PodSpecMgr
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
func NewPlugin(clock ext.Clock, idGenerator ext.IDGenerator, objectResolver *kube.ObjectResolver, podSpecMgr PodSpecMgr) vulnerabilityreport.Plugin {
	return &plugin{
		clock:          clock,
		idGenerator:    idGenerator,
		objectResolver: objectResolver,
		podSpecMgr:     podSpecMgr,
	}
}

// NewTrivyConfigAuditPlugin constructs a new configAudit.Plugin, which is using an
// upstream Trivy config audit scanner lib.
func NewTrivyConfigAuditPlugin(clock ext.Clock, idGenerator ext.IDGenerator, objectResolver *kube.ObjectResolver) configauditreport.PluginInMemory {
	return &plugin{
		clock:          clock,
		idGenerator:    idGenerator,
		objectResolver: objectResolver,
	}
}

// Init ensures the default Config required by this plugin.
func (p *plugin) Init(ctx trivyoperator.PluginContext) error {
	return ctx.EnsureConfig(trivyoperator.PluginConfig{
		Data: map[string]string{
			keyTrivyImageRepository:           DefaultImageRepository,
			keyTrivyImageTag:                  "0.45.1",
			KeyTrivySeverity:                  DefaultSeverity,
			keyTrivySlow:                      "true",
			keyTrivyMode:                      string(Standalone),
			keyTrivyTimeout:                   "5m0s",
			keyTrivyDBRepository:              DefaultDBRepository,
			keyTrivyJavaDBRepository:          DefaultJavaDBRepository,
			keyTrivyUseBuiltinRegoPolicies:    "true",
			keyTrivySupportedConfigAuditKinds: SupportedConfigAuditKinds,
			keyResourcesRequestsCPU:           "100m",
			keyResourcesRequestsMemory:        "100M",
			keyResourcesLimitsCPU:             "500m",
			keyResourcesLimitsMemory:          "500M",
		},
	})
}

func (p *plugin) GetScanJobSpec(ctx trivyoperator.PluginContext, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext) (corev1.PodSpec, []*corev1.Secret, error) {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	var podSpec corev1.PodSpec
	var secrets []*corev1.Secret

	podSpec, secrets, err = p.podSpecMgr.GetPodSpec(ctx, config, workload, credentials, securityContext, p)

	// add image pull secret to be used when pulling trivy image fom private registry
	podSpec.ImagePullSecrets = config.GetImagePullSecret()
	return podSpec, secrets, err
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

const (
	tmpVolumeName               = "tmp"
	ignoreFileVolumeName        = "ignorefile"
	sslCertDirVolumeName        = "ssl-cert-dir"
	ignoreFileName              = ".trivyignore"
	ignoreFileMountPath         = "/etc/trivy/" + ignoreFileName
	ignorePolicyVolumeName      = "ignorepolicy"
	ignorePolicyName            = "policy.rego"
	ignorePolicyMountPath       = "/etc/trivy/" + ignorePolicyName
	scanResultVolumeName        = "scanresult"
	FsSharedVolumeName          = "trivyoperator"
	SharedVolumeLocationOfTrivy = "/var/trivyoperator/trivy"
	SslCertDir                  = "/var/ssl-cert"
)

func checkGcpCrOrPivateRegistry(imageUrl string) bool {
	imageRegex := regexp.MustCompile(GCPCR_Inage_Regex)
	return imageRegex.MatchString(imageUrl)
}

func (p *plugin) initContainerEnvVar(trivyConfigName string, config Config) []corev1.EnvVar {
	envs := []corev1.EnvVar{
		constructEnvVarSourceFromConfigMap("HTTP_PROXY", trivyConfigName, keyTrivyHTTPProxy),
		constructEnvVarSourceFromConfigMap("HTTPS_PROXY", trivyConfigName, keyTrivyHTTPSProxy),
		constructEnvVarSourceFromConfigMap("NO_PROXY", trivyConfigName, keyTrivyNoProxy),
		constructEnvVarSourceFromSecret("GITHUB_TOKEN", trivyConfigName, keyTrivyGitHubToken),
	}

	if config.GetDBRepositoryInsecure() {
		envs = append(envs, corev1.EnvVar{
			Name:  "TRIVY_INSECURE",
			Value: "true",
		})
	}
	return envs
}

func (p *plugin) getCommandAndArgs(ctx trivyoperator.PluginContext, mode Mode, imageRef string, trivyServerURL string, resultFileName string) ([]string, []string) {
	command := []string{
		"trivy",
	}
	trivyConfig := ctx.GetTrivyOperatorConfig()
	compressLogs := trivyConfig.CompressLogs()
	c, err := p.getConfig(ctx)
	if err != nil {
		return []string{}, []string{}
	}
	slow := Slow(c)
	skipJavaDBUpdate := SkipJavaDBUpdate(c)
	vulnTypeArgs := p.vulnTypeFilter(ctx)
	scanners := Scanners(c)
	var vulnTypeFlag string
	if len(vulnTypeArgs) == 2 {
		vulnTypeFlag = fmt.Sprintf("%s %s ", vulnTypeArgs[0], vulnTypeArgs[1])
	}
	imcs := p.imageConfigSecretScanner(trivyConfig)
	var imageconfigSecretScannerFlag string
	if len(imcs) == 2 {
		imageconfigSecretScannerFlag = fmt.Sprintf("%s %s ", imcs[0], imcs[1])
	}
	var skipUpdate string
	if mode == ClientServer {
		if c.GetClientServerSkipUpdate() {
			skipUpdate = SkipDBUpdate(c)
		}
		if !compressLogs {
			args := []string{
				"--cache-dir",
				"/tmp/trivy/.cache",
				"--quiet",
				"image",
				scanners,
				getSecurityChecks(ctx),
				"--format",
				"json",
				"--server",
				trivyServerURL,
				imageRef,
			}
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
		return []string{"/bin/sh"}, []string{"-c", fmt.Sprintf(`trivy image %s '%s' %s %s %s %s %s %s --cache-dir /tmp/trivy/.cache --quiet %s --format json --server '%s' > /tmp/scan/%s &&  bzip2 -c /tmp/scan/%s | base64`, slow, imageRef, scanners, getSecurityChecks(ctx), imageconfigSecretScannerFlag, vulnTypeFlag, skipUpdate, skipJavaDBUpdate, getPkgList(ctx), trivyServerURL, resultFileName, resultFileName)}
	}
	skipUpdate = SkipDBUpdate(c)
	if !compressLogs {
		args := []string{
			"--cache-dir",
			"/tmp/trivy/.cache",
			"--quiet",
			"image",
			scanners,
			getSecurityChecks(ctx),
			"--format",
			"json",
			imageRef,
		}
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
	return []string{"/bin/sh"}, []string{"-c", fmt.Sprintf(`trivy image %s '%s' %s %s %s %s %s %s --cache-dir /tmp/trivy/.cache --quiet %s --format json > /tmp/scan/%s &&  bzip2 -c /tmp/scan/%s | base64`, slow, imageRef, scanners, getSecurityChecks(ctx), imageconfigSecretScannerFlag, vulnTypeFlag, skipUpdate, skipJavaDBUpdate, getPkgList(ctx), resultFileName, resultFileName)}
}

func (p *plugin) vulnTypeFilter(ctx trivyoperator.PluginContext) []string {
	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return []string{}
	}
	vulnType := config.GetVulnType()
	if len(vulnType) == 0 {
		return []string{}
	}
	return []string{"--vuln-type", vulnType}
}

func (p *plugin) imageConfigSecretScanner(tc trivyoperator.ConfigData) []string {

	if tc.ExposedSecretsScannerEnabled() {
		return []string{"--image-config-scanners", "secret"}
	}
	return []string{}
}

func getAutomountServiceAccountToken(ctx trivyoperator.PluginContext) bool {
	return ctx.GetTrivyOperatorConfig().GetScanJobAutomountServiceAccountToken()
}
func getUniqueScanResultFileName(name string) string {
	return fmt.Sprintf("result_%s.json", name)
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

func (p *plugin) getFSScanningArgs(ctx trivyoperator.PluginContext, command Command, mode Mode, trivyServerURL string) []string {
	c, err := p.getConfig(ctx)
	if err != nil {
		return []string{}
	}
	scanners := Scanners(c)
	imcs := p.imageConfigSecretScanner(c.Data)
	skipUpdate := SkipDBUpdate(c)
	args := []string{
		"--cache-dir",
		"/var/trivyoperator/trivy-db",
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
	pkgList := getPkgList(ctx)
	if len(pkgList) > 0 {
		args = append(args, pkgList)
	}
	return args
}

func (p *plugin) initContainerFSEnvVar(trivyConfigName string, config Config) []corev1.EnvVar {
	envs := []corev1.EnvVar{
		constructEnvVarSourceFromConfigMap("HTTP_PROXY", trivyConfigName, keyTrivyHTTPProxy),
		constructEnvVarSourceFromConfigMap("HTTPS_PROXY", trivyConfigName, keyTrivyHTTPSProxy),
		constructEnvVarSourceFromConfigMap("NO_PROXY", trivyConfigName, keyTrivyNoProxy),
		constructEnvVarSourceFromSecret("GITHUB_TOKEN", trivyConfigName, keyTrivyGitHubToken),
	}
	if config.GetDBRepositoryInsecure() {
		envs = append(envs, corev1.EnvVar{
			Name:  "TRIVY_INSECURE",
			Value: "true",
		})
	}
	return envs
}

func (p *plugin) appendTrivyInsecureEnv(config Config, image string, env []corev1.EnvVar) ([]corev1.EnvVar, error) {
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

func (p *plugin) appendTrivyNonSSLEnv(config Config, image string, env []corev1.EnvVar) ([]corev1.EnvVar, error) {
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

func (p *plugin) ParseReportData(ctx trivyoperator.PluginContext, imageRef string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityReportData, v1alpha1.ExposedSecretReportData, *v1alpha1.SbomReportData, error) {
	var vulnReport v1alpha1.VulnerabilityReportData
	var secretReport v1alpha1.ExposedSecretReportData
	var sbomReport v1alpha1.SbomReportData

	config, err := p.newConfigFrom(ctx)
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}
	cmd, err := config.GetCommand()
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}
	compressedLogs := ctx.GetTrivyOperatorConfig().CompressLogs()
	if compressedLogs && cmd != Filesystem && cmd != Rootfs {
		var errCompress error
		logsReader, errCompress = utils.ReadCompressData(logsReader)
		if errCompress != nil {
			return vulnReport, secretReport, &sbomReport, errCompress
		}
	}

	var reports ty.Report
	err = json.NewDecoder(logsReader).Decode(&reports)
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}

	vulnerabilities := make([]v1alpha1.Vulnerability, 0)
	secrets := make([]v1alpha1.ExposedSecret, 0)
	addFields := config.GetAdditionalVulnerabilityReportFields()

	for _, report := range reports.Results {
		vulnerabilities = append(vulnerabilities, getVulnerabilitiesFromScanResult(report, addFields)...)
		secrets = append(secrets, getExposedSecretsFromScanResult(report)...)
	}
	var bom *v1alpha1.BOM
	if ctx.GetTrivyOperatorConfig().GenerateSbomEnabled() {
		bom, err = generateSbomFromScanResult(reports)
		if err != nil {
			return vulnReport, secretReport, &sbomReport, err
		}
	}
	registry, artifact, err := p.parseImageRef(imageRef, reports.Metadata.ImageID)
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}

	trivyImageRef, err := config.GetImageRef()
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}

	version, err := trivyoperator.GetVersionFromImageRef(trivyImageRef)
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}
	var sbomData *v1alpha1.SbomReportData
	if bom != nil {
		sbomData = &v1alpha1.SbomReportData{
			UpdateTimestamp: metav1.NewTime(p.clock.Now()),
			Scanner: v1alpha1.Scanner{
				Name:    v1alpha1.ScannerNameTrivy,
				Vendor:  "Aqua Security",
				Version: version,
			},
			Registry: registry,
			Artifact: artifact,
			Summary:  bomSummary(*bom),
			Bom:      *bom,
		}
	}
	return v1alpha1.VulnerabilityReportData{
			UpdateTimestamp: metav1.NewTime(p.clock.Now()),
			Scanner: v1alpha1.Scanner{
				Name:    v1alpha1.ScannerNameTrivy,
				Vendor:  "Aqua Security",
				Version: version,
			},
			Registry:        registry,
			Artifact:        artifact,
			Summary:         p.vulnerabilitySummary(vulnerabilities),
			Vulnerabilities: vulnerabilities,
		}, v1alpha1.ExposedSecretReportData{
			UpdateTimestamp: metav1.NewTime(p.clock.Now()),
			Scanner: v1alpha1.Scanner{
				Name:    v1alpha1.ScannerNameTrivy,
				Vendor:  "Aqua Security",
				Version: version,
			},
			Registry: registry,
			Artifact: artifact,
			Summary:  p.secretSummary(secrets),
			Secrets:  secrets,
		}, sbomData, nil

}

func bomSummary(bom v1alpha1.BOM) v1alpha1.SbomSummary {
	return v1alpha1.SbomSummary{
		ComponentsCount:   len(bom.Components) + 1,
		DependenciesCount: len(*bom.Dependencies),
	}

}

func getVulnerabilitiesFromScanResult(report ty.Result, addFields AdditionalFields) []v1alpha1.Vulnerability {
	vulnerabilities := make([]v1alpha1.Vulnerability, 0)

	for _, sr := range report.Vulnerabilities {
		var pd, lmd string
		if sr.PublishedDate != nil {
			pd = sr.PublishedDate.Format(time.RFC3339)
		}
		if sr.LastModifiedDate != nil {
			lmd = sr.LastModifiedDate.Format(time.RFC3339)
		}
		vulnerability := v1alpha1.Vulnerability{
			VulnerabilityID:  sr.VulnerabilityID,
			Resource:         sr.PkgName,
			InstalledVersion: sr.InstalledVersion,
			FixedVersion:     sr.FixedVersion,
			PublishedDate:    pd,
			LastModifiedDate: lmd,
			Severity:         v1alpha1.Severity(sr.Severity),
			Title:            sr.Title,
			PrimaryLink:      sr.PrimaryURL,
			Links:            []string{},
			Score:            GetScoreFromCVSS(GetCvssV3(sr.CVSS)),
		}

		if addFields.Description {
			vulnerability.Description = sr.Description
		}
		if addFields.Links && sr.References != nil {
			vulnerability.Links = sr.References
		}
		if addFields.CVSS {
			vulnerability.CVSS = sr.CVSS
		}
		if addFields.Target {
			vulnerability.Target = report.Target
		}
		if addFields.Class {
			vulnerability.Class = string(report.Class)
		}
		if addFields.PackageType {
			vulnerability.PackageType = report.Type
		}
		if addFields.PkgPath {
			vulnerability.PkgPath = sr.PkgPath
		}

		vulnerabilities = append(vulnerabilities, vulnerability)
	}

	return vulnerabilities
}

func generateSbomFromScanResult(report ty.Report) (*v1alpha1.BOM, error) {
	var bom *v1alpha1.BOM
	if len(report.Results) > 0 && len(report.Results[0].Packages) > 0 {
		// capture os.Stdout with a writer
		done := capture()
		err := tr.Write(report, fg.Options{
			ReportOptions: fg.ReportOptions{
				Format: ty.FormatCycloneDX,
			},
		})
		if err != nil {
			return nil, err
		}
		bomWriter, err := done()
		if err != nil {
			return nil, err
		}
		var bom cdx.BOM
		err = json.Unmarshal([]byte(bomWriter), &bom)
		if err != nil {
			return nil, err
		}
		return cycloneDxBomToReport(bom), nil
	}
	return bom, nil
}

func getExposedSecretsFromScanResult(report ty.Result) []v1alpha1.ExposedSecret {
	secrets := make([]v1alpha1.ExposedSecret, 0)

	for _, sr := range report.Secrets {
		secrets = append(secrets, v1alpha1.ExposedSecret{
			Target:   report.Target,
			RuleID:   sr.RuleID,
			Title:    sr.Title,
			Severity: v1alpha1.Severity(sr.Severity),
			Category: string(sr.Category),
			Match:    sr.Match,
		})
	}

	return secrets
}

func (p *plugin) newConfigFrom(ctx trivyoperator.PluginContext) (Config, error) {
	return p.getConfig(ctx)
}

func (p *plugin) getConfig(ctx trivyoperator.PluginContext) (Config, error) {
	pluginConfig, err := ctx.GetConfig()
	if err != nil {
		return Config{}, err
	}
	return Config{PluginConfig: pluginConfig}, nil
}

// NewConfigForConfigAudit and interface which expose related configaudit report configuration
func (p *plugin) NewConfigForConfigAudit(ctx trivyoperator.PluginContext) (configauditreport.ConfigAuditConfig, error) {
	return p.getConfig(ctx)
}

func (p *plugin) vulnerabilitySummary(vulnerabilities []v1alpha1.Vulnerability) v1alpha1.VulnerabilitySummary {
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

func (p *plugin) secretSummary(secrets []v1alpha1.ExposedSecret) v1alpha1.ExposedSecretSummary {
	var s v1alpha1.ExposedSecretSummary
	for _, v := range secrets {
		switch v.Severity {
		case v1alpha1.SeverityCritical:
			s.CriticalCount++
		case v1alpha1.SeverityHigh:
			s.HighCount++
		case v1alpha1.SeverityMedium:
			s.MediumCount++
		case v1alpha1.SeverityLow:
			s.LowCount++
		}
	}
	return s
}

func (p *plugin) parseImageRef(imageRef string, imageID string) (v1alpha1.Registry, v1alpha1.Artifact, error) {
	ref, err := containerimage.ParseReference(imageRef)
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
	case containerimage.Tag:
		artifact.Tag = t.TagStr()
	case containerimage.Digest:
		artifact.Digest = t.DigestStr()
	}
	if len(artifact.Digest) == 0 {
		artifact.Digest = imageID
	}
	return registry, artifact, nil
}

func GetCvssV3(findingCvss types.VendorCVSS) map[string]*CVSS {
	cvssV3 := make(map[string]*CVSS)
	for vendor, cvss := range findingCvss {
		var v3Score *float64
		if cvss.V3Score != 0.0 {
			v3Score = pointer.Float64(cvss.V3Score)
		}
		cvssV3[string(vendor)] = &CVSS{v3Score}
	}
	return cvssV3
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

	if nvdScore != nil {
		return nvdScore
	}

	return vendorScore
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

func getContainers(spec corev1.PodSpec) []corev1.Container {
	containers := append(spec.Containers, spec.InitContainers...)

	// ephemeral container are not the same type as Containers/InitContainers,
	// then we add it in a different loop
	for _, c := range spec.EphemeralContainers {
		containers = append(containers, corev1.Container(c.EphemeralContainerCommon))
	}

	return containers
}

func CheckAwsEcrPrivateRegistry(ImageUrl string) string {
	if len(regexp.MustCompile(AWSECR_Image_Regex).FindAllStringSubmatch(ImageUrl, -1)) != 0 {
		return regexp.MustCompile(AWSECR_Image_Regex).FindAllStringSubmatch(ImageUrl, -1)[0][1]
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

func getPkgList(ctx trivyoperator.PluginContext) string {
	c := ctx.GetTrivyOperatorConfig()
	if c.GenerateSbomEnabled() {
		return "--list-all-pkgs"
	}
	return ""
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

type CVSS struct {
	V3Score *float64 `json:"V3Score,omitempty"`
}
