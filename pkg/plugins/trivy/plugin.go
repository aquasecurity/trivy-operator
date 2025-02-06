package trivy

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	containerimage "github.com/google/go-containerregistry/pkg/name"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/docker"
	"github.com/aquasecurity/trivy-operator/pkg/exposedsecretreport"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/sbomreport"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/utils"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
	ty "github.com/aquasecurity/trivy/pkg/types"
)

const (
	// Plugin the name of this plugin.
	Plugin = "Trivy"
)

const (
	SupportedConfigAuditKinds = "Workload,Service,Role,ClusterRole,NetworkPolicy,Ingress,LimitRange,ResourceQuota"
)

const (
	DefaultImageRepository  = "mirror.gcr.io/aquasec/trivy"
	DefaultDBRepository     = "mirror.gcr.io/aquasec/trivy-db"
	DefaultJavaDBRepository = "mirror.gcr.io/aquasec/trivy-java-db"
	DefaultSeverity         = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
)

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
func NewPlugin(clock ext.Clock, idGenerator ext.IDGenerator, objectResolver *kube.ObjectResolver) vulnerabilityreport.Plugin {
	plugin := &plugin{
		clock:          clock,
		idGenerator:    idGenerator,
		objectResolver: objectResolver,
	}
	return plugin
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
			keyTrivyImageTag:                  "0.52.2",
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

func (p *plugin) GetScanJobSpec(ctx trivyoperator.PluginContext, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext, sbomClusterReport map[string]v1alpha1.SbomReportData) (corev1.PodSpec, []*corev1.Secret, error) {
	config, err := getConfig(ctx)
	if err != nil {
		return corev1.PodSpec{}, nil, err
	}
	var podSpec corev1.PodSpec
	var secrets []*corev1.Secret
	podSpec, secrets, err = NewPodSpecMgr(config).GetPodSpec(ctx, config, workload, credentials, securityContext, p, sbomClusterReport)

	// add image pull secret to be used when pulling trivy image fom private registry
	podSpec.ImagePullSecrets = config.GetImagePullSecret()
	return podSpec, secrets, err
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

func (p *plugin) ParseReportData(ctx trivyoperator.PluginContext, imageRef string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityReportData, v1alpha1.ExposedSecretReportData, *v1alpha1.SbomReportData, error) {
	var vulnReport v1alpha1.VulnerabilityReportData
	var secretReport v1alpha1.ExposedSecretReportData

	config, err := getConfig(ctx)
	if err != nil {
		return vulnReport, secretReport, nil, err
	}
	cmd := config.GetCommand()
	if err != nil { // TODO: condition seems incorrect
		return vulnReport, secretReport, nil, err
	}
	compressedLogs := ctx.GetTrivyOperatorConfig().CompressLogs()
	if compressedLogs && cmd != Filesystem && cmd != Rootfs {
		var errCompress error
		logsReader, errCompress = utils.ReadCompressData(logsReader)
		if errCompress != nil {
			return vulnReport, secretReport, nil, errCompress
		}
	}

	var reports ty.Report
	err = json.NewDecoder(logsReader).Decode(&reports)
	if err != nil {
		return vulnReport, secretReport, nil, err
	}

	imageDigest := p.getImageDigest(reports)

	registry, artifact, err := p.parseImageRef(imageRef, imageDigest)
	if err != nil {
		return vulnReport, secretReport, nil, err
	}

	os := p.parseOSRef(reports)

	trivyImageRef, err := config.GetImageRef()
	if err != nil {
		return vulnReport, secretReport, nil, err
	}

	version, err := trivyoperator.GetVersionFromImageRef(trivyImageRef)
	if err != nil {
		return vulnReport, secretReport, nil, err
	}
	var sbomData *v1alpha1.SbomReportData
	if ctx.GetTrivyOperatorConfig().GenerateSbomEnabled() {
		sbomData, err = sbomreport.BuildSbomReportData(reports, p.clock, registry, artifact, version)
		if err != nil {
			return vulnReport, secretReport, nil, err
		}
	}
	vulnerabilities := make([]v1alpha1.Vulnerability, 0)
	secrets := make([]v1alpha1.ExposedSecret, 0)
	for _, report := range reports.Results {
		addFields := config.GetAdditionalVulnerabilityReportFields()
		vulnerabilities = append(vulnerabilities, vulnerabilityreport.GetVulnerabilitiesFromScanResult(report, addFields)...)
		secrets = append(secrets, getExposedSecretsFromScanResult(report)...)
	}
	vulnerabilitiesData := vulnerabilityreport.BuildVulnerabilityReportData(p.clock, registry, artifact, os, version, vulnerabilities)
	exposedSecretsData := exposedsecretreport.BuildExposedSecretsReportData(p.clock, registry, artifact, version, secrets)
	return vulnerabilitiesData, exposedSecretsData, sbomData, nil

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

// NewConfigForConfigAudit and interface which expose related configaudit report configuration
func (p *plugin) NewConfigForConfigAudit(ctx trivyoperator.PluginContext) (configauditreport.ConfigAuditConfig, error) {
	return getConfig(ctx)
}

func (p *plugin) parseImageRef(imageRef, imageDigest string) (v1alpha1.Registry, v1alpha1.Artifact, error) {
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
	if artifact.Digest == "" {
		artifact.Digest = imageDigest
	}
	return registry, artifact, nil
}

func (p *plugin) parseOSRef(reports ty.Report) v1alpha1.OS {
	os := v1alpha1.OS{}
	if reports.Metadata.OS != nil {
		os.Family = reports.Metadata.OS.Family
		os.Name = reports.Metadata.OS.Name
		eosl := reports.Metadata.OS.Eosl
		if eosl {
			os.Eosl = eosl
		}
	}

	return os
}

// ExcludeImage checks if the image should be excluded from scanning based on the excludeImagePattern (glob pattern)
func ExcludeImage(excludeImagePattern []string, imageName string) bool {
	if len(excludeImagePattern) == 0 {
		return false
	}
	for _, pattern := range excludeImagePattern {
		if matched, err := filepath.Match(pattern, imageName); err == nil && matched {
			return true
		}
	}
	return false
}

// getImageDigest extracts the image digest from the report metadata, returns empty string if not available
func (p *plugin) getImageDigest(reports ty.Report) string {
	if len(reports.Metadata.RepoDigests) == 0 {
		return ""
	}

	split := strings.Split(reports.Metadata.RepoDigests[0], "@")
	if len(split) < 2 {
		return ""
	}

	return split[1]
}
