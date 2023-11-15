package trivy

import (
	"encoding/json"
	"io"

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
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Plugin the name of this plugin.
	Plugin = "Trivy"
)

const (
	SupportedConfigAuditKinds = "Workload,Service,Role,ClusterRole,NetworkPolicy,Ingress,LimitRange,ResourceQuota"
)

const (
	DefaultImageRepository  = "ghcr.io/aquasecurity/trivy"
	DefaultDBRepository     = "ghcr.io/aquasecurity/trivy-db"
	DefaultJavaDBRepository = "ghcr.io/aquasecurity/trivy-java-db"
	DefaultSeverity         = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
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
			keyTrivyImageTag:                  "0.47.0",
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
	var sbomReport v1alpha1.SbomReportData

	config, err := getConfig(ctx)
	if err != nil {
		return vulnReport, secretReport, &sbomReport, err
	}
	cmd := config.GetCommand()
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

	os, err := p.parseOSRef(reports)
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
			OS:              os,
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
			OS:       os,
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
			vulnerability.PackageType = string(report.Type)
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

// NewConfigForConfigAudit and interface which expose related configaudit report configuration
func (p *plugin) NewConfigForConfigAudit(ctx trivyoperator.PluginContext) (configauditreport.ConfigAuditConfig, error) {
	return getConfig(ctx)
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

func (p *plugin) parseOSRef(reports ty.Report) (v1alpha1.OS, error) {
	os := v1alpha1.OS{}
	if reports.Metadata.OS != nil {
		os.Family = reports.Metadata.OS.Family
		os.Name = reports.Metadata.OS.Name
		eosl := reports.Metadata.OS.Eosl
		if eosl {
			os.Eosl = eosl
		}
	}

	return os, nil
}

func GetCvssV3(findingCvss types.VendorCVSS) map[string]*CVSS {
	cvssV3 := make(map[string]*CVSS)
	for vendor, cvss := range findingCvss {
		var v3Score *float64
		if cvss.V3Score != 0.0 {
			v3Score = ptr.To[float64](cvss.V3Score)
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

type CVSS struct {
	V3Score *float64 `json:"V3Score,omitempty"`
}
