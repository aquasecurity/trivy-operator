package metrics

import (
	"context"
	"strconv"

	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	k8smetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
)

const (
	namespace         = "namespace"
	name              = "name"
	resource_kind     = "resource_kind"
	resource_name     = "resource_name"
	container_name    = "container_name"
	image_registry    = "image_registry"
	image_repository  = "image_repository"
	image_tag         = "image_tag"
	image_digest      = "image_digest"
	installed_version = "installed_version"
	fixed_version     = "fixed_version"
	resource          = "resource"
	package_type      = "package_type"
	pkg_path          = "pkg_path"
	class             = "class"
	severity          = "severity"
	vuln_id           = "vuln_id"
	vuln_title        = "vuln_title"
	vuln_score        = "vuln_score"
	//compliance
	title       = "title"
	description = "description"
	status      = "status"
	//exposed secret
	secret_category = "secret_category"
	secret_rule_id  = "secret_rule_id"
	secret_target   = "secret_target"
	secret_title    = "secret_title"
	//config audit
	config_audit_id          = "config_audit_id"
	config_audit_title       = "config_audit_title"
	config_audit_description = "config_audit_description"
	config_audit_category    = "config_audit_category"
	config_audit_success     = "config_audit_success"
	//rbac assessment
	rbac_assessment_id          = "rbac_assessment_id"
	rbac_assessment_title       = "rbac_assessment_title"
	rbac_assessment_description = "rbac_assessment_description"
	rbac_assessment_category    = "rbac_assessment_category"
	rbac_assessment_success     = "rbac_assessment_success"
	//infra assessment
	infra_assessment_id          = "infra_assessment_id"
	infra_assessment_title       = "infra_assessment_title"
	infra_assessment_description = "infra_assessment_description"
	infra_assessment_category    = "infra_assessment_category"
	infra_assessment_success     = "infra_assessment_success"
)

type metricDescriptors struct {
	// Severities
	imageVulnSeverities       map[string]func(vs v1alpha1.VulnerabilitySummary) int
	exposedSecretSeverities   map[string]func(vs v1alpha1.ExposedSecretSummary) int
	configAuditSeverities     map[string]func(vs v1alpha1.ConfigAuditSummary) int
	rbacAssessmentSeverities  map[string]func(vs v1alpha1.RbacAssessmentSummary) int
	infraAssessmentSeverities map[string]func(vs v1alpha1.InfraAssessmentSummary) int
	complianceStatuses        map[string]func(vs v1alpha1.ComplianceSummary) int

	// Labels
	imageVulnLabels           []string
	vulnIdLabels              []string
	exposedSecretLabels       []string
	exposedSecretInfoLabels   []string
	configAuditLabels         []string
	configAuditInfoLabels     []string
	rbacAssessmentLabels      []string
	rbacAssessmentInfoLabels  []string
	infraAssessmentLabels     []string
	infraAssessmentInfoLabels []string
	complianceLabels          []string

	// Descriptors
	imageVulnDesc             *prometheus.Desc
	vulnIdDesc                *prometheus.Desc
	configAuditDesc           *prometheus.Desc
	configAuditInfoDesc       *prometheus.Desc
	exposedSecretDesc         *prometheus.Desc
	exposedSecretInfoDesc     *prometheus.Desc
	rbacAssessmentDesc        *prometheus.Desc
	rbacAssessmentInfoDesc    *prometheus.Desc
	clusterRbacAssessmentDesc *prometheus.Desc
	infraAssessmentDesc       *prometheus.Desc
	infraAssessmentInfoDesc   *prometheus.Desc
	complianceDesc            *prometheus.Desc
}

// ResourcesMetricsCollector is a custom Prometheus collector that produces
// metrics on-demand from the trivy-operator custom resources. Since these
// resources are already cached by the Kubernetes API client shared with the
// operator, metrics scrapes should never actually hit the API server.
// All resource reads are served from cache, reducing API server load without
// consuming additional cluster resources.
// An alternative (more traditional) approach would be to maintain metrics
// in the internal Prometheus registry on resource reconcile. The collector
// approach was selected in order to avoid potentially stale metrics; i.e.
// the controller would have to reconcile all resources at least once for the
// metrics to be up-to-date, which could take some time in large clusters.
// Also deleting metrics from registry for obsolete/deleted resources is
// challenging without introducing finalizers, which we want to avoid for
// operational reasons.
//
// For more advanced use-cases, and/or very large clusters, this internal
// collector can be disabled and replaced by
// https://github.com/giantswarm/starboard-exporter, which collects trivy
// metrics from a dedicated workload supporting sharding etc.
type ResourcesMetricsCollector struct {
	logr.Logger
	etc.Config
	trivyoperator.ConfigData
	client.Client
	metricDescriptors
}

func NewResourcesMetricsCollector(logger logr.Logger, config etc.Config, trvConfig trivyoperator.ConfigData, clt client.Client) *ResourcesMetricsCollector {
	metricDescriptors := buildMetricDescriptors(trvConfig)
	return &ResourcesMetricsCollector{
		Logger:            logger,
		Config:            config,
		ConfigData:        trvConfig,
		Client:            clt,
		metricDescriptors: metricDescriptors,
	}
}

func buildMetricDescriptors(config trivyoperator.ConfigData) metricDescriptors {
	imageVulnSeverities := map[string]func(vs v1alpha1.VulnerabilitySummary) int{
		SeverityCritical().Label: func(vs v1alpha1.VulnerabilitySummary) int {
			return vs.CriticalCount
		},
		SeverityHigh().Label: func(vs v1alpha1.VulnerabilitySummary) int {
			return vs.HighCount
		},
		SeverityMedium().Label: func(vs v1alpha1.VulnerabilitySummary) int {
			return vs.MediumCount
		},
		SeverityLow().Label: func(vs v1alpha1.VulnerabilitySummary) int {
			return vs.LowCount
		},
		SeverityUnknown().Label: func(vs v1alpha1.VulnerabilitySummary) int {
			return vs.UnknownCount
		},
	}
	exposedSecretSeverities := map[string]func(vs v1alpha1.ExposedSecretSummary) int{
		SeverityCritical().Label: func(vs v1alpha1.ExposedSecretSummary) int {
			return vs.CriticalCount
		},
		SeverityHigh().Label: func(vs v1alpha1.ExposedSecretSummary) int {
			return vs.HighCount
		},
		SeverityMedium().Label: func(vs v1alpha1.ExposedSecretSummary) int {
			return vs.MediumCount
		},
		SeverityLow().Label: func(vs v1alpha1.ExposedSecretSummary) int {
			return vs.LowCount
		},
	}
	configAuditSeverities := map[string]func(vs v1alpha1.ConfigAuditSummary) int{
		SeverityCritical().Label: func(cas v1alpha1.ConfigAuditSummary) int {
			return cas.CriticalCount
		},
		SeverityHigh().Label: func(cas v1alpha1.ConfigAuditSummary) int {
			return cas.HighCount
		},
		SeverityMedium().Label: func(cas v1alpha1.ConfigAuditSummary) int {
			return cas.MediumCount
		},
		SeverityLow().Label: func(cas v1alpha1.ConfigAuditSummary) int {
			return cas.LowCount
		},
	}
	rbacAssessmentSeverities := map[string]func(vs v1alpha1.RbacAssessmentSummary) int{
		SeverityCritical().Label: func(cas v1alpha1.RbacAssessmentSummary) int {
			return cas.CriticalCount
		},
		SeverityHigh().Label: func(cas v1alpha1.RbacAssessmentSummary) int {
			return cas.HighCount
		},
		SeverityMedium().Label: func(cas v1alpha1.RbacAssessmentSummary) int {
			return cas.MediumCount
		},
		SeverityLow().Label: func(cas v1alpha1.RbacAssessmentSummary) int {
			return cas.LowCount
		},
	}
	infraAssessmentSeverities := map[string]func(vs v1alpha1.InfraAssessmentSummary) int{
		SeverityCritical().Label: func(cas v1alpha1.InfraAssessmentSummary) int {
			return cas.CriticalCount
		},
		SeverityHigh().Label: func(cas v1alpha1.InfraAssessmentSummary) int {
			return cas.HighCount
		},
		SeverityMedium().Label: func(cas v1alpha1.InfraAssessmentSummary) int {
			return cas.MediumCount
		},
		SeverityLow().Label: func(cas v1alpha1.InfraAssessmentSummary) int {
			return cas.LowCount
		},
	}
	complainceStatuses := map[string]func(vs v1alpha1.ComplianceSummary) int{
		StatusFail().Label: func(cas v1alpha1.ComplianceSummary) int {
			return cas.FailCount
		},
		StatusPass().Label: func(cas v1alpha1.ComplianceSummary) int {
			return cas.PassCount
		},
	}

	dynamicLabels := getDynamicConfigLabels(config)
	imageVulnLabels := []string{
		namespace,
		name,
		resource_kind,
		resource_name,
		container_name,
		image_registry,
		image_repository,
		image_tag,
		image_digest,
		severity,
	}
	imageVulnLabels = append(imageVulnLabels, dynamicLabels...)
	vulnIdLabels := []string{
		namespace,
		name,
		resource_kind,
		resource_name,
		container_name,
		image_registry,
		image_repository,
		image_tag,
		image_digest,
		installed_version,
		fixed_version,
		resource,
		severity,
		package_type,
		pkg_path,
		class,
		vuln_id,
		vuln_title,
		vuln_score,
	}
	vulnIdLabels = append(vulnIdLabels, dynamicLabels...)
	exposedSecretLabels := []string{
		namespace,
		name,
		resource_kind,
		resource_name,
		container_name,
		image_registry,
		image_repository,
		image_tag,
		image_digest,
		severity,
	}
	exposedSecretLabels = append(exposedSecretLabels, dynamicLabels...)
	exposedSecretInfoLabels := []string{
		namespace,
		name,
		resource_kind,
		resource_name,
		container_name,
		image_registry,
		image_repository,
		image_tag,
		image_digest,
		secret_category,
		secret_rule_id,
		secret_target,
		secret_title,
		severity,
	}
	exposedSecretInfoLabels = append(exposedSecretInfoLabels, dynamicLabels...)
	configAuditLabels := []string{
		namespace,
		name,
		resource_kind,
		resource_name,
		severity,
	}
	configAuditLabels = append(configAuditLabels, dynamicLabels...)
	configAuditInfoLabels := []string{
		namespace,
		name,
		resource_kind,
		resource_name,
		config_audit_id,
		config_audit_title,
		config_audit_description,
		config_audit_category,
		config_audit_success,
		severity,
	}
	configAuditInfoLabels = append(configAuditInfoLabels, dynamicLabels...)
	rbacAssessmentLabels := []string{
		namespace,
		name,
		resource_kind,
		resource_name,
		severity,
	}
	rbacAssessmentLabels = append(rbacAssessmentLabels, dynamicLabels...)
	rbacAssessmentInfoLabels := []string{
		namespace,
		name,
		resource_kind,
		resource_name,
		rbac_assessment_id,
		rbac_assessment_title,
		rbac_assessment_description,
		rbac_assessment_category,
		rbac_assessment_success,
		severity,
	}
	rbacAssessmentInfoLabels = append(rbacAssessmentInfoLabels, dynamicLabels...)
	infraAssessmentLabels := []string{
		namespace,
		name,
		resource_kind,
		resource_name,
		severity,
	}
	infraAssessmentLabels = append(infraAssessmentLabels, dynamicLabels...)
	infraAssessmentInfoLabels := []string{
		namespace,
		name,
		resource_kind,
		resource_name,
		infra_assessment_id,
		infra_assessment_title,
		infra_assessment_description,
		infra_assessment_category,
		infra_assessment_success,
		severity,
	}
	infraAssessmentInfoLabels = append(infraAssessmentInfoLabels, dynamicLabels...)

	clusterComplianceLabels := []string{
		title,
		description,
		status,
	}
	clusterComplianceLabels = append(clusterComplianceLabels, dynamicLabels...)
	imageVulnDesc := prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "image", "vulnerabilities"),
		"Number of container image vulnerabilities",
		imageVulnLabels,
		nil,
	)
	vulnIdDesc := prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "vulnerability", "id"),
		"Number of container image vulnerabilities group by vulnerability id",
		vulnIdLabels,
		nil,
	)
	exposedSecretDesc := prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "image", "exposedsecrets"),
		"Number of image exposed secrets",
		exposedSecretLabels,
		nil,
	)
	exposedSecretInfoDesc := prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "exposedsecrets", "info"),
		"Number of container image exposed secrets group by secret rule id",
		exposedSecretInfoLabels,
		nil,
	)
	configAuditDesc := prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "resource", "configaudits"),
		"Number of failing resource configuration auditing checks",
		configAuditLabels,
		nil,
	)
	configAuditInfoDesc := prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "configaudits", "info"),
		"Number of failing resource configuration auditing checks Info",
		configAuditInfoLabels,
		nil,
	)
	rbacAssessmentDesc := prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "role", "rbacassessments"),
		"Number of rbac risky role assessment checks",
		rbacAssessmentLabels,
		nil,
	)
	rbacAssessmentInfoDesc := prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "rbacassessments", "info"),
		"Number of rbac risky role assessment checks Info",
		rbacAssessmentInfoLabels,
		nil,
	)
	clusterRbacAssessmentDesc := prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "clusterrole", "clusterrbacassessments"),
		"Number of rbac risky cluster role assessment checks",
		rbacAssessmentLabels[1:],
		nil,
	)
	infraAssessmentDesc := prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "resource", "infraassessments"),
		"Number of failing k8s infra assessment checks",
		infraAssessmentLabels,
		nil,
	)
	infraAssessmentInfoDesc := prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "infraassessments", "info"),
		"Number of failing k8s infra assessment checks Info",
		infraAssessmentInfoLabels,
		nil,
	)
	complianceDesc := prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "cluster", "compliance"),
		"cluster compliance report",
		clusterComplianceLabels,
		nil,
	)
	return metricDescriptors{
		imageVulnSeverities:       imageVulnSeverities,
		exposedSecretSeverities:   exposedSecretSeverities,
		configAuditSeverities:     configAuditSeverities,
		rbacAssessmentSeverities:  rbacAssessmentSeverities,
		infraAssessmentSeverities: infraAssessmentSeverities,
		complianceStatuses:        complainceStatuses,

		imageVulnLabels:           imageVulnLabels,
		vulnIdLabels:              vulnIdLabels,
		exposedSecretLabels:       exposedSecretLabels,
		exposedSecretInfoLabels:   exposedSecretInfoLabels,
		configAuditLabels:         configAuditLabels,
		configAuditInfoLabels:     configAuditInfoLabels,
		rbacAssessmentLabels:      rbacAssessmentLabels,
		rbacAssessmentInfoLabels:  rbacAssessmentInfoLabels,
		infraAssessmentLabels:     infraAssessmentLabels,
		infraAssessmentInfoLabels: infraAssessmentInfoLabels,
		complianceLabels:          clusterComplianceLabels,

		imageVulnDesc:             imageVulnDesc,
		vulnIdDesc:                vulnIdDesc,
		configAuditDesc:           configAuditDesc,
		configAuditInfoDesc:       configAuditInfoDesc,
		exposedSecretDesc:         exposedSecretDesc,
		exposedSecretInfoDesc:     exposedSecretInfoDesc,
		rbacAssessmentDesc:        rbacAssessmentDesc,
		rbacAssessmentInfoDesc:    rbacAssessmentInfoDesc,
		clusterRbacAssessmentDesc: clusterRbacAssessmentDesc,
		infraAssessmentDesc:       infraAssessmentDesc,
		infraAssessmentInfoDesc:   infraAssessmentInfoDesc,
		complianceDesc:            complianceDesc,
	}
}

func getDynamicConfigLabels(config trivyoperator.ConfigData) []string {
	labels := make([]string, 0)
	resourceLabels := config.GetReportResourceLabels()
	for _, label := range resourceLabels {
		labels = append(labels, config.GetMetricsResourceLabelsPrefix()+sanitizeLabelName(label))
	}
	return labels
}

func (c *ResourcesMetricsCollector) SetupWithManager(mgr ctrl.Manager) error {
	return mgr.Add(c)
}

func (c ResourcesMetricsCollector) Collect(metrics chan<- prometheus.Metric) {
	ctx := context.Background()

	targetNamespaces := c.Config.GetTargetNamespaces()
	if len(targetNamespaces) == 0 {
		targetNamespaces = append(targetNamespaces, "")
	}
	c.collectVulnerabilityReports(ctx, metrics, targetNamespaces)
	if c.Config.MetricsVulnerabilityId {
		c.collectVulnerabilityIdReports(ctx, metrics, targetNamespaces)
	}
	c.collectExposedSecretsReports(ctx, metrics, targetNamespaces)
	if c.Config.MetricsExposedSecretInfo {
		c.collectExposedSecretsInfoReports(ctx, metrics, targetNamespaces)
	}
	c.collectConfigAuditReports(ctx, metrics, targetNamespaces)
	if c.Config.MetricsConfigAuditInfo {
		c.collectConfigAuditInfoReports(ctx, metrics, targetNamespaces)
	}
	c.collectRbacAssessmentReports(ctx, metrics, targetNamespaces)
	if c.Config.MetricsRbacAssessmentInfo {
		c.collectRbacAssessmentInfoReports(ctx, metrics, targetNamespaces)
	}
	c.collectInfraAssessmentReports(ctx, metrics, targetNamespaces)
	if c.Config.MetricsInfraAssessmentInfo {
		c.collectInfraAssessmentInfoReports(ctx, metrics, targetNamespaces)
	}
	c.collectClusterRbacAssessmentReports(ctx, metrics)
	c.collectClusterComplianceReports(ctx, metrics)
}

func (c ResourcesMetricsCollector) collectVulnerabilityReports(ctx context.Context, metrics chan<- prometheus.Metric, targetNamespaces []string) {
	reports := &v1alpha1.VulnerabilityReportList{}
	labelValues := make([]string, len(c.imageVulnLabels))
	for _, n := range targetNamespaces {
		if err := c.List(ctx, reports, client.InNamespace(n)); err != nil {
			c.Logger.Error(err, "failed to list vulnerabilityreports from API", "namespace", n)
			continue
		}
		for _, r := range reports.Items {
			labelValues[0] = r.Namespace
			labelValues[1] = r.Name
			labelValues[2] = r.Labels[trivyoperator.LabelResourceKind]
			labelValues[3] = r.Labels[trivyoperator.LabelResourceName]
			labelValues[4] = r.Labels[trivyoperator.LabelContainerName]
			labelValues[5] = r.Report.Registry.Server
			labelValues[6] = r.Report.Artifact.Repository
			labelValues[7] = r.Report.Artifact.Tag
			labelValues[8] = r.Report.Artifact.Digest
			for i, label := range c.GetReportResourceLabels() {
				labelValues[i+10] = r.Labels[label]
			}
			for severity, countFn := range c.imageVulnSeverities {
				labelValues[9] = severity
				count := countFn(r.Report.Summary)
				metrics <- prometheus.MustNewConstMetric(c.imageVulnDesc, prometheus.GaugeValue, float64(count), labelValues...)
			}
		}
	}
}

func (c ResourcesMetricsCollector) collectVulnerabilityIdReports(ctx context.Context, metrics chan<- prometheus.Metric, targetNamespaces []string) {
	reports := &v1alpha1.VulnerabilityReportList{}
	vulnLabelValues := make([]string, len(c.vulnIdLabels))
	for _, n := range targetNamespaces {
		if err := c.List(ctx, reports, client.InNamespace(n)); err != nil {
			c.Logger.Error(err, "failed to list vulnerabilityreports from API", "namespace", n)
			continue
		}
		for _, r := range reports.Items {
			if c.Config.MetricsVulnerabilityId {
				vulnLabelValues[0] = r.Namespace
				vulnLabelValues[1] = r.Name
				vulnLabelValues[2] = r.Labels[trivyoperator.LabelResourceKind]
				vulnLabelValues[3] = r.Labels[trivyoperator.LabelResourceName]
				vulnLabelValues[4] = r.Labels[trivyoperator.LabelContainerName]
				vulnLabelValues[5] = r.Report.Registry.Server
				vulnLabelValues[6] = r.Report.Artifact.Repository
				vulnLabelValues[7] = r.Report.Artifact.Tag
				vulnLabelValues[8] = r.Report.Artifact.Digest
				for i, label := range c.GetReportResourceLabels() {
					vulnLabelValues[i+19] = r.Labels[label]
				}
				var vulnList = make(map[string]bool)
				for _, vuln := range r.Report.Vulnerabilities {
					vulnList[vuln.VulnerabilityID] = true
					vulnLabelValues[9] = vuln.InstalledVersion
					vulnLabelValues[10] = vuln.FixedVersion
					vulnLabelValues[11] = vuln.Resource
					vulnLabelValues[12] = NewSeverityLabel(vuln.Severity).Label
					vulnLabelValues[13] = vuln.PackageType
					vulnLabelValues[14] = vuln.PkgPath
					vulnLabelValues[15] = vuln.Class
					vulnLabelValues[16] = vuln.VulnerabilityID
					vulnLabelValues[17] = vuln.Title
					vulnLabelValues[18] = ""
					if vuln.Score != nil {
						vulnLabelValues[18] = strconv.FormatFloat(*vuln.Score, 'f', -1, 64)
					}
					metrics <- prometheus.MustNewConstMetric(c.vulnIdDesc, prometheus.GaugeValue, float64(1), vulnLabelValues...)
				}
			}
		}
	}
}

func (c ResourcesMetricsCollector) collectExposedSecretsReports(ctx context.Context, metrics chan<- prometheus.Metric, targetNamespaces []string) {
	reports := &v1alpha1.ExposedSecretReportList{}
	labelValues := make([]string, len(c.exposedSecretLabels))
	for _, n := range targetNamespaces {
		if err := c.List(ctx, reports, client.InNamespace(n)); err != nil {
			c.Logger.Error(err, "failed to list exposedsecretreports from API", "namespace", n)
			continue
		}
		for _, r := range reports.Items {
			labelValues[0] = r.Namespace
			labelValues[1] = r.Name
			labelValues[2] = r.Labels[trivyoperator.LabelResourceKind]
			labelValues[3] = r.Labels[trivyoperator.LabelResourceName]
			labelValues[4] = r.Labels[trivyoperator.LabelContainerName]
			labelValues[5] = r.Report.Registry.Server
			labelValues[6] = r.Report.Artifact.Repository
			labelValues[7] = r.Report.Artifact.Tag
			labelValues[8] = r.Report.Artifact.Digest
			for i, label := range c.GetReportResourceLabels() {
				labelValues[i+10] = r.Labels[label]
			}
			for severity, countFn := range c.exposedSecretSeverities {
				labelValues[9] = severity
				count := countFn(r.Report.Summary)
				metrics <- prometheus.MustNewConstMetric(c.exposedSecretDesc, prometheus.GaugeValue, float64(count), labelValues...)
			}
		}
	}
}

func (c ResourcesMetricsCollector) collectExposedSecretsInfoReports(ctx context.Context, metrics chan<- prometheus.Metric, targetNamespaces []string) {
	reports := &v1alpha1.ExposedSecretReportList{}
	labelValues := make([]string, len(c.exposedSecretInfoLabels))
	for _, n := range targetNamespaces {
		if err := c.List(ctx, reports, client.InNamespace(n)); err != nil {
			c.Logger.Error(err, "failed to list exposedsecretreports from API", "namespace", n)
			continue
		}
		for _, r := range reports.Items {
			if c.Config.MetricsExposedSecretInfo {
				labelValues[0] = r.Namespace
				labelValues[1] = r.Name
				labelValues[2] = r.Labels[trivyoperator.LabelResourceKind]
				labelValues[3] = r.Labels[trivyoperator.LabelResourceName]
				labelValues[4] = r.Labels[trivyoperator.LabelContainerName]
				labelValues[5] = r.Report.Registry.Server
				labelValues[6] = r.Report.Artifact.Repository
				labelValues[7] = r.Report.Artifact.Tag
				labelValues[8] = r.Report.Artifact.Digest
				for i, label := range c.GetReportResourceLabels() {
					labelValues[i+14] = r.Labels[label]
				}
				var secretList = make(map[string]bool)
				for _, secret := range r.Report.Secrets {
					secretHash := kube.ComputeHash(secret.Category + secret.RuleID + secret.Target + secret.Title + NewSeverityLabel(secret.Severity).Label)
					if secretList[secretHash] {
						continue
					}
					secretList[secretHash] = true
					labelValues[9] = secret.Category
					labelValues[10] = secret.RuleID
					labelValues[11] = secret.Target
					labelValues[12] = secret.Title
					labelValues[13] = NewSeverityLabel(secret.Severity).Label

					metrics <- prometheus.MustNewConstMetric(c.exposedSecretInfoDesc, prometheus.GaugeValue, float64(1), labelValues...)
				}
			}
		}
	}
}

func (c *ResourcesMetricsCollector) collectConfigAuditReports(ctx context.Context, metrics chan<- prometheus.Metric, targetNamespaces []string) {
	reports := &v1alpha1.ConfigAuditReportList{}
	labelValues := make([]string, len(c.configAuditLabels))
	for _, n := range targetNamespaces {
		if err := c.List(ctx, reports, client.InNamespace(n)); err != nil {
			c.Logger.Error(err, "failed to list configauditreports from API", "namespace", n)
			continue
		}
		for _, r := range reports.Items {
			labelValues[0] = r.Namespace
			labelValues[1] = r.Name
			labelValues[2] = r.Labels[trivyoperator.LabelResourceKind]
			labelValues[3] = r.Labels[trivyoperator.LabelResourceName]
			for i, label := range c.GetReportResourceLabels() {
				labelValues[i+5] = r.Labels[label]
			}
			for severity, countFn := range c.configAuditSeverities {
				labelValues[4] = severity
				count := countFn(r.Report.Summary)
				metrics <- prometheus.MustNewConstMetric(c.configAuditDesc, prometheus.GaugeValue, float64(count), labelValues...)
			}
		}
	}
}

func (c *ResourcesMetricsCollector) collectConfigAuditInfoReports(ctx context.Context, metrics chan<- prometheus.Metric, targetNamespaces []string) {
	reports := &v1alpha1.ConfigAuditReportList{}
	labelValues := make([]string, len(c.configAuditInfoLabels))
	for _, n := range targetNamespaces {
		if err := c.List(ctx, reports, client.InNamespace(n)); err != nil {
			c.Logger.Error(err, "failed to list configauditreports from API", "namespace", n)
			continue
		}
		for _, r := range reports.Items {
			if c.Config.MetricsConfigAuditInfo {
				labelValues[0] = r.Namespace
				labelValues[1] = r.Name
				labelValues[2] = r.Labels[trivyoperator.LabelResourceKind]
				labelValues[3] = r.Labels[trivyoperator.LabelResourceName]
				for _, config := range r.Report.Checks {
					labelValues[4] = config.ID
					labelValues[5] = config.Title
					labelValues[6] = config.Description
					labelValues[7] = config.Category
					labelValues[8] = strconv.FormatBool(config.Success)
					labelValues[9] = NewSeverityLabel(config.Severity).Label

					for i, label := range c.GetReportResourceLabels() {
						labelValues[i+10] = r.Labels[label]
					}

					metrics <- prometheus.MustNewConstMetric(c.configAuditInfoDesc, prometheus.GaugeValue, float64(1), labelValues...)

				}

			}
		}
	}
}

func (c *ResourcesMetricsCollector) collectRbacAssessmentReports(ctx context.Context, metrics chan<- prometheus.Metric, targetNamespaces []string) {
	reports := &v1alpha1.RbacAssessmentReportList{}
	labelValues := make([]string, len(c.rbacAssessmentLabels))
	for _, n := range targetNamespaces {
		if err := c.List(ctx, reports, client.InNamespace(n)); err != nil {
			c.Logger.Error(err, "failed to list rbacAssessment from API", "namespace", n)
			continue
		}
		for _, r := range reports.Items {
			labelValues[0] = r.Namespace
			labelValues[1] = r.Name
			labelValues[2] = r.Labels[trivyoperator.LabelResourceKind]
			labelValues[3] = r.Labels[trivyoperator.LabelResourceName]
			for i, label := range c.GetReportResourceLabels() {
				labelValues[i+5] = r.Labels[label]
			}
			c.populateRbacAssessmentValues(labelValues, c.rbacAssessmentDesc, r.Report.Summary, metrics, 4)
		}
	}
}

func (c *ResourcesMetricsCollector) collectRbacAssessmentInfoReports(ctx context.Context, metrics chan<- prometheus.Metric, targetNamespaces []string) {
	reports := &v1alpha1.RbacAssessmentReportList{}
	labelValues := make([]string, len(c.rbacAssessmentInfoLabels))
	for _, n := range targetNamespaces {
		if err := c.List(ctx, reports, client.InNamespace(n)); err != nil {
			c.Logger.Error(err, "failed to list rbacAssessment from API", "namespace", n)
			continue
		}
		for _, r := range reports.Items {
			if c.Config.MetricsRbacAssessmentInfo {
				labelValues[0] = r.Namespace
				labelValues[1] = r.Name
				labelValues[2] = r.Labels[trivyoperator.LabelResourceKind]
				labelValues[3] = r.Labels[trivyoperator.LabelResourceName]
				for _, rbac := range r.Report.Checks {
					labelValues[4] = rbac.ID
					labelValues[5] = rbac.Title
					labelValues[6] = rbac.Description
					labelValues[7] = rbac.Category
					labelValues[8] = strconv.FormatBool(rbac.Success)
					labelValues[9] = NewSeverityLabel(rbac.Severity).Label
					for i, label := range c.GetReportResourceLabels() {
						labelValues[i+10] = r.Labels[label]
					}

					metrics <- prometheus.MustNewConstMetric(c.rbacAssessmentInfoDesc, prometheus.GaugeValue, float64(1), labelValues...)
				}
			}
		}
	}
}

func (c *ResourcesMetricsCollector) collectInfraAssessmentReports(ctx context.Context, metrics chan<- prometheus.Metric, targetNamespaces []string) {
	reports := &v1alpha1.InfraAssessmentReportList{}
	labelValues := make([]string, len(c.infraAssessmentLabels))
	for _, n := range targetNamespaces {
		if err := c.List(ctx, reports, client.InNamespace(n)); err != nil {
			c.Logger.Error(err, "failed to list infraAssessment from API", "namespace", n)
			continue
		}
		for _, r := range reports.Items {
			labelValues[0] = r.Namespace
			labelValues[1] = r.Name
			labelValues[2] = r.Labels[trivyoperator.LabelResourceKind]
			labelValues[3] = r.Labels[trivyoperator.LabelResourceName]
			for i, label := range c.GetReportResourceLabels() {
				labelValues[i+5] = r.Labels[label]
			}
			c.populateInfraAssessmentValues(labelValues, c.infraAssessmentDesc, r.Report.Summary, metrics, 4)
		}
	}
}

func (c *ResourcesMetricsCollector) collectInfraAssessmentInfoReports(ctx context.Context, metrics chan<- prometheus.Metric, targetNamespaces []string) {
	reports := &v1alpha1.RbacAssessmentReportList{}
	labelValues := make([]string, len(c.infraAssessmentInfoLabels))
	for _, n := range targetNamespaces {
		if err := c.List(ctx, reports, client.InNamespace(n)); err != nil {
			c.Logger.Error(err, "failed to list infraAssessment from API", "namespace", n)
			continue
		}
		for _, r := range reports.Items {
			if c.Config.MetricsInfraAssessmentInfo {
				labelValues[0] = r.Namespace
				labelValues[1] = r.Name
				labelValues[2] = r.Labels[trivyoperator.LabelResourceKind]
				labelValues[3] = r.Labels[trivyoperator.LabelResourceName]
				for _, infra := range r.Report.Checks {
					labelValues[4] = infra.ID
					labelValues[5] = infra.Title
					labelValues[6] = infra.Description
					labelValues[7] = infra.Category
					labelValues[8] = strconv.FormatBool(infra.Success)
					labelValues[9] = NewSeverityLabel(infra.Severity).Label
					for i, label := range c.GetReportResourceLabels() {
						labelValues[i+10] = r.Labels[label]
					}

					metrics <- prometheus.MustNewConstMetric(c.infraAssessmentInfoDesc, prometheus.GaugeValue, float64(1), labelValues...)
				}
			}
		}
	}
}

func (c *ResourcesMetricsCollector) collectClusterRbacAssessmentReports(ctx context.Context, metrics chan<- prometheus.Metric) {
	reports := &v1alpha1.ClusterRbacAssessmentReportList{}
	labelValues := make([]string, len(c.rbacAssessmentLabels[1:]))
	if err := c.List(ctx, reports); err != nil {
		c.Logger.Error(err, "failed to list cluster rbacAssessment from API")
		return
	}
	for _, r := range reports.Items {
		labelValues[0] = r.Name
		labelValues[1] = r.Labels[trivyoperator.LabelResourceKind]
		labelValues[2] = r.Labels[trivyoperator.LabelResourceName]
		for i, label := range c.GetReportResourceLabels() {
			labelValues[i+4] = r.Labels[label]
		}
		c.populateRbacAssessmentValues(labelValues, c.clusterRbacAssessmentDesc, r.Report.Summary, metrics, 3)
	}
}

func (c *ResourcesMetricsCollector) collectClusterComplianceReports(ctx context.Context, metrics chan<- prometheus.Metric) {
	reports := &v1alpha1.ClusterComplianceReportList{}
	labelValues := make([]string, len(c.complianceLabels[0:]))
	if err := c.List(ctx, reports); err != nil {
		c.Logger.Error(err, "failed to list cluster compliance from API")
		return
	}
	for _, r := range reports.Items {
		labelValues[0] = r.Spec.Complaince.Title
		labelValues[1] = r.Spec.Complaince.Description
		for i, label := range c.GetReportResourceLabels() {
			labelValues[i+3] = r.Labels[label]
		}
		c.populateComplianceValues(labelValues, c.complianceDesc, r.Status.Summary, metrics, 2)
	}
}

func (c *ResourcesMetricsCollector) populateComplianceValues(labelValues []string, desc *prometheus.Desc, summary v1alpha1.ComplianceSummary, metrics chan<- prometheus.Metric, index int) {
	for status, countFn := range c.complianceStatuses {
		labelValues[index] = status
		count := countFn(summary)
		metrics <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, float64(count), labelValues...)
	}
}

func (c *ResourcesMetricsCollector) populateRbacAssessmentValues(labelValues []string, desc *prometheus.Desc, summary v1alpha1.RbacAssessmentSummary, metrics chan<- prometheus.Metric, index int) {
	for severity, countFn := range c.rbacAssessmentSeverities {
		labelValues[index] = severity
		count := countFn(summary)
		metrics <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, float64(count), labelValues...)
	}
}

func (c *ResourcesMetricsCollector) populateInfraAssessmentValues(labelValues []string, desc *prometheus.Desc, summary v1alpha1.InfraAssessmentSummary, metrics chan<- prometheus.Metric, index int) {
	for severity, countFn := range c.infraAssessmentSeverities {
		labelValues[index] = severity
		count := countFn(summary)
		metrics <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, float64(count), labelValues...)
	}
}

func (c ResourcesMetricsCollector) Describe(descs chan<- *prometheus.Desc) {
	descs <- c.imageVulnDesc
	descs <- c.vulnIdDesc
	descs <- c.configAuditDesc
	descs <- c.configAuditInfoDesc
	descs <- c.exposedSecretDesc
	descs <- c.exposedSecretInfoDesc
	descs <- c.rbacAssessmentDesc
	descs <- c.rbacAssessmentInfoDesc
	descs <- c.infraAssessmentDesc
	descs <- c.infraAssessmentInfoDesc
	descs <- c.clusterRbacAssessmentDesc
	descs <- c.complianceDesc
}

func (c ResourcesMetricsCollector) Start(ctx context.Context) error {
	c.Logger.Info("Registering resources metrics collector")
	if err := k8smetrics.Registry.Register(c); err != nil {
		return err
	}

	// Block until the context is done.
	<-ctx.Done()

	c.Logger.Info("Unregistering resources metrics collector")
	k8smetrics.Registry.Unregister(c)
	return nil
}

func (c ResourcesMetricsCollector) NeedLeaderElection() bool {
	return true
}

// Ensure ResourcesMetricsCollector is leader-election aware
var _ manager.LeaderElectionRunnable = &ResourcesMetricsCollector{}
