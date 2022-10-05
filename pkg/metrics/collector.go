package metrics

import (
	"context"

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
	namespace        = "namespace"
	name             = "name"
	image_registry   = "image_registry"
	image_repository = "image_repository"
	image_tag        = "image_tag"
	image_digest     = "image_digest"
	severity         = "severity"
	vuln_id          = "vuln_id"
)

var (
	imageVulnLabels = []string{
		namespace,
		name,
		image_registry,
		image_repository,
		image_tag,
		image_digest,
		severity,
	}
	vulnIdLabels = []string{
		namespace,
		name,
		image_registry,
		image_repository,
		image_tag,
		image_digest,
		severity,
		vuln_id,
	}
	imageVulnDesc = prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "image", "vulnerabilities"),
		"Number of container image vulnerabilities",
		imageVulnLabels,
		nil,
	)
	vulnIdDesc = prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "vulnerability", "id"),
		"Number of container image vulnerabilities group by vulnerability id",
		vulnIdLabels,
		nil,
	)
	imageVulnSeverities = map[string]func(vs v1alpha1.VulnerabilitySummary) int{
		"Critical": func(vs v1alpha1.VulnerabilitySummary) int {
			return vs.CriticalCount
		},
		"High": func(vs v1alpha1.VulnerabilitySummary) int {
			return vs.HighCount
		},
		"Medium": func(vs v1alpha1.VulnerabilitySummary) int {
			return vs.MediumCount
		},
		"Low": func(vs v1alpha1.VulnerabilitySummary) int {
			return vs.LowCount
		},
		"Unknown": func(vs v1alpha1.VulnerabilitySummary) int {
			return vs.UnknownCount
		},
	}
	exposedSecretLabels = []string{
		namespace,
		name,
		image_registry,
		image_repository,
		image_tag,
		image_digest,
		severity,
	}
	exposedSecretDesc = prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "image", "exposedsecrets"),
		"Number of image exposed secrets",
		exposedSecretLabels,
		nil,
	)
	exposedSecretSeverities = map[string]func(vs v1alpha1.ExposedSecretSummary) int{
		"Critical": func(vs v1alpha1.ExposedSecretSummary) int {
			return vs.CriticalCount
		},
		"High": func(vs v1alpha1.ExposedSecretSummary) int {
			return vs.HighCount
		},
		"Medium": func(vs v1alpha1.ExposedSecretSummary) int {
			return vs.MediumCount
		},
		"Low": func(vs v1alpha1.ExposedSecretSummary) int {
			return vs.LowCount
		},
	}
	configAuditLabels = []string{
		namespace,
		name,
		severity,
	}
	configAuditDesc = prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "resource", "configaudits"),
		"Number of failing resource configuration auditing checks",
		configAuditLabels,
		nil,
	)
	configAuditSeverities = map[string]func(vs v1alpha1.ConfigAuditSummary) int{
		"Critical": func(cas v1alpha1.ConfigAuditSummary) int {
			return cas.CriticalCount
		},
		"High": func(cas v1alpha1.ConfigAuditSummary) int {
			return cas.HighCount
		},
		"Medium": func(cas v1alpha1.ConfigAuditSummary) int {
			return cas.MediumCount
		},
		"Low": func(cas v1alpha1.ConfigAuditSummary) int {
			return cas.LowCount
		},
	}
	rbacAssessmentLabels = []string{
		namespace,
		name,
		severity,
	}
	rbacAssessmentDesc = prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "role", "rbacassessments"),
		"Number of rbac risky role assessment checks",
		rbacAssessmentLabels,
		nil,
	)
	clusterRbacAssessmentDesc = prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "clusterrole", "clusterrbacassessments"),
		"Number of rbac risky cluster role assessment checks",
		rbacAssessmentLabels[1:],
		nil,
	)
	rbacAssessmentSeverities = map[string]func(vs v1alpha1.RbacAssessmentSummary) int{
		"Critical": func(cas v1alpha1.RbacAssessmentSummary) int {
			return cas.CriticalCount
		},
		"High": func(cas v1alpha1.RbacAssessmentSummary) int {
			return cas.HighCount
		},
		"Medium": func(cas v1alpha1.RbacAssessmentSummary) int {
			return cas.MediumCount
		},
		"Low": func(cas v1alpha1.RbacAssessmentSummary) int {
			return cas.LowCount
		},
	}
)

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
	client.Client
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
	c.collectExposedSecretsReports(ctx, metrics, targetNamespaces)
	c.collectConfigAuditReports(ctx, metrics, targetNamespaces)
	c.collectRbacAssessmentReports(ctx, metrics, targetNamespaces)
	c.collectClusterRbacAssessmentReports(ctx, metrics)
}

func (c ResourcesMetricsCollector) collectVulnerabilityReports(ctx context.Context, metrics chan<- prometheus.Metric, targetNamespaces []string) {
	reports := &v1alpha1.VulnerabilityReportList{}
	labelValues := make([]string, len(imageVulnLabels))
	vulnLabelValues := make([]string, len(vulnIdLabels))
	for _, n := range targetNamespaces {
		if err := c.List(ctx, reports, client.InNamespace(n)); err != nil {
			c.Logger.Error(err, "failed to list vulnerabilityreports from API", "namespace", n)
			continue
		}
		for _, r := range reports.Items {
			labelValues[0] = r.Namespace
			labelValues[1] = r.Name
			labelValues[2] = r.Report.Registry.Server
			labelValues[3] = r.Report.Artifact.Repository
			labelValues[4] = r.Report.Artifact.Tag
			labelValues[5] = r.Report.Artifact.Digest
			for severity, countFn := range imageVulnSeverities {
				labelValues[6] = severity
				count := countFn(r.Report.Summary)
				metrics <- prometheus.MustNewConstMetric(imageVulnDesc, prometheus.GaugeValue, float64(count), labelValues...)
			}
			if c.Config.MetricsVulnerabilityId {
				vulnLabelValues[0] = r.Namespace
				vulnLabelValues[1] = r.Name
				vulnLabelValues[2] = r.Report.Registry.Server
				vulnLabelValues[3] = r.Report.Artifact.Repository
				vulnLabelValues[4] = r.Report.Artifact.Tag
				vulnLabelValues[5] = r.Report.Artifact.Digest
				var vulnList = make(map[string]bool)
				for _, vuln := range r.Report.Vulnerabilities {
					if vulnList[vuln.VulnerabilityID] {
						continue
					}
					vulnList[vuln.VulnerabilityID] = true
					vulnLabelValues[6] = string(vuln.Severity)
					vulnLabelValues[7] = vuln.VulnerabilityID
					metrics <- prometheus.MustNewConstMetric(vulnIdDesc, prometheus.GaugeValue, float64(1), vulnLabelValues...)
				}
			}
		}
	}
}

func (c ResourcesMetricsCollector) collectExposedSecretsReports(ctx context.Context, metrics chan<- prometheus.Metric, targetNamespaces []string) {
	reports := &v1alpha1.ExposedSecretReportList{}
	labelValues := make([]string, len(exposedSecretLabels))
	for _, n := range targetNamespaces {
		if err := c.List(ctx, reports, client.InNamespace(n)); err != nil {
			c.Logger.Error(err, "failed to list exposedsecretreports from API", "namespace", n)
			continue
		}
		for _, r := range reports.Items {
			labelValues[0] = r.Namespace
			labelValues[1] = r.Name
			labelValues[2] = r.Report.Registry.Server
			labelValues[3] = r.Report.Artifact.Repository
			labelValues[4] = r.Report.Artifact.Tag
			labelValues[5] = r.Report.Artifact.Digest
			for severity, countFn := range exposedSecretSeverities {
				labelValues[6] = severity
				count := countFn(r.Report.Summary)
				metrics <- prometheus.MustNewConstMetric(exposedSecretDesc, prometheus.GaugeValue, float64(count), labelValues...)
			}
		}
	}
}

func (c *ResourcesMetricsCollector) collectConfigAuditReports(ctx context.Context, metrics chan<- prometheus.Metric, targetNamespaces []string) {
	reports := &v1alpha1.ConfigAuditReportList{}
	labelValues := make([]string, len(configAuditLabels))
	for _, n := range targetNamespaces {
		if err := c.List(ctx, reports, client.InNamespace(n)); err != nil {
			c.Logger.Error(err, "failed to list configauditreports from API", "namespace", n)
			continue
		}
		for _, r := range reports.Items {
			labelValues[0] = r.Namespace
			labelValues[1] = r.Name
			for severity, countFn := range configAuditSeverities {
				labelValues[2] = severity
				count := countFn(r.Report.Summary)
				metrics <- prometheus.MustNewConstMetric(configAuditDesc, prometheus.GaugeValue, float64(count), labelValues...)
			}
		}
	}
}

func (c *ResourcesMetricsCollector) collectRbacAssessmentReports(ctx context.Context, metrics chan<- prometheus.Metric, targetNamespaces []string) {
	reports := &v1alpha1.RbacAssessmentReportList{}
	labelValues := make([]string, len(rbacAssessmentLabels))
	for _, n := range targetNamespaces {
		if err := c.List(ctx, reports, client.InNamespace(n)); err != nil {
			c.Logger.Error(err, "failed to list rbacAssessment from API", "namespace", n)
			continue
		}
		for _, r := range reports.Items {
			labelValues[0] = r.Namespace
			labelValues[1] = r.Name
			c.populateRbacAssessmentValues(labelValues, rbacAssessmentDesc, r.Report.Summary, metrics, 2)
		}
	}
}

func (c *ResourcesMetricsCollector) collectClusterRbacAssessmentReports(ctx context.Context, metrics chan<- prometheus.Metric) {
	reports := &v1alpha1.ClusterRbacAssessmentReportList{}
	labelValues := make([]string, len(rbacAssessmentLabels[1:]))
	if err := c.List(ctx, reports); err != nil {
		c.Logger.Error(err, "failed to list cluster rbacAssessment from API")
		return
	}
	for _, r := range reports.Items {
		labelValues[0] = r.Name
		c.populateRbacAssessmentValues(labelValues, clusterRbacAssessmentDesc, r.Report.Summary, metrics, 1)
	}
}

func (c *ResourcesMetricsCollector) populateRbacAssessmentValues(labelValues []string, desc *prometheus.Desc, summary v1alpha1.RbacAssessmentSummary, metrics chan<- prometheus.Metric, index int) {
	for severity, countFn := range rbacAssessmentSeverities {
		labelValues[index] = severity
		count := countFn(summary)
		metrics <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, float64(count), labelValues...)
	}
}

func (c ResourcesMetricsCollector) Describe(descs chan<- *prometheus.Desc) {
	descs <- imageVulnDesc
	descs <- vulnIdDesc
	descs <- configAuditDesc
	descs <- exposedSecretDesc
	descs <- rbacAssessmentDesc
	descs <- clusterRbacAssessmentDesc
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
