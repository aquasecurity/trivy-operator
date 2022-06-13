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

var (
	imageVulnLabels = []string{
		"namespace",
		"name",
		"image_registry",
		"image_repository",
		"image_tag",
		"image_digest",
		"severity",
	}
	imageVulnDesc = prometheus.NewDesc(
		prometheus.BuildFQName("trivy", "vulnerabilityreport", "image_vulnerabilities"),
		"Number of container image vulnerabilities",
		imageVulnLabels,
		nil,
	)
	severities = map[string]func(vs v1alpha1.VulnerabilitySummary) int{
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
)

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
}

func (c ResourcesMetricsCollector) collectVulnerabilityReports(ctx context.Context, metrics chan<- prometheus.Metric, targetNamespaces []string) {
	vrList := &v1alpha1.VulnerabilityReportList{}
	labelValues := make([]string, 7)
	for _, n := range targetNamespaces {
		if err := c.List(ctx, vrList, client.InNamespace(n)); err != nil {
			c.Logger.Error(err, "failed to list vulnerabilityreports from API", "namespace", n)
			continue
		}
		for _, vr := range vrList.Items {
			labelValues[0] = vr.Namespace
			labelValues[1] = vr.Name
			labelValues[2] = vr.Report.Registry.Server
			labelValues[3] = vr.Report.Artifact.Repository
			labelValues[4] = vr.Report.Artifact.Tag
			labelValues[5] = vr.Report.Artifact.Digest
			for severity, countFn := range severities {
				labelValues[6] = severity
				count := countFn(vr.Report.Summary)
				metrics <- prometheus.MustNewConstMetric(imageVulnDesc, prometheus.GaugeValue, float64(count), labelValues...)
			}
		}
	}
}

func (c ResourcesMetricsCollector) Describe(descs chan<- *prometheus.Desc) {
	descs <- imageVulnDesc
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
