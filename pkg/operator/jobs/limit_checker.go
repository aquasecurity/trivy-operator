package jobs

import (
	"context"

	batchv1 "k8s.io/api/batch/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

const ScannerName = "Trivy"

type LimitChecker interface {
	Check(ctx context.Context) (bool, int, error)
	CheckNodes(ctx context.Context) (bool, int, error)
}

func NewLimitChecker(config etc.Config, c client.Client, trivyOperatorConfig trivyoperator.ConfigData) LimitChecker {
	return &checker{
		config:              config,
		client:              c,
		trivyOperatorConfig: trivyOperatorConfig,
	}
}

type checker struct {
	config              etc.Config
	client              client.Client
	trivyOperatorConfig trivyoperator.ConfigData
}

func (c *checker) Check(ctx context.Context) (bool, int, error) {
	matchinglabels := client.MatchingLabels{
		trivyoperator.LabelK8SAppManagedBy:            trivyoperator.AppTrivyOperator,
		trivyoperator.LabelVulnerabilityReportScanner: ScannerName,
	}
	scanJobsCount, err := c.countJobs(ctx, matchinglabels)
	if err != nil {
		return false, 0, err
	}

	return scanJobsCount >= c.config.ConcurrentScanJobsLimit, scanJobsCount, nil
}

func (c *checker) CheckNodes(ctx context.Context) (bool, int, error) {
	matchinglabels := client.MatchingLabels{
		trivyoperator.LabelK8SAppManagedBy:   trivyoperator.AppTrivyOperator,
		trivyoperator.LabelNodeInfoCollector: ScannerName,
	}
	scanJobsCount, err := c.countJobs(ctx, matchinglabels)
	if err != nil {
		return false, 0, err
	}

	return scanJobsCount >= c.config.ConcurrentNodeCollectorLimit, scanJobsCount, nil
}

func (c *checker) countJobs(ctx context.Context, matchingLabels client.MatchingLabels) (int, error) {
	var scanJobs batchv1.JobList
	listOptions := []client.ListOption{matchingLabels}
	if !c.trivyOperatorConfig.VulnerabilityScanJobsInSameNamespace() {
		// scan jobs are running in only trivyoperator operator namespace
		listOptions = append(listOptions, client.InNamespace(c.config.Namespace))
	}
	err := c.client.List(ctx, &scanJobs, listOptions...)
	if err != nil {
		return 0, err
	}

	return len(scanJobs.Items), nil
}
