package jobs

import (
	"context"

	"github.com/aquasecurity/trivy-operator/pkg/config"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	batchv1 "k8s.io/api/batch/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type LimitChecker interface {
	Check(ctx context.Context) (bool, int, error)
}

func NewLimitChecker(cfg config.Config, c client.Client) LimitChecker {
	return &checker{
		cfg:    cfg,
		client: c,
	}
}

type checker struct {
	cfg    config.Config
	client client.Client
}

func (c *checker) Check(ctx context.Context) (bool, int, error) {
	scanJobsCount, err := c.countScanJobs(ctx)
	if err != nil {
		return false, 0, err
	}

	return scanJobsCount >= c.cfg.ConcurrentScanJobsLimit(), scanJobsCount, nil
}

func (c *checker) countScanJobs(ctx context.Context) (int, error) {
	var scanJobs batchv1.JobList
	listOptions := []client.ListOption{client.MatchingLabels{
		trivyoperator.LabelK8SAppManagedBy: trivyoperator.AppTrivyOperator,
	}}
	if !c.cfg.VulnerabilityScanJobsInSameNamespace() {
		// scan jobs are running in only trivyoperator operator namespace
		listOptions = append(listOptions, client.InNamespace(c.cfg.Namespace()))
	}
	err := c.client.List(ctx, &scanJobs, listOptions...)
	if err != nil {
		return 0, err
	}

	return len(scanJobs.Items), nil
}
