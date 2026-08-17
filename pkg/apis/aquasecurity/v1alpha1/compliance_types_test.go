package v1alpha1

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/compliance/report"
	ttypes "github.com/aquasecurity/trivy/pkg/types"
)

// complianceReportWith builds a report whose single control fails on n targets.
func complianceReportWith(n int) *report.ComplianceReport {
	results := make([]ttypes.Result, 0, n)
	for i := 0; i < n; i++ {
		results = append(results, ttypes.Result{
			Target: fmt.Sprintf("default/replicaset-app-%d", i),
			Misconfigurations: []ttypes.DetectedMisconfiguration{
				{
					ID:         "KSV0021",
					Title:      "Runs with GID <= 10000",
					Message:    "Force the container to run with group ID > 10000",
					Severity:   "LOW",
					Resolution: "Set 'containers[].securityContext.runAsGroup' to an integer > 10000.",
				},
			},
		})
	}
	return &report.ComplianceReport{
		ID:    "k8s-cis-1.23",
		Title: "CIS Kubernetes Benchmarks v1.23",
		Results: []*report.ControlCheckResult{
			{
				ID:       "5.7.3",
				Name:     "Apply Security Context to Your Pods and Containers",
				Severity: "LOW",
				Results:  results,
			},
		},
	}
}

func TestFromDetailReport_FailEntriesLimit(t *testing.T) {
	tests := []struct {
		name       string
		failures   int
		limit      int
		wantChecks int
	}{
		{name: "caps the checks kept per control", failures: 1000, limit: 10, wantChecks: 10},
		{name: "keeps everything below the limit", failures: 3, limit: 10, wantChecks: 3},
		{name: "zero means no limit", failures: 25, limit: 0, wantChecks: 25},
		{name: "negative means no limit", failures: 25, limit: -1, wantChecks: 25},
		{name: "limit of one still records the control as failing", failures: 500, limit: 1, wantChecks: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromDetailReport(complianceReportWith(tt.failures), tt.limit)
			assert.Len(t, got.Results, 1)
			assert.Len(t, got.Results[0].Checks, tt.wantChecks)
			for _, c := range got.Results[0].Checks {
				assert.False(t, c.Success)
			}
		})
	}
}

// A control with no misconfiguration must still get its synthetic passing check,
// whatever the limit is.
func TestFromDetailReport_PassingControl(t *testing.T) {
	for _, limit := range []int{0, 1, 10} {
		got := FromDetailReport(complianceReportWith(0), limit)
		assert.Len(t, got.Results, 1)
		assert.Len(t, got.Results[0].Checks, 1)
		assert.True(t, got.Results[0].Checks[0].Success)
	}
}
