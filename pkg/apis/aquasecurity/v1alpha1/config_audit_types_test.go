package v1alpha1_test

import (
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func TestConfigAuditSummaryFromChecks(t *testing.T) {
	checks := []v1alpha1.Check{
		{
			Severity: v1alpha1.SeverityCritical,
		},
		{
			Severity: v1alpha1.SeverityCritical,
			Success:  true,
		},
		{
			Severity: v1alpha1.SeverityHigh,
		},
		{
			Severity: v1alpha1.SeverityHigh,
			Success:  true,
		},
		{
			Severity: v1alpha1.SeverityCritical,
		},
		{
			Severity: v1alpha1.SeverityCritical,
			Success:  true,
		},
		{
			Severity: v1alpha1.SeverityMedium,
		},
		{
			Severity: v1alpha1.SeverityMedium,
			Success:  true,
		},
		{
			Severity: v1alpha1.SeverityMedium,
		},
		{
			Severity: v1alpha1.SeverityMedium,
			Success:  true,
		},
		{
			Severity: v1alpha1.SeverityMedium,
		},
		{
			Severity: v1alpha1.SeverityMedium,
			Success:  true,
		},
		{
			Severity: v1alpha1.SeverityLow,
		},
		{
			Severity: v1alpha1.SeverityLow,
			Success:  true,
		},
	}
	summary := v1alpha1.ConfigAuditSummaryFromChecks(checks)
	assert.Equal(t, v1alpha1.ConfigAuditSummary{
		CriticalCount: 2,
		HighCount:     1,
		MediumCount:   3,
		LowCount:      1,
	}, summary)
}
