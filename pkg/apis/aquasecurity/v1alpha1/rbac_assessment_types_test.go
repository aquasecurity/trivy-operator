package v1alpha1_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

func TestRbacAssessmentSummaryFromChecks(t *testing.T) {
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
	summary := v1alpha1.RbacAssessmentSummaryFromChecks(checks)
	assert.Equal(t, v1alpha1.RbacAssessmentSummary{
		CriticalCount: 2,
		HighCount:     1,
		MediumCount:   3,
		LowCount:      1,
	}, summary)
}
