package v1alpha1_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/shared"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

func TestInfraAssessmentSummaryFromChecks(t *testing.T) {
	checks := []v1alpha1.Check{
		{
			Severity: shared.SeverityCritical,
		},
		{
			Severity: shared.SeverityCritical,
			Success:  true,
		},
		{
			Severity: shared.SeverityHigh,
		},
		{
			Severity: shared.SeverityHigh,
			Success:  true,
		},
		{
			Severity: shared.SeverityCritical,
		},
		{
			Severity: shared.SeverityCritical,
			Success:  true,
		},
		{
			Severity: shared.SeverityMedium,
		},
		{
			Severity: shared.SeverityMedium,
			Success:  true,
		},
		{
			Severity: shared.SeverityMedium,
		},
		{
			Severity: shared.SeverityMedium,
			Success:  true,
		},
		{
			Severity: shared.SeverityMedium,
		},
		{
			Severity: shared.SeverityMedium,
			Success:  true,
		},
		{
			Severity: shared.SeverityLow,
		},
		{
			Severity: shared.SeverityLow,
			Success:  true,
		},
	}
	summary := v1alpha1.InfraAssessmentSummaryFromChecks(checks)
	assert.Equal(t, v1alpha1.InfraAssessmentSummary{
		CriticalCount: 2,
		HighCount:     1,
		MediumCount:   3,
		LowCount:      1,
	}, summary)
}
