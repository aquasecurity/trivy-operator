package report

import (
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/report/templates"
	"github.com/stretchr/testify/assert"
)

func TestOrderedBy(t *testing.T) {
	checks := []templates.CheckWithCount{
		{
			Check: v1alpha1.Check{
				ID:       "privilegeEscalationAllowed",
				Severity: "danger",
				Category: "Security",
			},
			AffectedWorkloads: 10,
		},
		{
			Check: v1alpha1.Check{
				ID:       "cpuLimitsMissing",
				Severity: "warning",
				Category: "Efficiency",
			},
			AffectedWorkloads: 12,
		},
		{
			Check: v1alpha1.Check{
				ID:       "cpuRequestsMissing",
				Severity: "warning",
				Category: "Efficiency",
			},
			AffectedWorkloads: 8,
		},
		{
			Check: v1alpha1.Check{
				ID:       "livenessProbeMissing",
				Severity: "warning",
				Category: "Reliability",
			},
			AffectedWorkloads: 5,
		},
		{
			Check: v1alpha1.Check{
				ID:       "insecureCapabilities",
				Severity: "warning",
				Category: "Security",
			},
			AffectedWorkloads: 5,
		},
	}

	OrderedBy(checkCompareFunc...).SortDesc(checks)
	assert.Equal(t, []templates.CheckWithCount{
		{
			Check: v1alpha1.Check{
				ID:       "cpuLimitsMissing",
				Severity: "warning",
				Category: "Efficiency",
			},
			AffectedWorkloads: 12,
		},
		{
			Check: v1alpha1.Check{
				ID:       "privilegeEscalationAllowed",
				Severity: "danger",
				Category: "Security",
			},
			AffectedWorkloads: 10,
		},
		{
			Check: v1alpha1.Check{
				ID:       "cpuRequestsMissing",
				Severity: "warning",
				Category: "Efficiency",
			},
			AffectedWorkloads: 8,
		},
		{
			Check: v1alpha1.Check{
				ID:       "insecureCapabilities",
				Severity: "warning",
				Category: "Security",
			},
			AffectedWorkloads: 5,
		},
		{
			Check: v1alpha1.Check{
				ID:       "livenessProbeMissing",
				Severity: "warning",
				Category: "Reliability",
			},
			AffectedWorkloads: 5,
		},
	}, checks)
}
