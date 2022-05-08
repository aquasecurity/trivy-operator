package report

import (
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/report/templates"
	"github.com/stretchr/testify/assert"
	"k8s.io/utils/pointer"
)

func Test_topNVulnerabilitiesByScore(t *testing.T) {
	testCases := []struct {
		name           string
		reports        []v1alpha1.VulnerabilityReport
		expectedOutput []templates.VulnerabilityWithCount
	}{
		{
			name: "Should return top 5 vulnerabilities with count",
			reports: []v1alpha1.VulnerabilityReport{
				{
					Report: v1alpha1.VulnerabilityReportData{
						Vulnerabilities: []v1alpha1.Vulnerability{
							{
								VulnerabilityID: "CVE-2019-1549",
								Severity:        v1alpha1.SeverityCritical,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1549",
								Score:           pointer.Float64Ptr(8.2),
							},
							{
								VulnerabilityID: "CVE-2019-1547",
								Severity:        v1alpha1.SeverityLow,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1547",
								Score:           pointer.Float64Ptr(6.3),
							},
							{
								VulnerabilityID: "CVE-2011-3374",
								Severity:        v1alpha1.SeverityMedium,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2011-3374",
								Score:           pointer.Float64Ptr(3.7),
							},
						},
					},
				},
				{
					Report: v1alpha1.VulnerabilityReportData{
						Vulnerabilities: []v1alpha1.Vulnerability{
							{
								VulnerabilityID: "CVE-2019-1548",
								Severity:        v1alpha1.SeverityCritical,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1548",
								Score:           pointer.Float64Ptr(9.1),
							},
							{
								VulnerabilityID: "CVE-2019-1547",
								Severity:        v1alpha1.SeverityLow,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1547",
								Score:           pointer.Float64Ptr(6.3),
							},
							{
								VulnerabilityID: "CVE-2020-27350",
								Severity:        v1alpha1.SeverityMedium,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2020-27350",
								Score:           pointer.Float64Ptr(5.7),
							},
							{
								VulnerabilityID: "CVE-2011-3374",
								Severity:        v1alpha1.SeverityMedium,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2011-3374",
								Score:           pointer.Float64Ptr(3.7),
							},
							{
								VulnerabilityID: "CVE-2011-3375",
								Severity:        v1alpha1.SeverityMedium,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2011-3374",
								Score:           pointer.Float64Ptr(3.6),
							},
						},
					},
				},
			},
			expectedOutput: []templates.VulnerabilityWithCount{
				{
					Vulnerability: v1alpha1.Vulnerability{
						VulnerabilityID: "CVE-2019-1548",
						Severity:        v1alpha1.SeverityCritical,
						PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1548",
						Score:           pointer.Float64Ptr(9.1),
					},
					AffectedWorkloads: 1,
				},
				{
					Vulnerability: v1alpha1.Vulnerability{
						VulnerabilityID: "CVE-2019-1549",
						Severity:        v1alpha1.SeverityCritical,
						PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1549",
						Score:           pointer.Float64Ptr(8.2),
					},
					AffectedWorkloads: 1,
				},
				{
					Vulnerability: v1alpha1.Vulnerability{
						VulnerabilityID: "CVE-2019-1547",
						Severity:        v1alpha1.SeverityLow,
						PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1547",
						Score:           pointer.Float64Ptr(6.3),
					},
					AffectedWorkloads: 2,
				},
				{
					Vulnerability: v1alpha1.Vulnerability{
						VulnerabilityID: "CVE-2020-27350",
						Severity:        v1alpha1.SeverityMedium,
						PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2020-27350",
						Score:           pointer.Float64Ptr(5.7),
					},
					AffectedWorkloads: 1,
				},
				{
					Vulnerability: v1alpha1.Vulnerability{
						VulnerabilityID: "CVE-2011-3374",
						Severity:        v1alpha1.SeverityMedium,
						PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2011-3374",
						Score:           pointer.Float64Ptr(3.7),
					},
					AffectedWorkloads: 2,
				},
			},
		},
		{
			name: "Should return 2 vulnerabilities with count when some input has nil scores",
			reports: []v1alpha1.VulnerabilityReport{
				{
					Report: v1alpha1.VulnerabilityReportData{
						Vulnerabilities: []v1alpha1.Vulnerability{
							{
								VulnerabilityID: "CVE-2019-1549",
								Severity:        v1alpha1.SeverityCritical,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1549",
								Score:           pointer.Float64Ptr(8.2),
							},
							{
								VulnerabilityID: "CVE-2019-1547",
								Severity:        v1alpha1.SeverityLow,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1547",
								Score:           nil,
							},
							{
								VulnerabilityID: "CVE-2011-3374",
								Severity:        v1alpha1.SeverityMedium,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2011-3374",
								Score:           pointer.Float64Ptr(3.7),
							},
						},
					},
				},
				{
					Report: v1alpha1.VulnerabilityReportData{
						Vulnerabilities: []v1alpha1.Vulnerability{
							{
								VulnerabilityID: "CVE-2019-1548",
								Severity:        v1alpha1.SeverityCritical,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1548",
								Score:           nil,
							},
							{
								VulnerabilityID: "CVE-2019-1547",
								Severity:        v1alpha1.SeverityLow,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1547",
								Score:           nil,
							},
							{
								VulnerabilityID: "CVE-2020-27350",
								Severity:        v1alpha1.SeverityMedium,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2020-27350",
								Score:           nil,
							},
							{
								VulnerabilityID: "CVE-2011-3374",
								Severity:        v1alpha1.SeverityMedium,
								PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2011-3374",
								Score:           pointer.Float64Ptr(3.7),
							},
						},
					},
				},
			},
			expectedOutput: []templates.VulnerabilityWithCount{
				{
					Vulnerability: v1alpha1.Vulnerability{
						VulnerabilityID: "CVE-2019-1549",
						Severity:        v1alpha1.SeverityCritical,
						PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2019-1549",
						Score:           pointer.Float64Ptr(8.2),
					},
					AffectedWorkloads: 1,
				},
				{
					Vulnerability: v1alpha1.Vulnerability{
						VulnerabilityID: "CVE-2011-3374",
						Severity:        v1alpha1.SeverityMedium,
						PrimaryLink:     "https://avd.aquasec.com/nvd/cve-2011-3374",
						Score:           pointer.Float64Ptr(3.7),
					},
					AffectedWorkloads: 2,
				},
			},
		},
	}

	for _, tc := range testCases {
		r := namespaceReporter{}
		t.Run(tc.name, func(t *testing.T) {
			vulWithCount := r.topNVulnerabilitiesByScore(tc.reports, 5)
			assert.Equal(t, tc.expectedOutput, vulWithCount)
		})
	}
}
