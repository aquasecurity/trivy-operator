package compliance

import (
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGenerateComplianceReport(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "decode basic data", data: base64.StdEncoding.EncodeToString([]byte("text for decode")), want: "text for decode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithLists(
				&v1alpha1.ConfigAuditReportList{
					TypeMeta: v1.TypeMeta{Kind: "ConfigAuditReport"},
					ListMeta: v1.ListMeta{},
					Items: []v1alpha1.ConfigAuditReport{
						{
							ObjectMeta: v1.ObjectMeta{Name: "resource"},
							Report: v1alpha1.ConfigAuditReportData{
								Checks: []v1alpha1.Check{
									{
										ID:      "AVD-KSV-0001",
										Title:   "some check",
										Success: false,
									},
								},
							},
						},
					}}).WithObjects(
				&v1alpha1.ClusterComplianceReport{
					TypeMeta:   v1.TypeMeta{Kind: "ConfigAuditReport"},
					ObjectMeta: v1.ObjectMeta{Name: "resource"},
					Spec: v1alpha1.ReportSpec{
						ReportFormat: "summary",
						Complaince: v1alpha1.Complaince{
							ID:    "1.0",
							Title: "nsa",
							Controls: []v1alpha1.Control{
								{
									ID: "1.0",
									Checks: []v1alpha1.SpecCheck{
										{
											ID: "AVD-KSV-0001",
										},
									},
								},
							},
						},
					},
				}).Build()
		})
	}
}
