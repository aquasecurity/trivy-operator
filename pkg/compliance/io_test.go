package compliance

import (
	"context"
	"reflect"
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGenerateComplianceReport(t *testing.T) {
	tests := []struct {
		name                    string
		configAuditList         *v1alpha1.ConfigAuditReportList
		clusterComplianceReport *v1alpha1.ClusterComplianceReport
		reportType              string
		wantStatus              *v1alpha1.ReportStatus
	}{
		{name: "build summary report", configAuditList: &v1alpha1.ConfigAuditReportList{
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
							{
								ID:      "KSV003",
								Title:   "another check",
								Success: false,
							},
							{
								ID:      "KCV0004",
								Title:   "another check",
								Success: false,
							},
						},
					},
				},
			}}, clusterComplianceReport: &v1alpha1.ClusterComplianceReport{
			TypeMeta:   v1.TypeMeta{Kind: "ConfigAuditReport"},
			ObjectMeta: v1.ObjectMeta{Name: "nsa"},
			Spec: v1alpha1.ReportSpec{
				ReportFormat: "summary",
				Complaince: v1alpha1.Complaince{
					ID:    "nsa",
					Title: "nsa",
					Controls: []v1alpha1.Control{
						{
							ID:          "1.0",
							Description: "check root permission",
							Checks: []v1alpha1.SpecCheck{
								{
									ID: "AVD-KSV-0001",
								},
							},
						},
						{
							ID:          "2.0",
							Description: "check fs permission",
							Checks: []v1alpha1.SpecCheck{
								{
									ID: "AVD-KSV-0002",
								},
							},
						},
						{
							ID:          "3.0",
							Description: "check network access",
							Checks: []v1alpha1.SpecCheck{
								{
									ID: "AVD-KSV-0003",
								},
							},
						},
						{
							ID:          "4.0",
							Description: "check apiserver permission",
							Checks: []v1alpha1.SpecCheck{
								{
									ID: "AVD-KCV-0004",
								},
							},
						},
					},
				},
			},
		}, reportType: "summary", wantStatus: &v1alpha1.ReportStatus{
			SummaryReport: &v1alpha1.SummaryReport{
				ID:    "nsa",
				Title: "nsa",
				SummaryControls: []v1alpha1.ControlCheckSummary{
					{
						ID:        "1.0",
						TotalFail: getIntPtr(1),
					},
					{
						ID:        "2.0",
						TotalFail: getIntPtr(0),
					},
					{
						ID:        "3.0",
						TotalFail: getIntPtr(1),
					},
					{
						ID:        "4.0",
						TotalFail: getIntPtr(1),
					},
				},
			},
		}},
		{name: "build detail report", configAuditList: &v1alpha1.ConfigAuditReportList{
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
							{
								ID:      "KSV003",
								Title:   "another check",
								Success: false,
							},
							{
								ID:      "KCV0004",
								Title:   "another check",
								Success: false,
							},
						},
					},
				},
			}}, clusterComplianceReport: &v1alpha1.ClusterComplianceReport{
			TypeMeta:   v1.TypeMeta{Kind: "ConfigAuditReport"},
			ObjectMeta: v1.ObjectMeta{Name: "nsa"},
			Spec: v1alpha1.ReportSpec{
				ReportFormat: "all",
				Complaince: v1alpha1.Complaince{
					ID:    "nsa",
					Title: "nsa",
					Controls: []v1alpha1.Control{
						{
							ID:          "1.0",
							Description: "check root permission",
							Checks: []v1alpha1.SpecCheck{
								{
									ID: "AVD-KSV-0001",
								},
							},
						},
						{
							ID:          "2.0",
							Description: "check fs permission",
							Checks: []v1alpha1.SpecCheck{
								{
									ID: "AVD-KSV-0002",
								},
							},
						},
						{
							ID:          "3.0",
							Description: "check network access",
							Checks: []v1alpha1.SpecCheck{
								{
									ID: "AVD-KSV-0003",
								},
							},
						},
						{
							ID:          "4.0",
							Description: "check apiserver permission",
							Checks: []v1alpha1.SpecCheck{
								{
									ID: "AVD-KCV-0004",
								},
							},
						},
					},
				},
			},
		}, reportType: "all", wantStatus: &v1alpha1.ReportStatus{
			DetailReport: &v1alpha1.ComplianceReport{
				ID:    "nsa",
				Title: "nsa",
				Results: []*v1alpha1.ControlCheckResult{
					{
						ID:          "1.0",
						Description: "check root permission",
						Checks: []v1alpha1.ComplianceCheck{
							{
								ID:       "AVD-KSV-0001",
								Title:    "some check",
								Target:   "/resource",
								Category: "Kubernetes Security Check",
								Messages: []string{""},
								Success:  false,
							},
						},
					},
					{
						ID:          "2.0",
						Description: "check fs permission",
						Checks: []v1alpha1.ComplianceCheck{
							{
								Success: true,
							},
						},
					},
					{
						ID:          "3.0",
						Description: "check network access",
						Checks: []v1alpha1.ComplianceCheck{
							{
								ID:       "AVD-KSV-0003",
								Title:    "another check",
								Target:   "/resource",
								Category: "Kubernetes Security Check",
								Messages: []string{""},
								Success:  false,
							},
						},
					},
					{
						ID:          "4.0",
						Description: "check apiserver permission",
						Checks: []v1alpha1.ComplianceCheck{
							{
								ID:       "AVD-KCV-0004",
								Title:    "another check",
								Target:   "/resource",
								Category: "Kubernetes Security Check",
								Messages: []string{""},
								Success:  false,
							},
						},
					},
				},
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).
				WithLists(tt.configAuditList).
				WithObjects(tt.clusterComplianceReport).
				WithStatusSubresource(tt.clusterComplianceReport).
				Build()
			mgr := NewMgr(c)
			err := mgr.GenerateComplianceReport(context.Background(), tt.clusterComplianceReport.Spec)
			assert.NoError(t, err)
			ccr, err := getReport(context.Background(), c)
			assert.NoError(t, err)
			if tt.reportType == "summary" {
				assert.True(t, reflect.DeepEqual(ccr.Status.SummaryReport, tt.wantStatus.SummaryReport))
			}
			if tt.reportType == "all" {
				assert.True(t, reflect.DeepEqual(ccr.Status.DetailReport, tt.wantStatus.DetailReport))
			}
		})
	}
}

func getReport(ctx context.Context, c client.Client) (*v1alpha1.ClusterComplianceReport, error) {
	var report v1alpha1.ClusterComplianceReport
	err := c.Get(ctx, types.NamespacedName{Namespace: "", Name: "nsa"}, &report)
	if err != nil {
		return nil, err
	}
	return &report, nil
}

func getIntPtr(val int) *int {
	return &val
}
