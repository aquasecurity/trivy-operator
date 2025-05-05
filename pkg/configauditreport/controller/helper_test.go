package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

const messageKSV048 = "ClusterRole 'system:controller:replicaset-controller' should not have access to resources ['pods', 'deployments', 'jobs', 'cronjobs', 'statefulsets', 'daemonsets', 'replicasets'ß, 'replicationcontrollers'] for verbs ['create', 'update', 'patch', 'delete', 'deletecollection', 'impersonate', '*']"

func newTestResource(kind string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetKind(kind)
	obj.SetAPIVersion("v1")
	return obj
}

type demoResult struct {
	md types.Metadata
}

func (r demoResult) GetMetadata() types.Metadata {
	return r.md
}
func (_ demoResult) GetRawValue() any {
	return nil
}

func newDemoResult(filename string, start, end int) demoResult {
	return demoResult{
		md: types.NewMetadata(types.NewRange(filename, start, end, "", nil), ""),
	}
}

func newResults() scan.Results {
	results := scan.Results{}
	results.AddPassedRego("builtin.kubernetes.KCV0001", "deny", nil, newDemoResult("inputs/file_0.yaml", 0, 0))
	results.AddRego(messageKSV048, "builtin.kubernetes.KSV048", "deny", nil, newDemoResult("inputs/file_0.yaml", 0, 0))
	return results
}

func TestFilter(t *testing.T) {
	results := newResults()

	tests := []struct {
		name                     string
		resource                 client.Object
		bi                       trivyoperator.BuildInfo
		configData               trivyoperator.ConfigData
		config                   etc.Config
		defaultSeverity          string
		expectedMisconfiguration Misconfiguration
	}{
		{
			name:            "good case",
			resource:        newTestResource("Pod"),
			bi:              trivyoperator.BuildInfo{},
			configData:      trivyoperator.ConfigData{},
			config:          etc.Config{},
			defaultSeverity: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
			expectedMisconfiguration: Misconfiguration{
				configAuditReportData: v1alpha1.ConfigAuditReportData{
					Scanner: v1alpha1.Scanner{
						Name:   "Trivy",
						Vendor: "Aqua Security",
					},
					Checks: []v1alpha1.Check{
						{
							Category: "Kubernetes Security Check",
							Success:  true,
						},
						{
							Category: "Kubernetes Security Check",
							Success:  false,
							Messages: []string{
								messageKSV048,
							},
						},
					},
				},
				rbacAssessmentReportData:  v1alpha1.RbacAssessmentReportData{},
				infraAssessmentReportData: v1alpha1.InfraAssessmentReportData{},
			},
		},
		{
			name:     "failed checks only",
			resource: newTestResource("Pod"),
			bi:       trivyoperator.BuildInfo{},
			configData: trivyoperator.ConfigData{
				trivyoperator.KeyReportRecordFailedChecksOnly: "true",
			},
			config:          etc.Config{},
			defaultSeverity: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
			expectedMisconfiguration: Misconfiguration{
				configAuditReportData: v1alpha1.ConfigAuditReportData{
					Scanner: v1alpha1.Scanner{
						Name:   "Trivy",
						Vendor: "Aqua Security",
					},
					Checks: []v1alpha1.Check{
						{
							Category: "Kubernetes Security Check",
							Success:  false,
							Messages: []string{
								messageKSV048,
							},
						},
					},
				},
				rbacAssessmentReportData:  v1alpha1.RbacAssessmentReportData{},
				infraAssessmentReportData: v1alpha1.InfraAssessmentReportData{},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			misconfiguration := filter(results, test.resource, test.bi, test.configData, test.config, test.defaultSeverity)
			misconfiguration.configAuditReportData.UpdateTimestamp = test.expectedMisconfiguration.configAuditReportData.UpdateTimestamp
			assert.Equal(t, test.expectedMisconfiguration, misconfiguration)
		})
	}
}
