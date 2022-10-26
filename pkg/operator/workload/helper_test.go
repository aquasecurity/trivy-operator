package workload

import (
	"context"
	"reflect"
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetReportsByLabel(t *testing.T) {
	tests := []struct {
		name       string
		resource   *v1alpha1.VulnerabilityReportList
		labels     []map[string]string
		annotation map[string]string
		namespaces []string
		wantReport *v1alpha1.VulnerabilityReportList
	}{
		{name: "get vulnerability report by label",
			resource: &v1alpha1.VulnerabilityReportList{
				Items: []v1alpha1.VulnerabilityReport{{Report: v1alpha1.VulnerabilityReportData{}}},
			},
			labels:     []map[string]string{{"trivy-operator.resource.name": "tt-reg"}},
			annotation: map[string]string{"trivy-operator.aquasecurity.github.io/report-ttl": "24h0m0s"},
			namespaces: []string{"default"},
			wantReport: &v1alpha1.VulnerabilityReportList{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for index, item := range tt.resource.Items {
				item.ObjectMeta.Labels = tt.labels[index]
				item.ObjectMeta.Namespace = tt.namespaces[index]
			}
			fclient := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithLists(tt.resource).Build()
			or := kube.NewObjectResolver(fclient, nil)
			for index, namespace := range tt.namespaces {
				err := GetReportsByLabel(context.TODO(), or, tt.wantReport, namespace, tt.labels[index])
				assert.NoError(t, err)
				for index, item := range tt.wantReport.Items {
					assert.True(t, reflect.DeepEqual(item.Labels, tt.labels[index]))
				}
			}
		})
	}
}
