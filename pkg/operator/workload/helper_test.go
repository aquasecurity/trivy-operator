package workload

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetReportsByLabel(t *testing.T) {
	tests := []struct {
		name             string
		reportsPath      string
		loadResourceFunc func(filePath string, resource interface{}) error
		loadObjectList   client.ObjectList
		wantObjectList   client.ObjectList
		labels           map[string]string
		namespace        string
	}{
		{name: "get vulnerability report by label", reportsPath: "./testdata/fixture/vulnerabilityReportList.json",
			loadResourceFunc: loadResource,
			labels:           map[string]string{"trivy-operator.resource.name": "tt-reg"}, namespace: "default", wantObjectList: &v1alpha1.VulnerabilityReportList{}, loadObjectList: &v1alpha1.VulnerabilityReportList{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.loadResourceFunc(tt.reportsPath, &tt.loadObjectList)
			assert.NoError(t, err)
			testClient := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithLists(tt.loadObjectList).Build()
			or := kube.NewObjectResolver(testClient, nil)
			ctx := context.TODO()
			reports, err := GetReportsByLabel(ctx, or, tt.wantObjectList, tt.namespace, tt.labels)
			assert.NoError(t, err)
			switch i := reports.(type) {
			case *v1alpha1.VulnerabilityReportList:
				for index, report := range i.Items {
					assert.Equal(t, tt.loadObjectList.(*v1alpha1.VulnerabilityReportList).Items[index], report)
				}
			case *v1alpha1.ConfigAuditReportList:
				for index, report := range i.Items {
					assert.Equal(t, tt.loadObjectList.(*v1alpha1.ConfigAuditReportList).Items[index], report)
				}
			case *v1alpha1.ExposedSecretReportList:
				for index, report := range i.Items {
					assert.Equal(t, tt.loadObjectList.(*v1alpha1.ExposedSecretReportList).Items[index], report)
				}
			}
		})
	}
}

func loadResource(filePath string, resource interface{}) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(data, &resource)
	if err != nil {
		return nil
	}
	return err
}
