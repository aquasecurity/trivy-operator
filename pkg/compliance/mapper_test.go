package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"reflect"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"testing"
)

func TestGetObjListByName(t *testing.T) {
	tests := []struct {
		name        string
		scannerName string
		want        string
	}{
		{name: "kube bench scanner name", scannerName: KubeBench, want: "*v1alpha1.CISKubeBenchReportList"},
		{name: "conf audit scanner name", scannerName: ConfigAudit, want: "*v1alpha1.ConfigAuditReportList"},
		{name: "no scanner name", scannerName: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := getObjListByName(tt.scannerName)
			if cl != nil {
				name := reflect.TypeOf(cl).String()
				assert.Equal(t, name, tt.want)
			}
		})
	}
}

func TestByScanner(t *testing.T) {
	tests := []struct {
		name        string
		scannerName string
		want        string
	}{
		{name: "kube bench scanner name", scannerName: KubeBench, want: "*compliance.kubeBench"},
		{name: "conf audit scanner name", scannerName: ConfigAudit, want: "*compliance.configAudit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl, err := byScanner(tt.scannerName)
			if err != nil {
				t.Error(err)
			}
			if cl != nil {
				name := reflect.TypeOf(cl).String()
				assert.Equal(t, name, tt.want)
			}
		})
	}
}

func TestMapComplianceScannerToResource(t *testing.T) {
	mgr := cm{}
	tests := []struct {
		name     string
		specPath string
		kClient  client.Client
		want     map[string]map[string]int
	}{
		{name: "map compliance spec to resource", specPath: "./testdata/fixture/clusterComplianceSpec.json", kClient: GetClient(t, "./testdata/fixture/cisBenchmarkReportList.json", "./testdata/fixture/configAuditReportList.json"),
			want: map[string]map[string]int{KubeBench: {"Node": 1, "LimitRange": 0, "NetworkPolicy": 0, "EncryptionConfiguration": 0}, ConfigAudit: {"DaemonSet": 0, "CronJob": 0, "Job": 0, "Pod": 1, "ReplicaSet": 0, "ReplicationController": 0, "StatefulSet": 0}}},
		{name: "map compliance spec to resource no data", specPath: "./testdata/fixture/clusterComplianceSpec.json", kClient: GetClient(t),
			want: map[string]map[string]int{KubeBench: {"Node": 0, "LimitRange": 0, "NetworkPolicy": 0, "EncryptionConfiguration": 0}, ConfigAudit: {"DaemonSet": 0, "CronJob": 0, "Job": 0, "Pod": 0, "ReplicaSet": 0, "ReplicationController": 0, "StatefulSet": 0}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := ioutil.ReadFile(tt.specPath)
			if err != nil {
				t.Error(err)
			}
			var spec v1alpha1.ClusterComplianceReport
			err = json.Unmarshal(d, &spec)
			if err != nil {
				t.Error(err)
			}
			pd := mgr.populateSpecDataToMaps(spec.Spec)
			mapData := mapComplianceScannerToResource(tt.kClient, context.Background(), pd.scannerResourceListNames)
			var match bool
			if len(mapData) > 0 {
				for key, val := range tt.want {
					if scanner, ok := mapData[key]; ok {
						for kScanner, kVal := range scanner {
							if cis, ok := kVal.(*v1alpha1.CISKubeBenchReportList); ok {
								if len(cis.Items) == val[kScanner] {
									match = true
								}
							}
							if cis, ok := kVal.(*v1alpha1.ConfigAuditReportList); ok {
								if len(cis.Items) == val[kScanner] {
									match = true
								}
							}
						}
					}
				}
			}
			assert.True(t, match)
		})
	}
}

func GetClient(t *testing.T, filePath ...string) client.Client {
	if len(filePath) == 0 {
		return fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithLists().Build()
	}
	if len(filePath) == 2 {
		var cisBenchList v1alpha1.CISKubeBenchReportList
		err := loadResource(filePath[0], &cisBenchList)
		if err != nil {
			t.Error(err)
		}
		var confAuditList v1alpha1.ConfigAuditReportList
		err = loadResource(filePath[1], &confAuditList)
		if err != nil {
			panic(err)
		}
		return fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithLists(&cisBenchList, &confAuditList).Build()
	}
	t.Error(fmt.Errorf("wrong num of file paths"))
	return nil
}

func TestMapReportDataToMap(t *testing.T) {
	tests := []struct {
		name       string
		objectType string
		mapfunc    func(objType string, objList client.ObjectList) map[string]*ScannerCheckResult
		reportList client.ObjectList
		wantResult map[string]*ScannerCheckResult
	}{
		{name: "map config audit report", objectType: "Pod", reportList: getConfAudit([]string{"KSV037", "KSV038"}, []bool{true, false}, []string{"aaa", "bbb"}), wantResult: getWantResults("./testdata/fixture/config_audit_check_result.json"), mapfunc: configAudit{}.mapReportData},
		{name: "map cis benchmark report", objectType: "Node", reportList: getCisInstance([]string{"1.1", "2.2"}, []string{"PASS", "FAIL"}, []string{"aaa", "bbb"}), wantResult: getWantResults("./testdata/fixture/cis_bench_check_result.json"), mapfunc: kubeBench{}.mapReportData},
		{name: "map empty config report", objectType: "Pod", reportList: &v1alpha1.ConfigAuditReportList{}, wantResult: map[string]*ScannerCheckResult{}, mapfunc: configAudit{}.mapReportData},
		{name: "map empty cis report ", objectType: "Node", reportList: &v1alpha1.CISKubeBenchReportList{}, wantResult: map[string]*ScannerCheckResult{}, mapfunc: kubeBench{}.mapReportData},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cct := tt.mapfunc(tt.objectType, tt.reportList)
			assert.True(t, reflect.DeepEqual(cct, tt.wantResult))
		})
	}
}

func getWantResults(filePath string) map[string]*ScannerCheckResult {
	var tct map[string]*ScannerCheckResult
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(data, &tct)
	if err != nil {
		return nil
	}
	return tct
}

func getWantMapResults(filePath string) map[string][]*ScannerCheckResult {
	var tct map[string][]*ScannerCheckResult
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(data, &tct)
	if err != nil {
		return nil
	}
	return tct
}

func getConfAudit(testIds []string, testStatus []bool, remediation []string) *v1alpha1.ConfigAuditReportList {
	return &v1alpha1.ConfigAuditReportList{Items: []v1alpha1.ConfigAuditReport{{Report: v1alpha1.ConfigAuditReportData{Checks: []v1alpha1.Check{{
		ID: testIds[0], Remediation: remediation[0], Success: testStatus[0]}, {
		ID: testIds[1], Remediation: remediation[1], Success: testStatus[1],
	}}}}}}
}

func getCisInstance(testIds []string, testStatus []string, remediation []string) *v1alpha1.CISKubeBenchReportList {
	return &v1alpha1.CISKubeBenchReportList{
		Items: []v1alpha1.CISKubeBenchReport{{Report: v1alpha1.CISKubeBenchReportData{Sections: []v1alpha1.CISKubeBenchSection{
			{Tests: []v1alpha1.CISKubeBenchTests{
				{Results: []v1alpha1.CISKubeBenchResult{
					{TestNumber: testIds[0], Status: testStatus[0], Remediation: remediation[0]},
					{TestNumber: testIds[1], Status: testStatus[1], Remediation: remediation[1]}}}},
			}}}}}}
}
