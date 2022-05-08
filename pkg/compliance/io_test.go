package compliance

import (
	"github.com/stretchr/testify/assert"

	//"github.com/stretchr/testify/assert"
	"io/ioutil"
	"reflect"
	"sort"
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/emirpasic/gods/sets/hashset"
	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestPopulateSpecDataToMaps(t *testing.T) {
	mgr := cm{}
	tests := []struct {
		name           string
		specPath       string
		scanners       []string
		ids            []string
		wantMappedData *specDataMapping
	}{
		{name: "spec file with good format", ids: []string{"1.0", "8.1"}, scanners: []string{"config-audit", "kube-bench"}, specPath: "./testdata/fixture/nsa-1.0.yaml", wantMappedData: &specDataMapping{
			scannerResourceListNames: map[string]*hashset.Set{"config-audit": hashset.New("Job", "Pod", "ReplicationController", "ReplicaSet", "StatefulSet", "DaemonSet", "CronJob"),
				"kube-bench": hashset.New("Node")},
			controlIDControlObject: map[string]v1alpha1.Control{"1.0": {ID: "1.0", Name: "Non-root containers",
				Kinds: []string{"Job", "Pod", "ReplicationController", "ReplicaSet", "StatefulSet", "DaemonSet", "CronJob"}, Severity: "MEDIUM",
				Mapping: v1alpha1.Mapping{Scanner: "config-audit", Checks: []v1alpha1.SpecCheck{{ID: "KSV012"}}}}, "8.1": {ID: "8.1", Name: "Audit log path is configure",
				Kinds:   []string{"Node"},
				Mapping: v1alpha1.Mapping{Scanner: "kube-bench", Checks: []v1alpha1.SpecCheck{{ID: "1.2.22"}}}, Severity: "MEDIUM"}},
			controlCheckIds: map[string][]string{"1.0": {"KSV012"}, "8.1": {"1.2.22"}}}},
		{name: "spec file with no controls", specPath: "./testdata/fixture/nsa-1.0_no_controls.yaml"}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specData, err := ioutil.ReadFile(tt.specPath)
			if err != nil {
				t.Errorf(err.Error())
			}
			var spec v1alpha1.ReportSpec
			err = yaml.Unmarshal(specData, &spec)
			if err != nil {
				t.Errorf(err.Error())
			}
			pd := mgr.populateSpecDataToMaps(spec)
			if len(pd.scannerResourceListNames) > 0 && len(pd.controlCheckIds) > 0 {
				if !cmp.Equal(pd.controlCheckIds, tt.wantMappedData.controlCheckIds, option()) {
					t.Errorf("TestPopulateSpecDataToMaps want %v got %v", tt.wantMappedData.controlCheckIds, pd.controlCheckIds)
				}
				if !cmp.Equal(pd.controlIDControlObject, tt.wantMappedData.controlIDControlObject, option()) {
					t.Errorf("TestPopulateSpecDataToMaps want %v got %v", tt.wantMappedData.controlIDControlObject, pd.controlIDControlObject)
				}
			}
		})
	}
}

func option() cmp.Option {
	trans := cmp.Transformer("Sort", func(in []string) []string {
		out := append([]string(nil), in...) // Copy input to avoid mutating it
		sort.Strings(out)
		return out
	})
	return trans
}

func TestControlChecksByScannerChecks(t *testing.T) {
	mgr := cm{}
	tests := []struct {
		name             string
		specPath         string
		mapScannerResult map[string][]*ScannerCheckResult
		want             []v1alpha1.ControlCheck
	}{
		{name: " control checks by scanner checks", specPath: "./testdata/fixture/nsa-1.0.yaml", want: []v1alpha1.ControlCheck{{ID: "1.0", Name: "Non-root containers",
			PassTotal: 1, FailTotal: 0, Severity: "MEDIUM"}, {ID: "8.1", Name: "Audit log path is configure", PassTotal: 0, FailTotal: 1, Severity: "MEDIUM"}},
			mapScannerResult: map[string][]*ScannerCheckResult{
				"KSV012": {{ID: "1.0", Remediation: "aaa", Details: []ResultDetails{{Status: "PASS"}}}},
				"1.2.22": {{ID: "2.0", Remediation: "bbb", Details: []ResultDetails{{Status: "FAIL"}}}},
			}}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specData, err := ioutil.ReadFile(tt.specPath)
			assert.NoError(t, err)
			var spec v1alpha1.ReportSpec
			err = yaml.Unmarshal(specData, &spec)
			assert.NoError(t, err)
			sm := mgr.populateSpecDataToMaps(spec)
			controlChecks := mgr.controlChecksByScannerChecks(sm, tt.mapScannerResult)
			sort.Sort(scannerCheckSort(controlChecks))
			sort.Sort(scannerCheckSort(tt.want))
			assert.True(t, reflect.DeepEqual(controlChecks, tt.want))
		})
	}
}

type scannerCheckSort []v1alpha1.ControlCheck

func (a scannerCheckSort) Len() int           { return len(a) }
func (a scannerCheckSort) Less(i, j int) bool { return a[i].ID < a[j].ID }
func (a scannerCheckSort) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func TestGetTotals(t *testing.T) {
	mgr := cm{}
	tests := []struct {
		name         string
		controlCheck []v1alpha1.ControlCheck
		want         summaryTotal
	}{
		{name: "get totals with data", controlCheck: []v1alpha1.ControlCheck{{ID: "1.0", Name: "Non-root containers", PassTotal: 1, FailTotal: 0}, {ID: "8.1", Name: "Audit log path is configure", PassTotal: 0, FailTotal: 1}},
			want: summaryTotal{pass: 1, fail: 1}},
		{name: "get totals with no data", controlCheck: []v1alpha1.ControlCheck{},
			want: summaryTotal{pass: 0, fail: 0}}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := mgr.getTotals(tt.controlCheck)
			assert.True(t, reflect.DeepEqual(sm, tt.want))
		})
	}
}

func TestCheckIdsToResults(t *testing.T) {
	mgr := cm{}
	tests := []struct {
		name       string
		reportList map[string]map[string]client.ObjectList
		wantResult map[string][]*ScannerCheckResult
	}{
		{name: "map check ids to results report", reportList: map[string]map[string]client.ObjectList{ConfigAudit: {"Pod": getConfAudit([]string{"KSV037", "KSV038"}, []bool{true, false}, []string{"aaa", "bbb"})}, KubeBench: {"Node": getCisInstance([]string{"1.1", "2.2"}, []string{"PASS", "FAIL"}, []string{"aaa", "bbb"})}}, wantResult: getWantMapResults("./testdata/fixture/check_data_result.json")},
		{name: "map empty data ", reportList: map[string]map[string]client.ObjectList{}, wantResult: map[string][]*ScannerCheckResult{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cct, err := mgr.checkIdsToResults(tt.reportList)
			if err != nil {
				t.Error(err)
			}
			assert.True(t, reflect.DeepEqual(cct, tt.wantResult))
		})
	}
}
