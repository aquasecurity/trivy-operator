package compliance

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

// fakeMgr implements Mgr and records calls.
type fakeMgr struct {
	called bool
	spec   v1alpha1.ReportSpec
	err    error
}

func (f *fakeMgr) GenerateComplianceReport(_ context.Context, spec v1alpha1.ReportSpec) error {
	f.called = true
	f.spec = spec
	return f.err
}

func TestClusterComplianceReconciler_generateComplianceReport(t *testing.T) {
	now := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	mkReport := func(createdAgo, updatedAgo time.Duration, cron string, format v1alpha1.ReportType) *v1alpha1.ClusterComplianceReport {
		return &v1alpha1.ClusterComplianceReport{
			TypeMeta:   v1.TypeMeta{Kind: "ClusterComplianceReport"},
			ObjectMeta: v1.ObjectMeta{Name: "nsa", CreationTimestamp: v1.NewTime(now.Add(-createdAgo))},
			Spec: v1alpha1.ReportSpec{
				Cron:         cron,
				ReportFormat: format,
				Compliance:   v1alpha1.Compliance{ID: "nsa", Title: "nsa"},
			},
			Status: v1alpha1.ReportStatus{UpdateTimestamp: v1.NewTime(now.Add(-updatedAgo))},
		}
	}

	type expectation struct {
		wantErr    bool
		mgrCalled  bool
		requeuePos bool // expect positive RequeueAfter
		wantFile   bool // expect JSON written to AltReportDir
	}

	tests := []struct {
		name   string
		setup  func() (*ClusterComplianceReportReconciler, types.NamespacedName, *fakeMgr, string)
		expect expectation
	}{
		{
			name: "not found is ignored",
			setup: func() (*ClusterComplianceReportReconciler, types.NamespacedName, *fakeMgr, string) {
				fm := &fakeMgr{}
				r := &ClusterComplianceReportReconciler{
					Client: fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).Build(),
					Mgr:    fm,
					Clock:  ext.NewFixedClock(now),
				}
				return r, types.NamespacedName{Name: "missing"}, fm, ""
			},
			expect: expectation{wantErr: false, mgrCalled: false, requeuePos: false, wantFile: false},
		},
		{
			name: "not due requeues",
			setup: func() (*ClusterComplianceReportReconciler, types.NamespacedName, *fakeMgr, string) {
				cr := mkReport(2*time.Minute, 0, "* * * * *", v1alpha1.ReportSummary) // updated at now
				c := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(cr).Build()
				fm := &fakeMgr{}
				r := &ClusterComplianceReportReconciler{Client: c, Mgr: fm, Clock: ext.NewFixedClock(now)}
				return r, types.NamespacedName{Name: "nsa"}, fm, ""
			},
			expect: expectation{wantErr: false, mgrCalled: false, requeuePos: true, wantFile: false},
		},
		{
			name: "due with alt storage writes file",
			setup: func() (*ClusterComplianceReportReconciler, types.NamespacedName, *fakeMgr, string) {
				dir := t.TempDir()
				cr := mkReport(10*time.Minute, 2*time.Minute, "* * * * *", v1alpha1.ReportSummary)
				c := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(cr).Build()
				fm := &fakeMgr{}
				r := &ClusterComplianceReportReconciler{Client: c, Mgr: fm, Clock: ext.NewFixedClock(now), Config: etc.Config{AltReportStorageEnabled: true, AltReportDir: dir}}
				return r, types.NamespacedName{Name: "nsa"}, fm, dir
			},
			expect: expectation{wantErr: false, mgrCalled: false, requeuePos: false, wantFile: true},
		},
		{
			name: "invoke once calls mgr",
			setup: func() (*ClusterComplianceReportReconciler, types.NamespacedName, *fakeMgr, string) {
				cr := mkReport(10*time.Minute, 2*time.Minute, "* * * * *", v1alpha1.ReportSummary)
				c := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(cr).Build()
				fm := &fakeMgr{}
				r := &ClusterComplianceReportReconciler{Client: c, Mgr: fm, Clock: ext.NewFixedClock(now), Config: etc.Config{InvokeClusterComplianceOnce: true}}
				return r, types.NamespacedName{Name: "nsa"}, fm, ""
			},
			expect: expectation{wantErr: false, mgrCalled: true, requeuePos: false, wantFile: false},
		},
		{
			name: "invalid cron returns error",
			setup: func() (*ClusterComplianceReportReconciler, types.NamespacedName, *fakeMgr, string) {
				cr := mkReport(0, 0, "invalid cron", v1alpha1.ReportSummary)
				c := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(cr).Build()
				fm := &fakeMgr{}
				r := &ClusterComplianceReportReconciler{Client: c, Mgr: fm, Clock: ext.NewFixedClock(now)}
				return r, types.NamespacedName{Name: "nsa"}, fm, ""
			},
			expect: expectation{wantErr: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, nn, fm, dir := tt.setup()
			res, err := r.generateComplianceReport(context.TODO(), nn)

			if tt.expect.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.expect.mgrCalled, fm.called)
			if tt.expect.requeuePos {
				assert.Greater(t, int64(res.RequeueAfter), int64(0))
			}

			if tt.expect.wantFile {
				outDir := filepath.Join(dir, "cluster_compliance_report")
				entries, readErr := os.ReadDir(outDir)
				require.NoError(t, readErr)
				require.Len(t, entries, 1)
				raw, rErr := os.ReadFile(filepath.Join(outDir, entries[0].Name()))
				require.NoError(t, rErr)
				var decoded v1alpha1.ClusterComplianceReport
				require.NoError(t, json.Unmarshal(raw, &decoded))
				require.Equal(t, "nsa", decoded.Name)
			}
		})
	}
}
