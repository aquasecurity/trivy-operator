package metrics

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-operator/pkg/kube"
)

func TestScanSkippedReason(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "replicaset not found", err: kube.ErrReplicaSetNotFound, want: ReasonReplicaSetNotFound},
		{name: "no running pods", err: kube.ErrNoRunningPods, want: ReasonNoRunningPods},
		{name: "unsupported kind", err: kube.ErrUnSupportedKind, want: ReasonUnsupportedKind},
		{
			// The caller wraps these before they reach us in some paths.
			name: "wrapped sentinel still classifies",
			err:  fmt.Errorf("constructing scan job: %w", kube.ErrNoRunningPods),
			want: ReasonNoRunningPods,
		},
		{
			// Anything else is a real failure, not a skip, and must not be
			// swallowed by the caller.
			name: "unrelated error is not a skip",
			err:  errors.New("connection refused"),
			want: "",
		},
		{name: "nil is not a skip", err: nil, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ScanSkippedReason(tt.err))
		})
	}
}

func TestObserveScanSkipped(t *testing.T) {
	workloadScanSkippedTotal.Reset()
	t.Cleanup(workloadScanSkippedTotal.Reset)

	ObserveScanSkipped("rook-ceph", "ReplicaSet", ReasonNoRunningPods)
	ObserveScanSkipped("rook-ceph", "ReplicaSet", ReasonNoRunningPods)
	ObserveScanSkipped("kube-system", "DaemonSet", ReasonNoContainers)

	expected := `
# HELP trivy_workload_scan_skipped_total Number of workloads the operator declined to submit a scan job for
# TYPE trivy_workload_scan_skipped_total counter
trivy_workload_scan_skipped_total{kind="DaemonSet",namespace="kube-system",reason="no_containers"} 1
trivy_workload_scan_skipped_total{kind="ReplicaSet",namespace="rook-ceph",reason="no_running_pods"} 2
`

	require.NoError(t, testutil.CollectAndCompare(
		workloadScanSkippedTotal, strings.NewReader(expected), "trivy_workload_scan_skipped_total"))
}

// A cluster-scoped workload has no namespace; that must not break the metric.
func TestObserveScanSkippedClusterScoped(t *testing.T) {
	workloadScanSkippedTotal.Reset()
	t.Cleanup(workloadScanSkippedTotal.Reset)

	ObserveScanSkipped("", "Node", ReasonUnsupportedKind)

	assert.Equal(t, 1, testutil.CollectAndCount(workloadScanSkippedTotal))
}
