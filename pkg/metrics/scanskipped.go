package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	k8smetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/aquasecurity/trivy-operator/pkg/kube"
)

// Reasons reported by ScanSkippedReason. A closed set, so the metric stays
// low cardinality.
const (
	ReasonReplicaSetNotFound = "replicaset_not_found"
	ReasonNoRunningPods      = "no_running_pods"
	ReasonUnsupportedKind    = "unsupported_kind"
	ReasonNoContainers       = "no_containers"
)

// workloadScanSkippedTotal counts workloads the operator decided not to scan.
//
// These decisions are deliberate and return nil, so they leave nothing behind:
// no scan job, no report, and no event. Every other metric in this package is
// derived from report objects that exist, which means a skipped workload and a
// workload with no findings are indistinguishable from outside. This counter
// is the only thing that separates them.
var workloadScanSkippedTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: prometheus.BuildFQName("trivy", "workload", "scan_skipped_total"),
		Help: "Number of workloads the operator declined to submit a scan job for",
	},
	[]string{namespace, "kind", "reason"},
)

func init() {
	k8smetrics.Registry.MustRegister(workloadScanSkippedTotal)
}

// ObserveScanSkipped records one workload that will not be scanned.
func ObserveScanSkipped(ns, kind, reason string) {
	workloadScanSkippedTotal.WithLabelValues(ns, kind, reason).Inc()
}

// ScanSkippedReason maps one of the sentinel errors that make the operator
// skip a workload onto a Reason constant. It returns "" for any other error,
// which callers should treat as a real failure rather than a skip.
func ScanSkippedReason(err error) string {
	switch {
	case errors.Is(err, kube.ErrReplicaSetNotFound):
		return ReasonReplicaSetNotFound
	case errors.Is(err, kube.ErrNoRunningPods):
		return ReasonNoRunningPods
	case errors.Is(err, kube.ErrUnSupportedKind):
		return ReasonUnsupportedKind
	default:
		return ""
	}
}
