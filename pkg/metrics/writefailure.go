package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	k8smetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Reasons reported by WriteFailureReason. They are a closed set so the metric
// stays low cardinality.
const (
	ReasonTooLarge  = "too_large"
	ReasonConflict  = "conflict"
	ReasonForbidden = "forbidden"
	ReasonTimeout   = "timeout"
	ReasonOther     = "other"
)

// reportWriteFailuresTotal counts report writes the API server rejected.
//
// Every other metric in this package is derived from report objects that
// exist, which means a report the API server refused to store is invisible:
// no object is created, so nothing is left to collect and the workload looks
// exactly like one that was never scanned. This counter is the only signal
// that the difference happened.
var reportWriteFailuresTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: prometheus.BuildFQName("trivy", "report", "write_failures_total"),
		Help: "Number of security report writes rejected by the Kubernetes API server",
	},
	[]string{namespace, image_repository, "kind", "reason"},
)

func init() {
	k8smetrics.Registry.MustRegister(reportWriteFailuresTotal)
}

// ObserveReportWriteFailure records one rejected write. repository may be
// empty for reports that are not tied to a container image.
func ObserveReportWriteFailure(ns, repository, kind string, err error) {
	reportWriteFailuresTotal.
		WithLabelValues(ns, repository, kind, WriteFailureReason(err)).
		Inc()
}

// WriteFailureReason maps err onto one of the Reason constants.
func WriteFailureReason(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case apierrors.IsRequestEntityTooLargeError(err), isResourceExhausted(err):
		return ReasonTooLarge
	case apierrors.IsConflict(err), apierrors.IsAlreadyExists(err):
		return ReasonConflict
	case apierrors.IsForbidden(err), apierrors.IsUnauthorized(err):
		return ReasonForbidden
	case apierrors.IsTimeout(err), apierrors.IsServerTimeout(err):
		return ReasonTimeout
	default:
		return ReasonOther
	}
}

// isResourceExhausted reports whether err carries etcd's gRPC
// ResourceExhausted status. The API server forwards that one as an opaque
// message rather than as a typed 413, so there is nothing but the text to
// match on -- see aquasecurity/trivy-operator#757.
func isResourceExhausted(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "ResourceExhausted") ||
		strings.Contains(msg, "larger than max")
}
