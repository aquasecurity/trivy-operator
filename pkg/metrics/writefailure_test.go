package metrics

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var vulnReportsResource = schema.GroupResource{
	Group:    "aquasecurity.github.io",
	Resource: "vulnerabilityreports",
}

func TestWriteFailureReason(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil error has no reason", err: nil, want: ""},
		{
			// The failure behind #757: etcd rejects the write and the API
			// server forwards the gRPC status as an opaque message, so there
			// is no typed error to match on.
			name: "etcd ResourceExhausted",
			err: errors.New("rpc error: code = ResourceExhausted desc = " +
				"trying to send message larger than max (2601323 vs. 2097152)"),
			want: ReasonTooLarge,
		},
		{
			name: "typed 413",
			err:  apierrors.NewRequestEntityTooLargeError("limit is 2097152"),
			want: ReasonTooLarge,
		},
		{
			name: "conflict",
			err:  apierrors.NewConflict(vulnReportsResource, "report", errors.New("conflict")),
			want: ReasonConflict,
		},
		{
			name: "already exists",
			err:  apierrors.NewAlreadyExists(vulnReportsResource, "report"),
			want: ReasonConflict,
		},
		{
			name: "forbidden",
			err:  apierrors.NewForbidden(vulnReportsResource, "report", errors.New("denied")),
			want: ReasonForbidden,
		},
		{
			name: "server timeout",
			err:  apierrors.NewServerTimeout(vulnReportsResource, "create", 1),
			want: ReasonTimeout,
		},
		{
			name: "not found is not special-cased",
			err:  apierrors.NewNotFound(vulnReportsResource, "report"),
			want: ReasonOther,
		},
		{
			name: "anything else",
			err:  errors.New("connection refused"),
			want: ReasonOther,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, WriteFailureReason(tt.err))
		})
	}
}

// The write path wraps the API error with the report identity before any
// caller sees it, so classification has to survive %w.
func TestWriteFailureReasonUnwrapsWrappedErrors(t *testing.T) {
	wrapped := fmt.Errorf("writing VulnerabilityReport nextcloud/report: %w",
		apierrors.NewRequestEntityTooLargeError("limit is 2097152"))

	assert.Equal(t, ReasonTooLarge, WriteFailureReason(wrapped))
}

func TestObserveReportWriteFailure(t *testing.T) {
	reportWriteFailuresTotal.Reset()
	t.Cleanup(reportWriteFailuresTotal.Reset)

	err := apierrors.NewRequestEntityTooLargeError("limit is 2097152")
	ObserveReportWriteFailure("nextcloud", "library/nextcloud", "VulnerabilityReport", err)
	ObserveReportWriteFailure("nextcloud", "library/nextcloud", "VulnerabilityReport", err)
	ObserveReportWriteFailure("authentik", "goauthentik/server", "VulnerabilityReport", err)

	expected := `
# HELP trivy_report_write_failures_total Number of security report writes rejected by the Kubernetes API server
# TYPE trivy_report_write_failures_total counter
trivy_report_write_failures_total{image_repository="goauthentik/server",kind="VulnerabilityReport",namespace="authentik",reason="too_large"} 1
trivy_report_write_failures_total{image_repository="library/nextcloud",kind="VulnerabilityReport",namespace="nextcloud",reason="too_large"} 2
`

	require.NoError(t, testutil.CollectAndCompare(
		reportWriteFailuresTotal, strings.NewReader(expected), "trivy_report_write_failures_total"))
}

// A cluster-scoped report has no namespace, and an artifact that is not a
// container image has no repository. Neither should break the metric.
func TestObserveReportWriteFailureWithEmptyLabels(t *testing.T) {
	reportWriteFailuresTotal.Reset()
	t.Cleanup(reportWriteFailuresTotal.Reset)

	ObserveReportWriteFailure("", "", "ClusterVulnerabilityReport", errors.New("boom"))

	assert.Equal(t, 1, testutil.CollectAndCount(reportWriteFailuresTotal))
}
