package compliance

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
)

func testingLogger(t *testing.T) logr.Logger {
	return testr.NewWithOptions(t, testr.Options{Verbosity: 1})
}

type dummyMgr struct{}

func (d dummyMgr) GenerateComplianceReport(_ context.Context, _ v1alpha1.ReportSpec) error {
	// No-op for testing webhook
	return nil
}

func TestClusterComplianceReportReconciler_WebhookCalled(t *testing.T) {
	webhookCalled := false
	var receivedBody string

	// Mock webhook server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookCalled = true
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	report := &v1alpha1.ClusterComplianceReport{
		TypeMeta:   v1.TypeMeta{Kind: "ConfigAuditReport"},
		ObjectMeta: v1.ObjectMeta{Name: "test-report"},
		Spec: v1alpha1.ReportSpec{
			ReportFormat: "summary",
			Cron:         "0 */6 * * *",
			Compliance: v1alpha1.Compliance{
				ID:    "nsa",
				Title: "nsa",
				Controls: []v1alpha1.Control{
					{
						ID:          "1.0",
						Description: "check root permission",
						Checks: []v1alpha1.SpecCheck{
							{
								ID: "AVD-KSV-0001",
							},
						},
					},
				},
			},
		},
		Status: v1alpha1.ReportStatus{
			UpdateTimestamp: v1.Time{Time: time.Now()},
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(report).Build()
	timeout := 10 * time.Second

	cfg := etc.Config{
		AltReportStorageEnabled:     true,
		AltReportDir:                t.TempDir(),
		WebhookBroadcastURL:         mockServer.URL,
		InvokeClusterComplianceOnce: true,
		WebhookBroadcastTimeout:     &timeout,
	}

	reconciler := &ClusterComplianceReportReconciler{
		Client: fakeClient,
		Config: cfg,
		Logger: testingLogger(t),
		Mgr:    dummyMgr{}, // No-op compliance generator
		Clock:  ext.NewSystemClock(),
	}

	_, err := reconciler.generateComplianceReport(t.Context(), types.NamespacedName{Name: "test-report"})
	require.NoError(t, err)

	assert.True(t, webhookCalled, "Expected webhook to be called")
	assert.Contains(t, receivedBody, "test-report", "Expected report name in webhook payload")
}
