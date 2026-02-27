package trivyjsonreport

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
)

func TestDeliveryService_DeliverReport_NotEnabled(t *testing.T) {
	config := etc.Config{TrivyJSONReportDeliveryEnabled: false, TrivyJSONReportDeliveryURL: "http://example.com"}
	svc := NewDeliveryService(log.Log, config)
	meta := &ReportMetadata{ArtifactName: "nginx:latest"}
	err := svc.DeliverReport(meta, []byte(`{}`))
	require.NoError(t, err)
}

func TestDeliveryService_DeliverReport_EmptyURL(t *testing.T) {
	config := etc.Config{TrivyJSONReportDeliveryEnabled: true, TrivyJSONReportDeliveryURL: ""}
	svc := NewDeliveryService(log.Log, config)
	meta := &ReportMetadata{ArtifactName: "nginx:latest"}
	err := svc.DeliverReport(meta, []byte(`{}`))
	require.NoError(t, err)
}

func TestDeliveryService_DeliverReport_Success(t *testing.T) {
	var receivedBody []byte
	var receivedHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		receivedHeader = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := etc.Config{
		TrivyJSONReportDeliveryEnabled:       true,
		TrivyJSONReportDeliveryURL:           server.URL,
		TrivyJSONReportDeliveryRetryAttempts: 1,
	}
	svc := NewDeliveryService(log.Log, config)
	meta := &ReportMetadata{ArtifactName: "nginx:latest", WorkloadKind: "Deployment", WorkloadName: "app"}
	payload := []byte(`{"SchemaVersion":2}`)
	err := svc.DeliverReport(meta, payload)
	require.NoError(t, err)
	assert.True(t, meta.Delivered)
	assert.NotNil(t, meta.DeliveredAt)
	assert.Equal(t, "application/json", receivedHeader)
	assert.Equal(t, payload, receivedBody)
}

func TestDeliveryService_DeliverReport_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	timeout := 5 * time.Second
	config := etc.Config{
		TrivyJSONReportDeliveryEnabled:       true,
		TrivyJSONReportDeliveryURL:           server.URL,
		TrivyJSONReportDeliveryRetryAttempts: 1, // single attempt so test finishes quickly
		TrivyJSONReportDeliveryTimeout:       &timeout,
	}
	svc := NewDeliveryService(log.Log, config)
	meta := &ReportMetadata{ArtifactName: "nginx:latest"}
	err := svc.DeliverReport(meta, []byte(`{}`))
	require.Error(t, err)
	assert.False(t, meta.Delivered)
	assert.Contains(t, meta.LastDeliveryError, "500")
}

func TestNewDeliveryService(t *testing.T) {
	timeout := 30 * time.Second
	config := etc.Config{TrivyJSONReportDeliveryTimeout: &timeout}
	svc := NewDeliveryService(log.Log, config)
	require.NotNil(t, svc.HTTPClient)
	assert.Equal(t, 30*time.Second, svc.HTTPClient.Timeout)
}
