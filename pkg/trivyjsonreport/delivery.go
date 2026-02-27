package trivyjsonreport

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-logr/logr"

	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
)

// DeliveryService handles delivering TrivyJSON reports to HTTP endpoints
type DeliveryService struct {
	Config     etc.Config
	HTTPClient *http.Client
	Logger     logr.Logger
}

// NewDeliveryService creates a new DeliveryService
func NewDeliveryService(logger logr.Logger, config etc.Config) *DeliveryService {
	timeout := 60 * time.Second
	if config.TrivyJSONReportDeliveryTimeout != nil {
		timeout = *config.TrivyJSONReportDeliveryTimeout
	}

	return &DeliveryService{
		Config: config,
		Logger: logger,
		HTTPClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// DeliverReport sends the raw Trivy JSON to the configured endpoint
// The rawJSON is sent as-is in the request body with Content-Type: application/json
// Returns nil if delivery is not enabled or URL is not configured
func (d *DeliveryService) DeliverReport(metadata *ReportMetadata, rawJSON []byte) error {
	if !d.Config.TrivyJSONReportDeliveryEnabled {
		return nil
	}

	if d.Config.TrivyJSONReportDeliveryURL == "" {
		return nil
	}

	log := d.Logger.WithValues(
		"artifact", metadata.ArtifactName,
		"namespace", metadata.Namespace,
		"workload", fmt.Sprintf("%s/%s", metadata.WorkloadKind, metadata.WorkloadName),
	)

	var lastErr error
	maxAttempts := d.Config.TrivyJSONReportDeliveryRetryAttempts
	if maxAttempts <= 0 {
		maxAttempts = 3
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		now := time.Now().UTC()
		metadata.DeliveryAttempts = attempt
		metadata.LastDeliveryAttempt = &now

		err := d.send(rawJSON)
		if err == nil {
			// Success
			metadata.Delivered = true
			deliveredAt := time.Now().UTC()
			metadata.DeliveredAt = &deliveredAt
			metadata.LastDeliveryError = ""

			log.Info("Successfully delivered TrivyJSON report",
				"endpoint", d.Config.TrivyJSONReportDeliveryURL,
				"attempts", attempt)

			return nil
		}

		lastErr = err
		metadata.LastDeliveryError = err.Error()

		if attempt < maxAttempts {
			log.Info("Delivery attempt failed, retrying",
				"attempt", attempt,
				"maxAttempts", maxAttempts,
				"error", err.Error())
			// Exponential backoff: 5s, 10s, 15s, ...
			time.Sleep(time.Duration(attempt) * 5 * time.Second)
		}
	}

	log.Error(lastErr, "Delivery failed after max attempts",
		"attempts", maxAttempts,
		"endpoint", d.Config.TrivyJSONReportDeliveryURL)

	return fmt.Errorf("delivery failed after %d attempts: %w", maxAttempts, lastErr)
}

// send performs the actual HTTP POST request
func (d *DeliveryService) send(rawJSON []byte) error {
	req, err := http.NewRequest(http.MethodPost, d.Config.TrivyJSONReportDeliveryURL, bytes.NewReader(rawJSON))
	if err != nil {
		return fmt.Errorf("creating HTTP request: %w", err)
	}

	// Set content type
	req.Header.Set("Content-Type", "application/json")

	// Set custom headers
	customHeaders := d.Config.GetTrivyJSONReportDeliveryCustomHeaders()
	for key, values := range customHeaders {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// #nosec G704 -- URL is from operator config (user-configured webhook), not user input taint
	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	if resp == nil {
		return fmt.Errorf("no response from endpoint")
	}
	defer resp.Body.Close()

	// Read response body for error messages (limit size to avoid unbounded memory use)
	const maxResponseBodySize = 1 << 20 // 1 MiB
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
