package trivyjsonreport

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ReportMetadata contains metadata about a TrivyJSON report and its delivery status
type ReportMetadata struct {
	// ArtifactName is the scanned artifact (e.g., image name)
	ArtifactName string `json:"artifactName"`
	// ArtifactType is the type of artifact (e.g., "container_image")
	ArtifactType string `json:"artifactType"`
	// Namespace is the Kubernetes namespace (empty for cluster-scoped)
	Namespace string `json:"namespace,omitempty"`
	// WorkloadKind is the kind of workload (e.g., "Deployment", "ReplicaSet")
	WorkloadKind string `json:"workloadKind"`
	// WorkloadName is the name of the workload
	WorkloadName string `json:"workloadName"`
	// ContainerName is the name of the container
	ContainerName string `json:"containerName"`
	// CreatedAt is when the report was created
	CreatedAt time.Time `json:"createdAt"`
	// ReportFile is the path to the raw JSON report file
	ReportFile string `json:"reportFile"`
	// Delivered indicates if the report was successfully delivered
	Delivered bool `json:"delivered"`
	// DeliveredAt is when the report was delivered
	DeliveredAt *time.Time `json:"deliveredAt,omitempty"`
	// DeliveryAttempts is the number of delivery attempts
	DeliveryAttempts int `json:"deliveryAttempts"`
	// LastDeliveryError is the last delivery error message
	LastDeliveryError string `json:"lastDeliveryError,omitempty"`
	// LastDeliveryAttempt is when the last delivery attempt was made
	LastDeliveryAttempt *time.Time `json:"lastDeliveryAttempt,omitempty"`
}

// Writer handles writing TrivyJSON reports to file storage
type Writer struct {
	BaseDir string
}

// NewWriter creates a new file-based Writer
func NewWriter(baseDir string) *Writer {
	return &Writer{BaseDir: baseDir}
}

// safePathSegment returns an error if the segment could be used for path traversal.
func safePathSegment(name, segment string) error {
	if segment == "" {
		return nil
	}
	if strings.Contains(segment, "..") || strings.Contains(segment, "/") || strings.Contains(segment, "\\") {
		return fmt.Errorf("%s contains invalid path characters", name)
	}
	return nil
}

// WriteReport writes a namespaced TrivyJSON report and its metadata to file storage
func (w *Writer) WriteReport(namespace, workloadKind, workloadName, containerName, artifactName, artifactType string, rawJSON []byte) (*ReportMetadata, error) {
	if w.BaseDir == "" {
		return nil, errors.New("storage directory not configured")
	}
	if err := safePathSegment("namespace", namespace); err != nil {
		return nil, err
	}
	if err := safePathSegment("workloadKind", workloadKind); err != nil {
		return nil, err
	}
	if err := safePathSegment("workloadName", workloadName); err != nil {
		return nil, err
	}
	if err := safePathSegment("containerName", containerName); err != nil {
		return nil, err
	}

	// Create directory structure
	dir := filepath.Join(w.BaseDir, "namespaced", namespace)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Generate filenames
	baseName := fmt.Sprintf("%s-%s-%s", workloadKind, workloadName, containerName)
	reportFile := filepath.Join(dir, baseName+".json")
	metadataFile := filepath.Join(dir, baseName+".metadata.json")

	// Write raw JSON report
	if err := os.WriteFile(reportFile, rawJSON, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write report file: %w", err)
	}

	// Create metadata
	now := time.Now().UTC()
	metadata := &ReportMetadata{
		ArtifactName:  artifactName,
		ArtifactType:  artifactType,
		Namespace:     namespace,
		WorkloadKind:  workloadKind,
		WorkloadName:  workloadName,
		ContainerName: containerName,
		CreatedAt:     now,
		ReportFile:    reportFile,
		Delivered:     false,
	}

	// Write metadata
	if err := w.writeMetadata(metadataFile, metadata); err != nil {
		return nil, fmt.Errorf("failed to write metadata: %w", err)
	}

	return metadata, nil
}

// WriteClusterReport writes a cluster-scoped TrivyJSON report and its metadata to file storage
func (w *Writer) WriteClusterReport(workloadKind, workloadName, containerName, artifactName, artifactType string, rawJSON []byte) (*ReportMetadata, error) {
	if w.BaseDir == "" {
		return nil, errors.New("storage directory not configured")
	}
	if err := safePathSegment("workloadKind", workloadKind); err != nil {
		return nil, err
	}
	if err := safePathSegment("workloadName", workloadName); err != nil {
		return nil, err
	}
	if err := safePathSegment("containerName", containerName); err != nil {
		return nil, err
	}

	// Create directory structure
	dir := filepath.Join(w.BaseDir, "cluster")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Generate filenames
	baseName := fmt.Sprintf("%s-%s-%s", workloadKind, workloadName, containerName)
	reportFile := filepath.Join(dir, baseName+".json")
	metadataFile := filepath.Join(dir, baseName+".metadata.json")

	// Write raw JSON report
	if err := os.WriteFile(reportFile, rawJSON, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write report file: %w", err)
	}

	// Create metadata
	now := time.Now().UTC()
	metadata := &ReportMetadata{
		ArtifactName:  artifactName,
		ArtifactType:  artifactType,
		Namespace:     "", // cluster-scoped
		WorkloadKind:  workloadKind,
		WorkloadName:  workloadName,
		ContainerName: containerName,
		CreatedAt:     now,
		ReportFile:    reportFile,
		Delivered:     false,
	}

	// Write metadata
	if err := w.writeMetadata(metadataFile, metadata); err != nil {
		return nil, fmt.Errorf("failed to write metadata: %w", err)
	}

	return metadata, nil
}

// UpdateMetadata updates the metadata file for a report
func (w *Writer) UpdateMetadata(metadata *ReportMetadata) error {
	metadataFile, err := getMetadataFilePath(metadata.ReportFile)
	if err != nil {
		return err
	}
	return w.writeMetadata(metadataFile, metadata)
}

// writeMetadata writes metadata to a file
func (w *Writer) writeMetadata(filePath string, metadata *ReportMetadata) error {
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	return os.WriteFile(filePath, data, 0o600)
}

// ReadMetadata reads metadata from a file
func (w *Writer) ReadMetadata(metadataFile string) (*ReportMetadata, error) {
	data, err := os.ReadFile(metadataFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata file: %w", err)
	}

	var metadata ReportMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &metadata, nil
}

// getMetadataFilePath returns the metadata file path for a report file ending with ".json".
func getMetadataFilePath(reportFile string) (string, error) {
	if len(reportFile) < 5 || !strings.HasSuffix(reportFile, ".json") {
		return "", fmt.Errorf("report file path must end with .json: %q", reportFile)
	}
	return reportFile[:len(reportFile)-5] + ".metadata.json", nil
}

// GetMetadataFilePath returns the metadata file path for a report file.
// Returns the derived path without validation; use getMetadataFilePath when the path must be validated.
func GetMetadataFilePath(reportFile string) string {
	if len(reportFile) < 5 || !strings.HasSuffix(reportFile, ".json") {
		return reportFile + ".metadata.json"
	}
	return reportFile[:len(reportFile)-5] + ".metadata.json"
}
