package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
)

// StorageReader abstracts reading reports from different storage backends (CRD or filesystem).
type StorageReader interface {
	// ReadVulnerabilityReports reads all vulnerability reports from the storage backend.
	ReadVulnerabilityReports(ctx context.Context, namespace string) ([]v1alpha1.VulnerabilityReport, error)

	// ReadExposedSecretReports reads all exposed secret reports from the storage backend.
	ReadExposedSecretReports(ctx context.Context, namespace string) ([]v1alpha1.ExposedSecretReport, error)

	// ReadConfigAuditReports reads all config audit reports from the storage backend.
	ReadConfigAuditReports(ctx context.Context, namespace string) ([]v1alpha1.ConfigAuditReport, error)

	// ReadRbacAssessmentReports reads all RBAC assessment reports from the storage backend.
	ReadRbacAssessmentReports(ctx context.Context, namespace string) ([]v1alpha1.RbacAssessmentReport, error)

	// ReadInfraAssessmentReports reads all infra assessment reports from the storage backend.
	ReadInfraAssessmentReports(ctx context.Context, namespace string) ([]v1alpha1.InfraAssessmentReport, error)

	// ReadClusterRbacAssessmentReports reads all cluster RBAC assessment reports from the storage backend.
	ReadClusterRbacAssessmentReports(ctx context.Context) ([]v1alpha1.ClusterRbacAssessmentReport, error)

	// ReadClusterComplianceReports reads all cluster compliance reports from the storage backend.
	ReadClusterComplianceReports(ctx context.Context) ([]v1alpha1.ClusterComplianceReport, error)
}

// CRDStorageReader reads reports from Kubernetes CRDs (the current/default implementation).
type CRDStorageReader struct {
	client client.Client
	logger logr.Logger
}

// NewCRDStorageReader creates a new CRDStorageReader.
func NewCRDStorageReader(c client.Client, logger logr.Logger) StorageReader {
	return &CRDStorageReader{
		client: c,
		logger: logger,
	}
}

func (r *CRDStorageReader) ReadVulnerabilityReports(ctx context.Context, namespace string) ([]v1alpha1.VulnerabilityReport, error) {
	var list v1alpha1.VulnerabilityReportList
	if err := r.client.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (r *CRDStorageReader) ReadExposedSecretReports(ctx context.Context, namespace string) ([]v1alpha1.ExposedSecretReport, error) {
	var list v1alpha1.ExposedSecretReportList
	if err := r.client.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (r *CRDStorageReader) ReadConfigAuditReports(ctx context.Context, namespace string) ([]v1alpha1.ConfigAuditReport, error) {
	var list v1alpha1.ConfigAuditReportList
	if err := r.client.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (r *CRDStorageReader) ReadRbacAssessmentReports(ctx context.Context, namespace string) ([]v1alpha1.RbacAssessmentReport, error) {
	var list v1alpha1.RbacAssessmentReportList
	if err := r.client.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (r *CRDStorageReader) ReadInfraAssessmentReports(ctx context.Context, namespace string) ([]v1alpha1.InfraAssessmentReport, error) {
	var list v1alpha1.InfraAssessmentReportList
	if err := r.client.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (r *CRDStorageReader) ReadClusterRbacAssessmentReports(ctx context.Context) ([]v1alpha1.ClusterRbacAssessmentReport, error) {
	var list v1alpha1.ClusterRbacAssessmentReportList
	if err := r.client.List(ctx, &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (r *CRDStorageReader) ReadClusterComplianceReports(ctx context.Context) ([]v1alpha1.ClusterComplianceReport, error) {
	var list v1alpha1.ClusterComplianceReportList
	if err := r.client.List(ctx, &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

// FilesystemStorageReader reads reports from the alternate storage filesystem.
type FilesystemStorageReader struct {
	baseDir string
	logger  logr.Logger
}

// NewFilesystemStorageReader creates a new FilesystemStorageReader.
func NewFilesystemStorageReader(baseDir string, logger logr.Logger) StorageReader {
	return &FilesystemStorageReader{
		baseDir: baseDir,
		logger:  logger,
	}
}

// readReportsFromDirectory reads JSON reports from a directory and unmarshals them into the provided slice.
// This is a generic helper function that works with any report type.
func readReportsFromDirectory[T any](dir string, logger logr.Logger) ([]T, error) {
	var reports []T

	// Check if directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		// Directory doesn't exist - return empty list, not an error
		logger.V(1).Info("Report directory does not exist, returning empty list", "dir", dir)
		return reports, nil
	}

	// Read all files in the directory
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %q: %w", dir, err)
	}

	for _, entry := range entries {
		// Skip directories and non-JSON files
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			logger.Error(err, "Failed to read report file", "path", filePath)
			continue // Skip this file but continue processing others
		}

		// Try to unmarshal as a single report first
		var report T
		if err := json.Unmarshal(data, &report); err != nil {
			// If that fails, try to unmarshal as an array
			var reportArray []T
			if err2 := json.Unmarshal(data, &reportArray); err2 != nil {
				logger.Error(err, "Failed to unmarshal report file (tried both single and array)", "path", filePath)
				continue
			}
			reports = append(reports, reportArray...)
		} else {
			reports = append(reports, report)
		}
	}

	logger.V(1).Info("Read reports from filesystem", "dir", dir, "count", len(reports))
	return reports, nil
}

func (r *FilesystemStorageReader) ReadVulnerabilityReports(_ context.Context, namespace string) ([]v1alpha1.VulnerabilityReport, error) {
	dir := filepath.Join(r.baseDir, "vulnerability_reports")
	reports, err := readReportsFromDirectory[v1alpha1.VulnerabilityReport](dir, r.logger)
	if err != nil {
		return nil, err
	}

	// Filter by namespace if specified
	if namespace != "" {
		filtered := make([]v1alpha1.VulnerabilityReport, 0)
		for _, report := range reports {
			if report.Namespace == namespace {
				filtered = append(filtered, report)
			}
		}
		return filtered, nil
	}

	return reports, nil
}

func (r *FilesystemStorageReader) ReadExposedSecretReports(_ context.Context, namespace string) ([]v1alpha1.ExposedSecretReport, error) {
	dir := filepath.Join(r.baseDir, "secret_reports")
	reports, err := readReportsFromDirectory[v1alpha1.ExposedSecretReport](dir, r.logger)
	if err != nil {
		return nil, err
	}

	// Filter by namespace if specified
	if namespace != "" {
		filtered := make([]v1alpha1.ExposedSecretReport, 0)
		for _, report := range reports {
			if report.Namespace == namespace {
				filtered = append(filtered, report)
			}
		}
		return filtered, nil
	}

	return reports, nil
}

func (r *FilesystemStorageReader) ReadConfigAuditReports(_ context.Context, namespace string) ([]v1alpha1.ConfigAuditReport, error) {
	dir := filepath.Join(r.baseDir, "config_audit_reports")
	reports, err := readReportsFromDirectory[v1alpha1.ConfigAuditReport](dir, r.logger)
	if err != nil {
		return nil, err
	}

	// Filter out reports without required metadata (malformed reports)
	validReports := make([]v1alpha1.ConfigAuditReport, 0)
	for _, report := range reports {
		// Skip reports that don't have name or required labels
		if report.Name == "" || report.Labels == nil || len(report.Labels) == 0 {
			r.logger.V(1).Info("Skipping malformed config audit report without required metadata",
				"name", report.Name, "hasLabels", report.Labels != nil)
			continue
		}
		validReports = append(validReports, report)
	}

	// Filter by namespace if specified
	if namespace != "" {
		filtered := make([]v1alpha1.ConfigAuditReport, 0)
		for _, report := range validReports {
			if report.Namespace == namespace {
				filtered = append(filtered, report)
			}
		}
		return filtered, nil
	}

	return validReports, nil
}

func (r *FilesystemStorageReader) ReadRbacAssessmentReports(_ context.Context, namespace string) ([]v1alpha1.RbacAssessmentReport, error) {
	dir := filepath.Join(r.baseDir, "rbac_assessment_reports")
	reports, err := readReportsFromDirectory[v1alpha1.RbacAssessmentReport](dir, r.logger)
	if err != nil {
		return nil, err
	}

	// Filter out reports without required metadata (malformed reports)
	validReports := make([]v1alpha1.RbacAssessmentReport, 0)
	for _, report := range reports {
		// Skip reports that don't have name or required labels
		if report.Name == "" || report.Labels == nil || len(report.Labels) == 0 {
			r.logger.V(1).Info("Skipping malformed RBAC assessment report without required metadata",
				"name", report.Name, "hasLabels", report.Labels != nil)
			continue
		}
		validReports = append(validReports, report)
	}

	// Filter by namespace if specified
	if namespace != "" {
		filtered := make([]v1alpha1.RbacAssessmentReport, 0)
		for _, report := range validReports {
			if report.Namespace == namespace {
				filtered = append(filtered, report)
			}
		}
		return filtered, nil
	}

	return validReports, nil
}

func (r *FilesystemStorageReader) ReadInfraAssessmentReports(_ context.Context, namespace string) ([]v1alpha1.InfraAssessmentReport, error) {
	dir := filepath.Join(r.baseDir, "infra_assessment_reports")
	reports, err := readReportsFromDirectory[v1alpha1.InfraAssessmentReport](dir, r.logger)
	if err != nil {
		return nil, err
	}

	// Filter out reports without required metadata (malformed reports)
	validReports := make([]v1alpha1.InfraAssessmentReport, 0)
	for _, report := range reports {
		// Skip reports that don't have name or required labels
		if report.Name == "" || report.Labels == nil || len(report.Labels) == 0 {
			r.logger.V(1).Info("Skipping malformed infra assessment report without required metadata",
				"name", report.Name, "hasLabels", report.Labels != nil)
			continue
		}
		validReports = append(validReports, report)
	}

	// Filter by namespace if specified
	if namespace != "" {
		filtered := make([]v1alpha1.InfraAssessmentReport, 0)
		for _, report := range validReports {
			if report.Namespace == namespace {
				filtered = append(filtered, report)
			}
		}
		return filtered, nil
	}

	return validReports, nil
}

func (r *FilesystemStorageReader) ReadClusterRbacAssessmentReports(_ context.Context) ([]v1alpha1.ClusterRbacAssessmentReport, error) {
	dir := filepath.Join(r.baseDir, "cluster_rbac_assessment_reports")
	reports, err := readReportsFromDirectory[v1alpha1.ClusterRbacAssessmentReport](dir, r.logger)
	if err != nil {
		return nil, err
	}

	// Filter out reports without required metadata (malformed reports)
	validReports := make([]v1alpha1.ClusterRbacAssessmentReport, 0)
	for _, report := range reports {
		// Skip reports that don't have name or required labels
		if report.Name == "" || report.Labels == nil || len(report.Labels) == 0 {
			r.logger.V(1).Info("Skipping malformed cluster RBAC assessment report without required metadata",
				"name", report.Name, "hasLabels", report.Labels != nil)
			continue
		}
		validReports = append(validReports, report)
	}

	return validReports, nil
}

func (r *FilesystemStorageReader) ReadClusterComplianceReports(_ context.Context) ([]v1alpha1.ClusterComplianceReport, error) {
	dir := filepath.Join(r.baseDir, "cluster_compliance_report")
	return readReportsFromDirectory[v1alpha1.ClusterComplianceReport](dir, r.logger)
}

// NewStorageReader creates the appropriate StorageReader based on configuration.
// If alternate storage is enabled, it returns a FilesystemStorageReader.
// Otherwise, it returns a CRDStorageReader.
func NewStorageReader(config etc.Config, c client.Client, logger logr.Logger) StorageReader {
	if config.AltReportStorageEnabled && config.AltReportDir != "" {
		logger.Info("Using filesystem storage reader for metrics", "dir", config.AltReportDir)
		return NewFilesystemStorageReader(config.AltReportDir, logger)
	}
	logger.V(1).Info("Using CRD storage reader for metrics")
	return NewCRDStorageReader(c, logger)
}
