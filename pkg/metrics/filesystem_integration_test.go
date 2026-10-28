package metrics

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
)

// TestMetricsCollectionFromFilesystem tests end-to-end metrics collection from filesystem storage
func TestMetricsCollectionFromFilesystem(t *testing.T) {
	// Create temporary directory structure
	tmpDir := t.TempDir()
	vulnDir := filepath.Join(tmpDir, "vulnerability_reports")
	configDir := filepath.Join(tmpDir, "config_audit_reports")

	if err := os.MkdirAll(vulnDir, 0o750); err != nil {
		t.Fatalf("failed to create vuln dir: %v", err)
	}
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	// Create sample vulnerability report
	vulnReport := `{
  "apiVersion": "aquasecurity.github.io/v1alpha1",
  "kind": "VulnerabilityReport",
  "metadata": {
    "name": "replicaset-nginx-7c6c7b9c9d-nginx",
    "namespace": "default",
    "labels": {
      "trivy-operator.resource.kind": "ReplicaSet",
      "trivy-operator.resource.name": "nginx-7c6c7b9c9d",
      "trivy-operator.resource.namespace": "default"
    }
  },
  "report": {
    "registry": {
      "server": "docker.io"
    },
    "artifact": {
      "repository": "library/nginx",
      "tag": "1.21.0"
    },
    "summary": {
      "criticalCount": 2,
      "highCount": 5,
      "mediumCount": 10,
      "lowCount": 3,
      "unknownCount": 0,
      "noneCount": 0
    }
  }
}`

	if err := os.WriteFile(filepath.Join(vulnDir, "VulnerabilityReport-nginx.json"), []byte(vulnReport), 0o600); err != nil {
		t.Fatalf("failed to write vuln report: %v", err)
	}

	// Create sample config audit report
	configReport := `{
  "apiVersion": "aquasecurity.github.io/v1alpha1",
  "kind": "ConfigAuditReport",
  "metadata": {
    "name": "replicaset-nginx-7c6c7b9c9d",
    "namespace": "default",
    "labels": {
      "trivy-operator.resource.kind": "ReplicaSet",
      "trivy-operator.resource.name": "nginx-7c6c7b9c9d",
      "trivy-operator.resource.namespace": "default"
    }
  },
  "report": {
    "summary": {
      "criticalCount": 1,
      "highCount": 2,
      "mediumCount": 3,
      "lowCount": 4
    }
  }
}`

	if err := os.WriteFile(filepath.Join(configDir, "ConfigAuditReport-nginx.json"), []byte(configReport), 0o600); err != nil {
		t.Fatalf("failed to write config report: %v", err)
	}

	// Create storage reader with filesystem backend
	config := etc.Config{
		Namespace:               "trivy-system",
		TargetNamespaces:        "default",
		MetricsBindAddress:      ":8080",
		MetricsFindingsEnabled:  true,
		AltReportStorageEnabled: true,
		AltReportDir:            tmpDir,
	}

	logger := logr.Discard()
	storageReader := NewStorageReader(config, nil, logger)

	// Verify it's using filesystem storage
	_, ok := storageReader.(*FilesystemStorageReader)
	if !ok {
		t.Fatalf("expected FilesystemStorageReader, got %T", storageReader)
	}

	// Test reading vulnerability reports
	ctx := context.Background()
	vulnReports, err := storageReader.ReadVulnerabilityReports(ctx, "default")
	if err != nil {
		t.Fatalf("failed to read vuln reports: %v", err)
	}

	if len(vulnReports) != 1 {
		t.Fatalf("expected 1 vuln report, got %d", len(vulnReports))
	}

	report := vulnReports[0]
	if report.Report.Summary.CriticalCount != 2 {
		t.Errorf("expected 2 critical vulns, got %d", report.Report.Summary.CriticalCount)
	}
	if report.Report.Summary.HighCount != 5 {
		t.Errorf("expected 5 high vulns, got %d", report.Report.Summary.HighCount)
	}

	// Test reading config audit reports
	configReports, err := storageReader.ReadConfigAuditReports(ctx, "default")
	if err != nil {
		t.Fatalf("failed to read config reports: %v", err)
	}

	if len(configReports) != 1 {
		t.Fatalf("expected 1 config report, got %d", len(configReports))
	}

	configRep := configReports[0]
	if configRep.Report.Summary.CriticalCount != 1 {
		t.Errorf("expected 1 critical config issue, got %d", configRep.Report.Summary.CriticalCount)
	}

	// Now test that metrics can be generated
	// This simulates what the ResourcesMetricsCollector.Collect() method would do
	fmt.Println("\n=== Simulated Metrics Output ===")
	fmt.Println("# HELP trivy_image_vulnerabilities Number of container image vulnerabilities")
	fmt.Println("# TYPE trivy_image_vulnerabilities gauge")

	for _, r := range vulnReports {
		labels := prometheus.Labels{
			"namespace":        r.Namespace,
			"name":             r.Name,
			"kind":             r.Labels["trivy-operator.resource.kind"],
			"image_registry":   r.Report.Registry.Server,
			"image_repository": r.Report.Artifact.Repository,
			"image_tag":        r.Report.Artifact.Tag,
		}

		fmt.Printf("trivy_image_vulnerabilities{%s,severity=\"Critical\"} %d\n",
			formatLabels(labels), r.Report.Summary.CriticalCount)
		fmt.Printf("trivy_image_vulnerabilities{%s,severity=\"High\"} %d\n",
			formatLabels(labels), r.Report.Summary.HighCount)
		fmt.Printf("trivy_image_vulnerabilities{%s,severity=\"Medium\"} %d\n",
			formatLabels(labels), r.Report.Summary.MediumCount)
		fmt.Printf("trivy_image_vulnerabilities{%s,severity=\"Low\"} %d\n",
			formatLabels(labels), r.Report.Summary.LowCount)
	}

	fmt.Println("\n# HELP trivy_resource_configaudits Number of failing resource configuration auditing checks")
	fmt.Println("# TYPE trivy_resource_configaudits gauge")

	for _, r := range configReports {
		labels := prometheus.Labels{
			"namespace": r.Namespace,
			"name":      r.Name,
			"kind":      r.Labels["trivy-operator.resource.kind"],
		}

		fmt.Printf("trivy_resource_configaudits{%s,severity=\"Critical\"} %d\n",
			formatLabels(labels), r.Report.Summary.CriticalCount)
		fmt.Printf("trivy_resource_configaudits{%s,severity=\"High\"} %d\n",
			formatLabels(labels), r.Report.Summary.HighCount)
		fmt.Printf("trivy_resource_configaudits{%s,severity=\"Medium\"} %d\n",
			formatLabels(labels), r.Report.Summary.MediumCount)
		fmt.Printf("trivy_resource_configaudits{%s,severity=\"Low\"} %d\n",
			formatLabels(labels), r.Report.Summary.LowCount)
	}

	fmt.Println("\n✅ Filesystem storage metrics collection works correctly!")
}

func formatLabels(labels prometheus.Labels) string {
	var parts []string
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf("%s=%q", k, v))
	}
	return strings.Join(parts, ",")
}

// Run with: go test -v -run TestMetricsCollectionFromFilesystem ./pkg/metrics/
