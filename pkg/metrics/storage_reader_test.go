package metrics

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

func TestCRDStorageReader(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	// Create test data
	vr1 := &v1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-vuln-1",
			Namespace: "default",
			Labels: labels.Set{
				trivyoperator.LabelResourceKind:  "ReplicaSet",
				trivyoperator.LabelResourceName:  "nginx",
				trivyoperator.LabelContainerName: "nginx",
			},
		},
		Report: v1alpha1.VulnerabilityReportData{
			Summary: v1alpha1.VulnerabilitySummary{
				CriticalCount: 1,
				HighCount:     2,
			},
		},
	}

	vr2 := &v1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-vuln-2",
			Namespace: "kube-system",
			Labels: labels.Set{
				trivyoperator.LabelResourceKind:  "Deployment",
				trivyoperator.LabelResourceName:  "coredns",
				trivyoperator.LabelContainerName: "coredns",
			},
		},
		Report: v1alpha1.VulnerabilityReportData{
			Summary: v1alpha1.VulnerabilitySummary{
				CriticalCount: 0,
				HighCount:     1,
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(vr1, vr2).
		Build()

	reader := NewCRDStorageReader(client, logr.Discard())

	t.Run("ReadVulnerabilityReports - all namespaces", func(t *testing.T) {
		ctx := context.Background()
		reports, err := reader.ReadVulnerabilityReports(ctx, "")

		require.NoError(t, err)
		assert.Len(t, reports, 2)
	})

	t.Run("ReadVulnerabilityReports - specific namespace", func(t *testing.T) {
		ctx := context.Background()
		reports, err := reader.ReadVulnerabilityReports(ctx, "default")

		require.NoError(t, err)
		assert.Len(t, reports, 1)
		assert.Equal(t, "test-vuln-1", reports[0].Name)
		assert.Equal(t, "default", reports[0].Namespace)
	})
}

func TestFilesystemStorageReader(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Create test vulnerability reports
	vulnReportsDir := filepath.Join(tmpDir, "vulnerability_reports")
	require.NoError(t, os.MkdirAll(vulnReportsDir, 0o750))

	vr1 := v1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-vuln-1",
			Namespace: "default",
			Labels: labels.Set{
				trivyoperator.LabelResourceKind:  "ReplicaSet",
				trivyoperator.LabelResourceName:  "nginx",
				trivyoperator.LabelContainerName: "nginx",
			},
		},
		Report: v1alpha1.VulnerabilityReportData{
			Summary: v1alpha1.VulnerabilitySummary{
				CriticalCount: 1,
				HighCount:     2,
			},
		},
	}

	vr2 := v1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-vuln-2",
			Namespace: "kube-system",
			Labels: labels.Set{
				trivyoperator.LabelResourceKind:  "Deployment",
				trivyoperator.LabelResourceName:  "coredns",
				trivyoperator.LabelContainerName: "coredns",
			},
		},
		Report: v1alpha1.VulnerabilityReportData{
			Summary: v1alpha1.VulnerabilitySummary{
				CriticalCount: 0,
				HighCount:     1,
			},
		},
	}

	// Write reports as JSON files
	vr1Data, err := json.Marshal(vr1)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(vulnReportsDir, "ReplicaSet-nginx-nginx.json"), vr1Data, 0o600))

	vr2Data, err := json.Marshal(vr2)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(vulnReportsDir, "Deployment-coredns-coredns.json"), vr2Data, 0o600))

	reader := NewFilesystemStorageReader(tmpDir, logr.Discard())

	t.Run("ReadVulnerabilityReports - all namespaces", func(t *testing.T) {
		ctx := context.Background()
		reports, err := reader.ReadVulnerabilityReports(ctx, "")

		require.NoError(t, err)
		assert.Len(t, reports, 2)
	})

	t.Run("ReadVulnerabilityReports - specific namespace", func(t *testing.T) {
		ctx := context.Background()
		reports, err := reader.ReadVulnerabilityReports(ctx, "default")

		require.NoError(t, err)
		assert.Len(t, reports, 1)
		assert.Equal(t, "test-vuln-1", reports[0].Name)
		assert.Equal(t, "default", reports[0].Namespace)
	})

	t.Run("ReadVulnerabilityReports - non-existent directory", func(t *testing.T) {
		reader := NewFilesystemStorageReader("/non/existent/path", logr.Discard())
		ctx := context.Background()
		reports, err := reader.ReadVulnerabilityReports(ctx, "")

		// Should not return an error, just an empty list
		require.NoError(t, err)
		assert.Empty(t, reports)
	})

	// Test config audit reports
	t.Run("ReadConfigAuditReports", func(t *testing.T) {
		configAuditDir := filepath.Join(tmpDir, "config_audit_reports")
		require.NoError(t, os.MkdirAll(configAuditDir, 0o750))

		car := v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-config-1",
				Namespace: "default",
				Labels: labels.Set{
					trivyoperator.LabelResourceKind: "Pod",
					trivyoperator.LabelResourceName: "test-pod",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{
				Summary: v1alpha1.ConfigAuditSummary{
					CriticalCount: 1,
					HighCount:     2,
				},
			},
		}

		carData, err := json.Marshal(car)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(configAuditDir, "Pod-test-pod.json"), carData, 0o600))

		ctx := context.Background()
		reports, err := reader.ReadConfigAuditReports(ctx, "")

		require.NoError(t, err)
		assert.Len(t, reports, 1)
		assert.Equal(t, "test-config-1", reports[0].Name)
	})

	// Test cluster compliance reports
	t.Run("ReadClusterComplianceReports", func(t *testing.T) {
		complianceDir := filepath.Join(tmpDir, "cluster_compliance_report")
		require.NoError(t, os.MkdirAll(complianceDir, 0o750))

		ccr := v1alpha1.ClusterComplianceReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "nsa-1.0",
			},
			Spec: v1alpha1.ReportSpec{
				Compliance: v1alpha1.Compliance{
					Title:       "NSA",
					Description: "National Security Agency - Kubernetes Hardening Guidance",
				},
			},
			Status: v1alpha1.ReportStatus{
				Summary: v1alpha1.ComplianceSummary{
					PassCount: 10,
					FailCount: 2,
				},
			},
		}

		ccrData, err := json.Marshal(ccr)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(complianceDir, "ClusterComplianceReport-nsa-1.0.json"), ccrData, 0o600))

		ctx := context.Background()
		reports, err := reader.ReadClusterComplianceReports(ctx)

		require.NoError(t, err)
		assert.Len(t, reports, 1)
		assert.Equal(t, "nsa-1.0", reports[0].Name)
	})

	// Test array format (some reports might be written as arrays)
	t.Run("ReadReports - array format", func(t *testing.T) {
		secretsDir := filepath.Join(tmpDir, "secret_reports")
		require.NoError(t, os.MkdirAll(secretsDir, 0o750))

		esr1 := v1alpha1.ExposedSecretReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret-1",
				Namespace: "default",
			},
		}

		esr2 := v1alpha1.ExposedSecretReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret-2",
				Namespace: "default",
			},
		}

		// Write as an array
		esrArray := []v1alpha1.ExposedSecretReport{esr1, esr2}
		esrData, err := json.Marshal(esrArray)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(secretsDir, "Pod-test-pod.json"), esrData, 0o600))

		ctx := context.Background()
		reports, err := reader.ReadExposedSecretReports(ctx, "")

		require.NoError(t, err)
		assert.Len(t, reports, 2)
	})

	// Test handling of corrupt JSON files
	t.Run("ReadReports - corrupt JSON file", func(t *testing.T) {
		rbacDir := filepath.Join(tmpDir, "rbac_assessment_reports")
		require.NoError(t, os.MkdirAll(rbacDir, 0o750))

		// Write invalid JSON
		require.NoError(t, os.WriteFile(filepath.Join(rbacDir, "corrupt.json"), []byte("not valid json"), 0o600))

		ctx := context.Background()
		reports, err := reader.ReadRbacAssessmentReports(ctx, "")

		// Should not fail, just skip the corrupt file
		require.NoError(t, err)
		assert.Empty(t, reports)
	})
}

func TestNewStorageReader(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(scheme))
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	t.Run("Returns CRDStorageReader when alternate storage disabled", func(t *testing.T) {
		config := etc.Config{
			AltReportStorageEnabled: false,
			AltReportDir:            "",
		}

		reader := NewStorageReader(config, client, logr.Discard())

		_, ok := reader.(*CRDStorageReader)
		assert.True(t, ok, "Expected CRDStorageReader")
	})

	t.Run("Returns FilesystemStorageReader when alternate storage enabled", func(t *testing.T) {
		tmpDir := t.TempDir()
		config := etc.Config{
			AltReportStorageEnabled: true,
			AltReportDir:            tmpDir,
		}

		reader := NewStorageReader(config, client, logr.Discard())

		_, ok := reader.(*FilesystemStorageReader)
		assert.True(t, ok, "Expected FilesystemStorageReader")
	})

	t.Run("Returns CRDStorageReader when dir is empty", func(t *testing.T) {
		config := etc.Config{
			AltReportStorageEnabled: true,
			AltReportDir:            "",
		}

		reader := NewStorageReader(config, client, logr.Discard())

		_, ok := reader.(*CRDStorageReader)
		assert.True(t, ok, "Expected CRDStorageReader when dir is empty")
	})
}

func TestFilesystemStorageReader_AllReportTypes(t *testing.T) {
	tmpDir := t.TempDir()
	reader := NewFilesystemStorageReader(tmpDir, logr.Discard())
	ctx := context.Background()

	t.Run("ReadExposedSecretReports", func(t *testing.T) {
		dir := filepath.Join(tmpDir, "secret_reports")
		require.NoError(t, os.MkdirAll(dir, 0o750))

		esr := v1alpha1.ExposedSecretReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret",
				Namespace: "default",
			},
		}

		data, err := json.Marshal(esr)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "test.json"), data, 0o600))

		reports, err := reader.ReadExposedSecretReports(ctx, "")
		require.NoError(t, err)
		assert.Len(t, reports, 1)
	})

	t.Run("ReadRbacAssessmentReports", func(t *testing.T) {
		dir := filepath.Join(tmpDir, "rbac_assessment_reports")
		require.NoError(t, os.MkdirAll(dir, 0o750))

		rar := v1alpha1.RbacAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-rbac",
				Namespace: "default",
				Labels: map[string]string{
					"trivy-operator.resource.kind": "Role",
					"trivy-operator.resource.name": "test-role",
				},
			},
		}

		data, err := json.Marshal(rar)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "test.json"), data, 0o600))

		reports, err := reader.ReadRbacAssessmentReports(ctx, "")
		require.NoError(t, err)
		assert.Len(t, reports, 1)
	})

	t.Run("ReadInfraAssessmentReports", func(t *testing.T) {
		dir := filepath.Join(tmpDir, "infra_assessment_reports")
		require.NoError(t, os.MkdirAll(dir, 0o750))

		iar := v1alpha1.InfraAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-infra",
				Namespace: "default",
				Labels: map[string]string{
					"trivy-operator.resource.kind": "Pod",
					"trivy-operator.resource.name": "test-pod",
				},
			},
		}

		data, err := json.Marshal(iar)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "test.json"), data, 0o600))

		reports, err := reader.ReadInfraAssessmentReports(ctx, "")
		require.NoError(t, err)
		assert.Len(t, reports, 1)
	})

	t.Run("ReadClusterRbacAssessmentReports", func(t *testing.T) {
		dir := filepath.Join(tmpDir, "cluster_rbac_assessment_reports")
		require.NoError(t, os.MkdirAll(dir, 0o750))

		crar := v1alpha1.ClusterRbacAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-cluster-rbac",
				Labels: map[string]string{
					"trivy-operator.resource.kind": "ClusterRole",
					"trivy-operator.resource.name": "test-cluster-role",
				},
			},
		}

		data, err := json.Marshal(crar)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "test.json"), data, 0o600))

		reports, err := reader.ReadClusterRbacAssessmentReports(ctx)
		require.NoError(t, err)
		assert.Len(t, reports, 1)
	})
}
