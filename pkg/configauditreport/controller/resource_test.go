package controller

import (
	"path/filepath"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
)

func TestWriteAlternateReports(t *testing.T) {
	// filter() populates only the config-audit data for a non-role resource such
	// as a ReplicaSet, leaving the rbac and infra report structs zero-valued.
	// writeAlternateReports must not write empty files for the report types that
	// do not apply to the resource (see #2853).
	dir := t.TempDir()

	r := &ResourceController{
		Config: etc.Config{
			AltReportStorageEnabled:       true,
			AltReportDir:                  dir,
			InfraAssessmentScannerEnabled: true,
			RbacAssessmentScannerEnabled:  true,
		},
	}

	resource := newTestResource("ReplicaSet")
	resource.SetName("cilium-operator-77d76d7bbb")

	misConfigData := Misconfiguration{
		configAuditReportData: v1alpha1.ConfigAuditReportData{
			Scanner: scanner(r.BuildInfo),
			Checks:  []v1alpha1.Check{{ID: "KSV001", Category: "Kubernetes Security Check"}},
		},
	}

	_, err := r.writeAlternateReports(resource, misConfigData, logr.Discard())
	require.NoError(t, err)

	fileName := "ReplicaSet-cilium-operator-77d76d7bbb.json"

	// the config-audit report is the one filter() populated, so it is written
	assert.FileExists(t, filepath.Join(dir, "config_audit_reports", fileName))

	// the rbac and infra reports do not apply to a ReplicaSet, so neither the
	// files nor their directories should be created
	assert.NoFileExists(t, filepath.Join(dir, "rbac_assessment_reports", fileName))
	assert.NoFileExists(t, filepath.Join(dir, "infra_assessment_reports", fileName))
	assert.NoDirExists(t, filepath.Join(dir, "rbac_assessment_reports"))
	assert.NoDirExists(t, filepath.Join(dir, "infra_assessment_reports"))
}

func TestWriteAlternateReportsRole(t *testing.T) {
	// For a role-type resource (ClusterRole), filter() populates only the rbac
	// report, so only the rbac file should be written.
	dir := t.TempDir()

	r := &ResourceController{
		Config: etc.Config{
			AltReportStorageEnabled:       true,
			AltReportDir:                  dir,
			InfraAssessmentScannerEnabled: true,
			RbacAssessmentScannerEnabled:  true,
		},
	}

	resource := newTestResource("ClusterRole")
	resource.SetName("envoy-gateway-gateway-helm-certgen")

	misConfigData := Misconfiguration{
		rbacAssessmentReportData: v1alpha1.RbacAssessmentReportData{
			Scanner: scanner(r.BuildInfo),
			Checks:  []v1alpha1.Check{{ID: "KSV048", Category: "Kubernetes Security Check"}},
		},
	}

	_, err := r.writeAlternateReports(resource, misConfigData, logr.Discard())
	require.NoError(t, err)

	fileName := "ClusterRole-envoy-gateway-gateway-helm-certgen.json"

	assert.FileExists(t, filepath.Join(dir, "rbac_assessment_reports", fileName))
	assert.NoFileExists(t, filepath.Join(dir, "config_audit_reports", fileName))
	assert.NoFileExists(t, filepath.Join(dir, "infra_assessment_reports", fileName))
	assert.NoDirExists(t, filepath.Join(dir, "config_audit_reports"))
	assert.NoDirExists(t, filepath.Join(dir, "infra_assessment_reports"))
}
