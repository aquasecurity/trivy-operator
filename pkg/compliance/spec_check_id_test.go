package compliance

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

// Check IDs in a compliance spec are compared against the IDs on the
// misconfiguration findings with a case sensitive match, so a control that
// spells its check ID in lower case aggregates to zero checks and renders as
// passing even while the underlying check is failing.
func TestComplianceCheckIDMatchIsCaseSensitive(t *testing.T) {
	configAuditList := &v1alpha1.ConfigAuditReportList{
		TypeMeta: v1.TypeMeta{Kind: "ConfigAuditReport"},
		Items: []v1alpha1.ConfigAuditReport{
			{
				ObjectMeta: v1.ObjectMeta{Name: "resource"},
				Report: v1alpha1.ConfigAuditReportData{
					Checks: []v1alpha1.Check{
						{ID: "AVD-KSV-0030", Title: "Seccomp policies should be set", Success: false},
					},
				},
			},
		},
	}
	report := &v1alpha1.ClusterComplianceReport{
		TypeMeta:   v1.TypeMeta{Kind: "ConfigAuditReport"},
		ObjectMeta: v1.ObjectMeta{Name: "nsa"},
		Spec: v1alpha1.ReportSpec{
			ReportFormat: "summary",
			Compliance: v1alpha1.Compliance{
				ID:    "nsa",
				Title: "nsa",
				Controls: []v1alpha1.Control{
					{
						ID:          "1.0",
						Description: "seccomp, spelled as the report spells it",
						Checks:      []v1alpha1.SpecCheck{{ID: "AVD-KSV-0030"}},
					},
					{
						ID:          "2.0",
						Description: "seccomp, spelled in lower case",
						Checks:      []v1alpha1.SpecCheck{{ID: "avd-ksv-0030"}},
					},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).
		WithLists(configAuditList).
		WithObjects(report).
		WithStatusSubresource(report).
		Build()
	require.NoError(t, NewMgr(c).GenerateComplianceReport(t.Context(), report.Spec))

	got, err := getReport(t.Context(), c)
	require.NoError(t, err)
	require.NotNil(t, got.Status.SummaryReport)

	fails := make(map[string]int)
	for _, control := range got.Status.SummaryReport.SummaryControls {
		require.NotNil(t, control.TotalFail, "control %s has no failure count", control.ID)
		fails[control.ID] = *control.TotalFail
	}
	assert.Equal(t, 1, fails["1.0"], "the upper case control should see the failing check")
	assert.Equal(t, 0, fails["2.0"], "the lower case control matches nothing and reports as passing")
}

// The shipped specs are the input to that match, so none of their check IDs
// may be lower cased.
func TestShippedSpecCheckIDsAreUpperCase(t *testing.T) {
	specs, err := filepath.Glob(filepath.Join("..", "..", "deploy", "helm", "templates", "specs", "*.yaml"))
	require.NoError(t, err)
	require.NotEmpty(t, specs)

	checkID := regexp.MustCompile(`(?m)^\s+- id: ((?i:avd|ksv|kcv|cmd)-\S+)`)
	for _, spec := range specs {
		content, err := os.ReadFile(spec)
		require.NoError(t, err)
		for _, match := range checkID.FindAllStringSubmatch(string(content), -1) {
			id := match[1]
			assert.Equal(t, strings.ToUpper(id), id, "%s: check ID %q is not upper case", filepath.Base(spec), id)
		}
	}
}
