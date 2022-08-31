package webhook

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_sendReports(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		assert.JSONEq(t, `[{"metadata":{"creationTimestamp":null},"report":{"updateTimestamp":null,"scanner":{"name":"","vendor":"","version":""},"registry":{"server":""},"artifact":{"repository":""},"summary":{"criticalCount":0,"highCount":0,"mediumCount":0,"lowCount":0,"unknownCount":0,"noneCount":0},"vulnerabilities":[{"vulnerabilityID":"CVE-2022-1234","resource":"","installedVersion":"1.2.3","fixedVersion":"3.4.5","severity":"CRITICAL","title":"foo bar very baz","links":null,"target":""}]}}]`, string(b))
	}))
	defer ts.Close()

	require.NoError(t, sendReports([]v1alpha1.VulnerabilityReport{
		{
			Report: v1alpha1.VulnerabilityReportData{
				Vulnerabilities: []v1alpha1.Vulnerability{
					{
						VulnerabilityID:  "CVE-2022-1234",
						InstalledVersion: "1.2.3",
						FixedVersion:     "3.4.5",
						Severity:         "CRITICAL",
						Title:            "foo bar very baz",
					},
				},
			},
		},
	}, ts.URL, time.Second))

	// TODO: Add more test cases
}
