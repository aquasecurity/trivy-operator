package webhook

import (
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

func Test_sendReports(t *testing.T) {
	testcases := []struct {
		name          string
		want          string
		inputReport   any
		timeout       time.Duration
		expectedError string
		headerValues  http.Header
	}{
		{
			name: "happy path, vuln report data",
			want: `{"metadata":{"creationTimestamp":null},"report":{"updateTimestamp":null,"scanner":{"name":"","vendor":"","version":""},"registry":{"server":""},"artifact":{"repository":""},"os":{"family":""},"summary":{"criticalCount":0,"highCount":0,"mediumCount":0,"lowCount":0,"unknownCount":0,"noneCount":0},"vulnerabilities":[{"vulnerabilityID":"CVE-2022-1234","resource":"","installedVersion":"1.2.3","fixedVersion":"3.4.5","severity":"CRITICAL","title":"foo bar very baz", "lastModifiedDate":"", "links":null, "publishedDate":"", "target":"","class":"os-pkgs"}]}}`,
			inputReport: v1alpha1.VulnerabilityReport{
				Report: v1alpha1.VulnerabilityReportData{
					Vulnerabilities: []v1alpha1.Vulnerability{
						{
							VulnerabilityID:  "CVE-2022-1234",
							InstalledVersion: "1.2.3",
							FixedVersion:     "3.4.5",
							Severity:         "CRITICAL",
							Title:            "foo bar very baz",
							Class:            "os-pkgs",
						},
					},
				},
			},
			timeout:      time.Hour,
			headerValues: http.Header{},
		},
		{
			name: "happy path, secret report data",
			want: `{"metadata":{"creationTimestamp":null},"report":{"updateTimestamp":null,"scanner":{"name":"","vendor":"","version":""},"registry":{"server":""},"artifact":{"repository":""},"summary":{"criticalCount":0,"highCount":0,"mediumCount":0,"lowCount":0},"secrets":[{"target":"foo bar baz","ruleID":"foo123","title":"bad bad secret","category":"","severity":"CRITICAL","match":""}]}}`,
			inputReport: v1alpha1.ExposedSecretReport{
				Report: v1alpha1.ExposedSecretReportData{
					Secrets: []v1alpha1.ExposedSecret{
						{
							Target:   "foo bar baz",
							RuleID:   "foo123",
							Title:    "bad bad secret",
							Severity: "CRITICAL",
						},
					},
				},
			},
			timeout:      time.Hour,
			headerValues: http.Header{},
		},
		{
			name: "sad path, timeout occurs",
			inputReport: v1alpha1.VulnerabilityReport{
				Report: v1alpha1.VulnerabilityReportData{},
			},
			timeout:       time.Nanosecond,
			expectedError: "context deadline exceeded (Client.Timeout exceeded while awaiting headers)",
			headerValues:  http.Header{},
		},
		{
			name:          "sad path, bad report",
			inputReport:   math.Inf(1),
			timeout:       time.Hour,
			expectedError: `failed to marshal reports`,
			headerValues:  http.Header{},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				assert.JSONEq(t, tc.want, string(b))
			}))
			defer ts.Close()
			gotError := sendReport(tc.inputReport, ts.URL, tc.timeout, tc.headerValues)
			switch {
			case tc.expectedError != "":
				require.ErrorContains(t, gotError, tc.expectedError, tc.name)
			default:
				require.NoError(t, gotError, tc.name)
			}
		})
	}
}
