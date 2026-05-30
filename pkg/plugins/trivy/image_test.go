package trivy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/aquasecurity/trivy-operator/pkg/plugins/trivy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

func TestCheckGcpCrOrPrivateRegistry(t *testing.T) {
	assert.True(t, trivy.CheckGcpCrOrPrivateRegistry("gcr.io/company/application"))
	assert.True(t, trivy.CheckGcpCrOrPrivateRegistry("us.gcr.io/company/application"))
	assert.True(t, trivy.CheckGcpCrOrPrivateRegistry("eu.gcr.io/company/application"))
	assert.True(t, trivy.CheckGcpCrOrPrivateRegistry("asia.gcr.io/company/application"))
	assert.True(t, trivy.CheckGcpCrOrPrivateRegistry("us-central1-docker.pkg.dev/company/application"))
}

func TestGetMirroredImage(t *testing.T) {
	testCases := []struct {
		name          string
		image         string
		mirrors       map[string]string
		expected      string
		expectedError string
	}{
		{
			name:     "Mirror not match",
			image:    "alpine",
			mirrors:  map[string]string{"gcr.io": "mirror.io"},
			expected: "alpine",
		},
		{
			name:     "Mirror match",
			image:    "alpine",
			mirrors:  map[string]string{"index.docker.io": "mirror.io"},
			expected: "mirror.io/library/alpine:latest",
		},
		{
			name:          "Broken image",
			image:         "alpine@sha256:broken",
			expectedError: "could not parse reference: alpine@sha256:broken",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expected, err := trivy.GetMirroredImage(tc.image, tc.mirrors)
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, expected)
			}
		})
	}
}

// TestScanCommands_NoShellTokens is a regression guard against the
// scan Job's Command/Args reintroducing /bin/sh or its coreutils
// pals. Removing those was the entire point of the distroless
// support work — if a future refactor adds them back, this test
// breaks loudly.
func TestScanCommands_NoShellTokens(t *testing.T) {
	bannedTokens := []string{"/bin/sh", "sh", "bzip2", "base64", "cat"}

	for _, compressLogs := range []string{"true", "false"} {
		t.Run("compressLogs="+compressLogs, func(t *testing.T) {
			cfg := map[string]string{
				"trivy.tag":                    "0.41.0",
				"scanJob.compressLogs":         compressLogs,
				"trivy.clientServerSkipUpdate": "false",
			}
			client := fake.NewClientBuilder().
				WithScheme(trivyoperator.NewScheme()).
				WithObjects(&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "trivy-operator-trivy-config", Namespace: "trivyoperator-ns"},
					Data:       cfg,
				}).
				Build()
			pctx := trivyoperator.NewPluginContext().
				WithName("trivy").
				WithNamespace("trivyoperator-ns").
				WithClient(client).
				WithTrivyOperatorConfig(cfg).
				Get()

			cmd, args := trivy.GetSbomScanCommandAndArgs(pctx, trivy.Standalone, "/tmp/scan/bom.json", "", "result.json")
			for _, banned := range bannedTokens {
				assert.NotContains(t, strings.Join(cmd, " "), banned, "SBOM Command contains banned token %q", banned)
				assert.NotContains(t, strings.Join(args, " "), banned, "SBOM Args contains banned token %q", banned)
			}
			if compressLogs == "false" {
				assert.Equal(t, []string{"trivy"}, cmd, "no-compress should run trivy directly")
				assert.Contains(t, args, "--quiet", "no-compress should pass --quiet")
				assert.NotContains(t, strings.Join(args, " "), "--output", "no-compress should not pass --output (trivy writes to stdout)")
			} else {
				assert.Equal(t, []string{trivy.ScanWrapperPath}, cmd, "compress should run via scan-wrapper")
				assert.Contains(t, args, "--compress")
			}
		})
	}
}

func TestGetSbomScanCommandAndArgs(t *testing.T) {
	testCases := []struct {
		name           string
		mode           trivy.Mode
		sbomFile       string
		serverUrl      string
		resultFileName string
		wantCmd        []string
		wantArgs       []string
		compressedLogs string
	}{
		{
			name:           "command and args for standalone mode compress",
			mode:           trivy.Standalone,
			sbomFile:       "/tmp/scan/bom.json",
			serverUrl:      "",
			resultFileName: "result_output.json",
			compressedLogs: "true",
			wantCmd:        []string{trivy.ScanWrapperPath},
			wantArgs: []string{
				"--compress", "--result", "/tmp/scan/result_output.json", "--",
				"trivy", "--cache-dir", "/tmp/trivy/.cache", "sbom", "--format", "json",
				"/tmp/scan/bom.json", "--slow", "--skip-db-update",
				"--output", "/tmp/scan/result_output.json",
			},
		},
		{
			name:           "command and args for standalone mode non compress",
			mode:           trivy.Standalone,
			sbomFile:       "/tmp/scan/bom.json",
			serverUrl:      "",
			resultFileName: "result_output.json",
			compressedLogs: "false",
			wantCmd:        []string{"trivy"},
			wantArgs: []string{
				"--cache-dir", "/tmp/trivy/.cache", "sbom", "--format", "json",
				"/tmp/scan/bom.json", "--slow", "--skip-db-update", "--quiet",
			},
		},
		{
			name:           "command and args for client/server mode compress",
			mode:           trivy.ClientServer,
			sbomFile:       "/tmp/scan/bom.json",
			serverUrl:      "http://trivy-server:8080",
			resultFileName: "result_output.json",
			compressedLogs: "true",
			wantCmd:        []string{trivy.ScanWrapperPath},
			wantArgs: []string{
				"--compress", "--result", "/tmp/scan/result_output.json", "--",
				"trivy", "--cache-dir", "/tmp/trivy/.cache", "sbom", "--format", "json",
				"--server", "http://trivy-server:8080", "/tmp/scan/bom.json", "--slow",
				"--output", "/tmp/scan/result_output.json",
			},
		},
		{
			name:           "command and args for client/server mode non compress",
			mode:           trivy.ClientServer,
			sbomFile:       "/tmp/scan/bom.json",
			serverUrl:      "http://trivy-server:8080",
			resultFileName: "result_output.json",
			compressedLogs: "false",
			wantCmd:        []string{"trivy"},
			wantArgs: []string{
				"--cache-dir", "/tmp/trivy/.cache", "sbom", "--format", "json",
				"--server", "http://trivy-server:8080", "/tmp/scan/bom.json", "--slow", "--quiet",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewClientBuilder().
				WithScheme(trivyoperator.NewScheme()).
				WithObjects(&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "trivy-operator-trivy-config",
						Namespace: "trivyoperator-ns",
					},
					Data: map[string]string{
						"trivy.tag":                    "0.41.0",
						"scanJob.compressLogs":         tc.compressedLogs,
						"trivy.clientServerSkipUpdate": "false",
					},
				}).
				Build()

			pluginContext := trivyoperator.NewPluginContext().
				WithName("trivy").
				WithNamespace("trivyoperator-ns").
				WithClient(client).
				WithTrivyOperatorConfig(map[string]string{
					"trivy.tag":                    "0.41.0",
					"scanJob.compressLogs":         tc.compressedLogs,
					"trivy.clientServerSkipUpdate": "false",
				}).
				Get()
			cmd, args := trivy.GetSbomScanCommandAndArgs(pluginContext, tc.mode, tc.sbomFile, tc.serverUrl, tc.resultFileName)
			assert.Equal(t, tc.wantCmd, cmd)
			assert.Equal(t, tc.wantArgs, args)
		})
	}
}
