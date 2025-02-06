package trivy_test

import (
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
			resultFileName: "output.json",
			compressedLogs: "true",
			wantArgs:       []string{"-c", "trivy sbom --slow /tmp/scan/bom.json  --skip-db-update  --cache-dir /tmp/trivy/.cache --quiet --format json > /tmp/scan/output.json &&  bzip2 -c /tmp/scan/output.json | base64"},
			wantCmd:        []string{"/bin/sh"},
		},
		{
			name:           "command and args for standalone mode non compress",
			mode:           trivy.Standalone,
			sbomFile:       "/tmp/scan/bom.json",
			serverUrl:      "",
			resultFileName: "",
			compressedLogs: "false",
			wantArgs:       []string{"--cache-dir", "/tmp/trivy/.cache", "--quiet", "sbom", "--format", "json", "/tmp/scan/bom.json", "--slow", "--skip-db-update"},
			wantCmd:        []string{"trivy"},
		},
		{
			name:           "command and args for client/server mode compress",
			mode:           trivy.ClientServer,
			sbomFile:       "/tmp/scan/bom.json",
			serverUrl:      "http://trivy-server:8080",
			resultFileName: "output.json",
			compressedLogs: "true",
			wantArgs:       []string{"-c", "trivy sbom --slow /tmp/scan/bom.json    --cache-dir /tmp/trivy/.cache --quiet --format json --server 'http://trivy-server:8080' > /tmp/scan/output.json &&  bzip2 -c /tmp/scan/output.json | base64"},
			wantCmd:        []string{"/bin/sh"},
		},
		{
			name:           "command and args for client/server mode non compress",
			mode:           trivy.ClientServer,
			sbomFile:       "/tmp/scan/bom.json",
			serverUrl:      "http://trivy-server:8080",
			resultFileName: "",
			compressedLogs: "false",
			wantArgs:       []string{"--cache-dir", "/tmp/trivy/.cache", "--quiet", "sbom", "--format", "json", "--server", "http://trivy-server:8080", "/tmp/scan/bom.json", "--slow"},
			wantCmd:        []string{"trivy"},
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
