package trivy_test

import (
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/plugins/trivy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetSbomFSScanningArgs(t *testing.T) {
	testCases := []struct {
		name           string
		mode           trivy.Mode
		sbomFile       string
		serverUrl      string
		resultFileName string
		wantCmd        []string
		wantArgs       []string
	}{
		{
			name:           "command and args for standalone mode",
			mode:           trivy.Standalone,
			sbomFile:       "/tmp/scan/bom.json",
			serverUrl:      "",
			resultFileName: "",
			wantArgs:       []string{"--cache-dir", "/var/trivyoperator/trivy-db", "--quiet", "sbom", "--format", "json", "--skip-db-update", "/tmp/scan/bom.json", "--slow"},
			wantCmd:        []string{trivy.SharedVolumeLocationOfTrivy},
		},
		{
			name:           "command and args for client/server mode",
			mode:           trivy.ClientServer,
			sbomFile:       "/tmp/scan/bom.json",
			serverUrl:      "http://trivy-server:8080",
			resultFileName: "",
			wantArgs:       []string{"--cache-dir", "/var/trivyoperator/trivy-db", "--quiet", "sbom", "--format", "json", "--skip-db-update", "/tmp/scan/bom.json", "--server", "http://trivy-server:8080", "--slow"},
			wantCmd:        []string{trivy.SharedVolumeLocationOfTrivy},
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
					"trivy.clientServerSkipUpdate": "false",
				}).
				Get()
			cmd, args := trivy.GetSbomFSScanningArgs(pluginContext, tc.mode, tc.serverUrl, tc.sbomFile)
			assert.Equal(t, tc.wantCmd, cmd)
			assert.Equal(t, tc.wantArgs, args)
		})
	}
}

func TestGetFSScanningArgs(t *testing.T) {
	testCases := []struct {
		name           string
		mode           trivy.Mode
		command        trivy.Command
		serverUrl      string
		resultFileName string
		wantArgs       []string
	}{
		{
			name:     "command and args for standalone mode",
			mode:     trivy.Standalone,
			command:  trivy.Filesystem,
			wantArgs: []string{"--cache-dir", "/var/trivyoperator/trivy-db", "--quiet", "filesystem", "--scanners", "", "--skip-db-update", "--format", "json", "/", "--slow", "--include-dev-deps"},
		},
		{
			name:           "command and args for client/server mode",
			mode:           trivy.ClientServer,
			command:        trivy.Rootfs,
			serverUrl:      "http://trivy-server:8080",
			resultFileName: "",
			wantArgs:       []string{"--cache-dir", "/var/trivyoperator/trivy-db", "--quiet", "filesystem", "--scanners", "", "--skip-db-update", "--format", "json", "/", "--server", "http://trivy-server:8080", "--slow", "--include-dev-deps"},
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
						"trivy.clientServerSkipUpdate": "false",
						"trivy.includeDevDeps":         "true",
					},
				}).
				Build()

			pluginContext := trivyoperator.NewPluginContext().
				WithName("trivy").
				WithNamespace("trivyoperator-ns").
				WithClient(client).
				WithTrivyOperatorConfig(map[string]string{
					"trivy.tag":                    "0.41.0",
					"trivy.clientServerSkipUpdate": "false",
				}).
				Get()
			args := trivy.GetFSScanningArgs(pluginContext, trivy.Filesystem, tc.mode, tc.serverUrl)
			assert.Equal(t, tc.wantArgs, args)
		})
	}
}
