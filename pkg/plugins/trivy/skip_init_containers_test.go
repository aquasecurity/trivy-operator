package trivy_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/plugins/trivy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

func TestGetScanJobSpecSkipInitContainers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      trivy.Mode
		command   trivy.Command
		skipInit  bool
		wantNames []string
	}{
		{name: "image scan skips init containers", mode: trivy.Standalone, command: trivy.Image, skipInit: true, wantNames: []string{"app", "debug"}},
		{name: "image scan includes init containers by default", mode: trivy.Standalone, command: trivy.Image, wantNames: []string{"app", "bootstrap", "debug"}},
		{name: "standalone filesystem scan skips init containers", mode: trivy.Standalone, command: trivy.Filesystem, skipInit: true, wantNames: []string{"app", "debug"}},
		{name: "client server filesystem scan skips init containers", mode: trivy.ClientServer, command: trivy.Filesystem, skipInit: true, wantNames: []string{"app", "debug"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configData := map[string]string{
				"trivy.repository":                "docker.io/aquasec/trivy",
				"trivy.tag":                       "0.35.0",
				"trivy.mode":                      string(tc.mode),
				"trivy.command":                   string(tc.command),
				"trivy.dbRepository":              trivy.DefaultDBRepository,
				"trivy.javaDbRepository":          trivy.DefaultJavaDBRepository,
				"trivy.serverURL":                 "http://trivy-server:4954",
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			}
			fakeClient := fake.NewClientBuilder().WithObjects(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      trivyoperator.GetPluginConfigMapName(trivy.Plugin),
					Namespace: "operator",
				},
				Data: configData,
			}).Build()
			operatorConfig := map[string]string{
				trivyoperator.KeyVulnerabilityScannerEnabled:       "true",
				trivyoperator.KeyVulnerabilityScansInSameNamespace: "true",
			}
			if tc.skipInit {
				operatorConfig["scanJob.skipInitContainers"] = "true"
			}
			pluginContext := trivyoperator.NewPluginContext().
				WithName(trivy.Plugin).
				WithNamespace("operator").
				WithServiceAccountName("operator-sa").
				WithTrivyOperatorConfig(operatorConfig).
				WithClient(fakeClient).
				Get()
			resolver := kube.NewObjectResolver(fakeClient, &kube.CompatibleObjectMapper{})
			instance := trivy.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &resolver)
			workload := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "workload-ns"},
				Spec: corev1.PodSpec{
					Containers:     []corev1.Container{{Name: "app", Image: "example/app:latest"}},
					InitContainers: []corev1.Container{{Name: "bootstrap", Image: "example/bootstrap:latest"}},
					EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
						Name: "debug", Image: "example/debug:latest",
					}}},
				},
			}

			jobSpec, _, err := instance.GetScanJobSpec(pluginContext, workload, nil, nil, make(map[string]v1alpha1.SbomReportData))
			require.NoError(t, err)
			gotNames := make([]string, 0, len(jobSpec.Containers))
			for _, container := range jobSpec.Containers {
				gotNames = append(gotNames, container.Name)
			}
			require.Equal(t, tc.wantNames, gotNames)
		})
	}
}
