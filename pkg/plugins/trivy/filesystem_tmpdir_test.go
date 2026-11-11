package trivy_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/plugins/trivy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

func TestFilesystemScanJobUsesWritableTempDirectory(t *testing.T) {
	for _, mode := range []trivy.Mode{trivy.Standalone, trivy.ClientServer} {
		t.Run(string(mode), func(t *testing.T) {
			configData := map[string]string{
				"trivy.repository":                "docker.io/aquasec/trivy",
				"trivy.tag":                       "0.35.0",
				"trivy.mode":                      string(mode),
				"trivy.command":                   string(trivy.Filesystem),
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
			pluginContext := trivyoperator.NewPluginContext().
				WithName(trivy.Plugin).
				WithNamespace("operator").
				WithServiceAccountName("operator-sa").
				WithTrivyOperatorConfig(map[string]string{
					trivyoperator.KeyVulnerabilityScannerEnabled:       "true",
					trivyoperator.KeyVulnerabilityScansInSameNamespace: "true",
				}).
				WithClient(fakeClient).
				Get()
			resolver := kube.NewObjectResolver(fakeClient, &kube.CompatibleObjectMapper{})
			instance := trivy.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &resolver)
			workload := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "workload-ns"},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "example/app:latest"}}},
			}

			jobSpec, _, err := instance.GetScanJobSpec(pluginContext, workload, nil, nil, nil)
			require.NoError(t, err)
			require.Len(t, jobSpec.Containers, 1)
			require.Equal(t, "/tmp", jobSpec.Containers[0].WorkingDir)
			tmpDirSet := false
			for _, env := range jobSpec.Containers[0].Env {
				if env.Name == "TMPDIR" && env.Value == "/tmp" {
					tmpDirSet = true
				}
			}
			require.True(t, tmpDirSet, "scanner container must ignore an image-baked TMPDIR")
		})
	}
}
