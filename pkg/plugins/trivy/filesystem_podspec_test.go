package trivy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

// Regression tests for #3103: filesystem scan jobs run Trivy in a container
// built from the scanned image, so they inherit the image's working directory
// and environment. The scan container must pin both to the operator-provided
// /tmp volume instead, otherwise images with a WORKDIR the scan job cannot
// enter (distroless nonroot, mode 0700) or a TMPDIR that only exists at
// runtime (forgejo rootless) break the scan before it starts.
func assertScanContainerRunsInTmpDir(t *testing.T, spec corev1.PodSpec) {
	require.NotEmpty(t, spec.Containers)
	for _, c := range spec.Containers {
		assert.Equal(t, "/tmp", c.WorkingDir,
			"scan container %q must not inherit the scanned image's working directory", c.Name)
		assert.Contains(t, c.Env, corev1.EnvVar{Name: "TMPDIR", Value: "/tmp"},
			"scan container %q must pin TMPDIR to the operator-provided /tmp volume", c.Name)
	}
}

func newFSPodSpecPluginContext(t *testing.T) (trivyoperator.PluginContext, *plugin) {
	client := fake.NewClientBuilder().
		WithScheme(trivyoperator.NewScheme()).
		WithObjects(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "trivy-operator-trivy-config",
				Namespace: "trivyoperator-ns",
			},
			Data: map[string]string{
				"trivy.repository":   "aquasec/trivy",
				"trivy.tag":          "0.41.0",
				"trivy.dbRepository": "mirror.gcr.io/aquasec/trivy-db",
				"trivy.command":      "filesystem",
				"trivy.serverURL":    "http://trivy-server:4954",
				"vulnerabilityReports.scanJobsInSameNamespace": "true",
			},
		}).
		Build()

	pluginContext := trivyoperator.NewPluginContext().
		WithName("trivy").
		WithNamespace("trivyoperator-ns").
		WithClient(client).
		WithTrivyOperatorConfig(map[string]string{
			"trivy.repository":   "aquasec/trivy",
			"trivy.tag":          "0.41.0",
			"trivy.dbRepository": "mirror.gcr.io/aquasec/trivy-db",
			"trivy.command":      "filesystem",
			"trivy.serverURL":    "http://trivy-server:4954",
			"vulnerabilityReports.scanJobsInSameNamespace": "true",
		}).
		Get()

	resolver := kube.NewObjectResolver(client, &kube.CompatibleObjectMapper{})
	p := NewPlugin(ext.NewSystemClock(), ext.NewSimpleIDGenerator(), &resolver).(*plugin)
	return pluginContext, p
}

func newPodWorkload() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "hubble-relay",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "hubble-relay",
					Image: "quay.io/cilium/hubble-relay:v1.19.5",
				},
			},
		},
	}
}

func TestGetPodSpecForStandaloneFSModePinsWorkDirAndTmpDir(t *testing.T) {
	pluginContext, p := newFSPodSpecPluginContext(t)
	config, err := getConfig(pluginContext)
	require.NoError(t, err)

	spec, _, err := GetPodSpecForStandaloneFSMode(pluginContext, config, newPodWorkload(), nil, &corev1.SecurityContext{}, p, nil)
	require.NoError(t, err)

	assertScanContainerRunsInTmpDir(t, spec)
}

func TestGetPodSpecForClientServerFSModePinsWorkDirAndTmpDir(t *testing.T) {
	pluginContext, p := newFSPodSpecPluginContext(t)
	config, err := getConfig(pluginContext)
	require.NoError(t, err)

	spec, _, err := GetPodSpecForClientServerFSMode(pluginContext, config, newPodWorkload(), nil, &corev1.SecurityContext{}, p, nil)
	require.NoError(t, err)

	assertScanContainerRunsInTmpDir(t, spec)
}
