package polaris_test

import (
	. "github.com/onsi/gomega"

	"context"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/plugin/polaris"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	fixedTime  = time.Now()
	fixedClock = ext.NewFixedClock(fixedTime)
)

const polarisVersion = "4.2"

func TestConfig_GetResourceRequirements(t *testing.T) {
	testCases := []struct {
		name                 string
		config               polaris.Config
		expectedError        string
		expectedRequirements corev1.ResourceRequirements
	}{
		{
			name:          "Should return empty requirements by default",
			config:        polaris.Config{PluginConfig: trivyoperator.PluginConfig{}},
			expectedError: "",
			expectedRequirements: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{},
				Limits:   corev1.ResourceList{},
			},
		},
		{
			name: "Should return configured resource requirement",
			config: polaris.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"polaris.resources.requests.cpu":    "800m",
					"polaris.resources.requests.memory": "200M",
					"polaris.resources.limits.cpu":      "600m",
					"polaris.resources.limits.memory":   "700M",
				},
			}},
			expectedError: "",
			expectedRequirements: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("800m"),
					corev1.ResourceMemory: resource.MustParse("200M"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("600m"),
					corev1.ResourceMemory: resource.MustParse("700M"),
				},
			},
		},
		{
			name: "Should return error if resource is not parseable",
			config: polaris.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"polaris.resources.requests.cpu": "roughly 100",
				},
			}},
			expectedError: "parsing resource definition polaris.resources.requests.cpu: roughly 100 quantities must match the regular expression '^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$'",
			expectedRequirements: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("800m"),
					corev1.ResourceMemory: resource.MustParse("200M"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("600m"),
					corev1.ResourceMemory: resource.MustParse("700M"),
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resourceRequirement, err := tc.config.GetResourceRequirements()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expectedRequirements, resourceRequirement, tc.name)
			}

		})
	}
}

func TestPlugin_IsApplicable(t *testing.T) {

	t.Run("Should always return true", func(t *testing.T) {
		g := NewGomegaWithT(t)

		client := fake.NewClientBuilder().Build()

		pluginContext := trivyoperator.NewPluginContext().
			WithName(polaris.Plugin).
			WithNamespace("trivyoperator-ns").
			WithServiceAccountName("trivyoperator-sa").
			WithClient(client).
			Get()

		instance := polaris.NewPlugin(fixedClock)
		ready, _, err := instance.IsApplicable(pluginContext, &corev1.Pod{})
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(ready).To(BeTrue())
	})
}

func TestPlugin_Init(t *testing.T) {

	t.Run("Should create the default config", func(t *testing.T) {
		g := NewGomegaWithT(t)

		client := fake.NewClientBuilder().Build()

		pluginContext := trivyoperator.NewPluginContext().
			WithName(polaris.Plugin).
			WithNamespace("trivyoperator-ns").
			WithServiceAccountName("trivyoperator-sa").
			WithClient(client).
			Get()

		instance := polaris.NewPlugin(fixedClock)
		err := instance.Init(pluginContext)
		g.Expect(err).ToNot(HaveOccurred())

		var cm corev1.ConfigMap
		err = client.Get(context.Background(), types.NamespacedName{
			Namespace: "trivyoperator-ns",
			Name:      "trivyoperator-polaris-config",
		}, &cm)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(cm).To(Equal(corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "trivyoperator-polaris-config",
				Namespace: "trivyoperator-ns",
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "trivyoperator",
				},
				ResourceVersion: "1",
			},
			Data: map[string]string{
				"polaris.imageRef":                  "quay.io/fairwinds/polaris:" + polarisVersion,
				"polaris.config.yaml":               polaris.DefaultConfigYAML,
				"polaris.resources.requests.cpu":    "50m",
				"polaris.resources.requests.memory": "50M",
				"polaris.resources.limits.cpu":      "300m",
				"polaris.resources.limits.memory":   "300M",
			},
		}))
	})

	t.Run("Should not overwrite existing config", func(t *testing.T) {
		g := NewGomegaWithT(t)

		client := fake.NewClientBuilder().WithObjects(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "trivyoperator-polaris-config",
				Namespace:       "trivyoperator-ns",
				ResourceVersion: "0",
			},
			Data: map[string]string{
				"polaris.imageRef": "quay.io/fairwinds/polaris:" + polarisVersion,
				"polaris.config.yaml": `checks:
  cpuRequestsMissing: warning`,
			},
		}).Build()

		pluginContext := trivyoperator.NewPluginContext().
			WithName(polaris.Plugin).
			WithNamespace("trivyoperator-ns").
			WithServiceAccountName("trivyoperator-sa").
			WithClient(client).
			Get()

		instance := polaris.NewPlugin(fixedClock)
		err := instance.Init(pluginContext)
		g.Expect(err).ToNot(HaveOccurred())

		var cm corev1.ConfigMap
		err = client.Get(context.Background(), types.NamespacedName{
			Namespace: "trivyoperator-ns",
			Name:      "trivyoperator-polaris-config",
		}, &cm)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(cm).To(Equal(corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            "trivyoperator-polaris-config",
				Namespace:       "trivyoperator-ns",
				ResourceVersion: "0",
			},
			Data: map[string]string{
				"polaris.imageRef": "quay.io/fairwinds/polaris:" + polarisVersion,
				"polaris.config.yaml": `checks:
  cpuRequestsMissing: warning`,
			},
		}))
	})

}

func TestPlugin_GetScanJobSpec(t *testing.T) {
	testCases := []struct {
		name string

		config map[string]string
		obj    client.Object

		expectedJobSpec corev1.PodSpec
	}{
		{
			name: "Should return job spec for Deployment",
			config: map[string]string{
				"polaris.imageRef":                  "quay.io/fairwinds/polaris:" + polarisVersion,
				"polaris.resources.requests.cpu":    "50m",
				"polaris.resources.requests.memory": "50M",
				"polaris.resources.limits.cpu":      "300m",
				"polaris.resources.limits.memory":   "300M",
			},
			obj: &appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "apps/v1",
					Kind:       "Deployment",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: metav1.NamespaceDefault,
				},
			},
			expectedJobSpec: corev1.PodSpec{
				ServiceAccountName:           "trivyoperator-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(true),
				RestartPolicy:                corev1.RestartPolicyNever,
				Affinity:                     trivyoperator.LinuxNodeAffinity(),
				Volumes: []corev1.Volume{
					{
						Name: "config",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: trivyoperator.GetPluginConfigMapName(polaris.Plugin),
								},
							},
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "polaris",
						Image:                    "quay.io/fairwinds/polaris:" + polarisVersion,
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Resources: corev1.ResourceRequirements{
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("300m"),
								corev1.ResourceMemory: resource.MustParse("300M"),
							},
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("50m"),
								corev1.ResourceMemory: resource.MustParse("50M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "config",
								MountPath: "/etc/trivyoperator",
							},
						},
						Command: []string{"sh"},
						Args: []string{
							"-c",
							"polaris audit --log-level error --config /etc/trivyoperator/polaris.config.yaml --resource default/Deployment.apps/v1/nginx 2> /dev/null",
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.BoolPtr(false),
							AllowPrivilegeEscalation: pointer.BoolPtr(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.BoolPtr(true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewGomegaWithT(t)

			pluginContext := trivyoperator.NewPluginContext().
				WithName(polaris.Plugin).
				WithNamespace("trivyoperator-ns").
				WithServiceAccountName("trivyoperator-sa").
				WithClient(fake.NewClientBuilder().WithObjects(&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "trivyoperator-polaris-config",
						Namespace: "trivyoperator-ns",
					},
					Data: tc.config,
				}).Build()).Get()

			instance := polaris.NewPlugin(fixedClock)
			jobSpec, secrets, err := instance.GetScanJobSpec(pluginContext, tc.obj)

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(secrets).To(BeNil())
			g.Expect(jobSpec).To(Equal(tc.expectedJobSpec))
		})
	}

}

func TestPlugin_GetContainerName(t *testing.T) {
	g := NewGomegaWithT(t)
	plugin := polaris.NewPlugin(fixedClock)
	g.Expect(plugin.GetContainerName()).To(Equal("polaris"))
}

func TestPlugin_ParseConfigAuditReportData(t *testing.T) {
	g := NewGomegaWithT(t)
	testReport, err := os.Open("testdata/polaris-report.json")
	g.Expect(err).ToNot(HaveOccurred())
	defer func() {
		_ = testReport.Close()
	}()

	pluginContext := trivyoperator.NewPluginContext().
		WithName(polaris.Plugin).
		WithNamespace("trivyoperator-ns").
		WithServiceAccountName("trivyoperator-sa").
		WithClient(fake.NewClientBuilder().WithObjects(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "trivyoperator-polaris-config",
				Namespace: "trivyoperator-ns",
			},
			Data: map[string]string{
				"polaris.imageRef": "quay.io/fairwinds/polaris:" + polarisVersion,
			},
		}).Build()).
		Get()

	plugin := polaris.NewPlugin(fixedClock)
	result, err := plugin.ParseConfigAuditReportData(pluginContext, testReport)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(result.UpdateTimestamp).To(Equal(metav1.NewTime(fixedTime)))
	g.Expect(result.Scanner).To(Equal(v1alpha1.Scanner{
		Name:    "Polaris",
		Vendor:  "Fairwinds Ops",
		Version: polarisVersion,
	}))
	g.Expect(result.Summary).To(Equal(v1alpha1.ConfigAuditSummary{
		CriticalCount: 1,
		LowCount:      1,
	}))
	g.Expect(result.PodChecks).To(ConsistOf(v1alpha1.Check{
		ID:       "hostIPCSet",
		Messages: []string{"Host IPC is not configured"},
		Success:  false,
		Severity: v1alpha1.SeverityCritical,
		Category: "Security",
	}, v1alpha1.Check{
		ID:       "hostNetworkSet",
		Messages: []string{"Host network is not configured"},
		Success:  true,
		Severity: v1alpha1.SeverityLow,
		Category: "Networking",
	}))
	g.Expect(result.ContainerChecks).To(HaveLen(1))
	g.Expect(result.ContainerChecks["db"]).To(ConsistOf(v1alpha1.Check{
		ID:       "cpuLimitsMissing",
		Messages: []string{"CPU limits are set"},
		Success:  false,
		Severity: v1alpha1.SeverityLow,
		Category: "Resources",
		Scope: &v1alpha1.CheckScope{
			Type:  "Container",
			Value: "db",
		},
	}, v1alpha1.Check{
		ID:       "cpuRequestsMissing",
		Messages: []string{"CPU requests are set"},
		Success:  true,
		Severity: v1alpha1.SeverityLow,
		Category: "Resources",
		Scope: &v1alpha1.CheckScope{
			Type:  "Container",
			Value: "db",
		},
	}))
}

func TestPlugin_ConfigHash(t *testing.T) {

	newPluginContextWithConfigData := func(data map[string]string) trivyoperator.PluginContext {
		return trivyoperator.NewPluginContext().
			WithName(polaris.Plugin).
			WithNamespace("trivyoperator-ns").
			WithClient(fake.NewClientBuilder().
				WithObjects(&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "trivyoperator-polaris-config",
						Namespace: "trivyoperator-ns",
					},
					Data: data,
				}).
				Build()).
			Get()
	}

	t.Run("Should return different hash for different config data", func(t *testing.T) {
		g := NewGomegaWithT(t)

		pluginContext1 := newPluginContextWithConfigData(map[string]string{
			"foo":   "bar",
			"brown": "fox",
		})
		pluginContext2 := newPluginContextWithConfigData(map[string]string{
			"brown": "fox",
			"foo":   "baz",
		})

		plugin := polaris.NewPlugin(fixedClock)
		hash1, err := plugin.ConfigHash(pluginContext1, "")
		g.Expect(err).ToNot(HaveOccurred())

		hash2, err := plugin.ConfigHash(pluginContext2, "")
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(hash1).ToNot(Equal(hash2))
	})

	t.Run("Should return the same hash for the same config data", func(t *testing.T) {
		g := NewGomegaWithT(t)

		pluginContext1 := newPluginContextWithConfigData(map[string]string{
			"foo":   "bar",
			"brown": "fox",
		})
		pluginContext2 := newPluginContextWithConfigData(map[string]string{
			"brown": "fox",
			"foo":   "bar",
		})

		plugin := polaris.NewPlugin(fixedClock)
		hash1, err := plugin.ConfigHash(pluginContext1, "")
		g.Expect(err).ToNot(HaveOccurred())

		hash2, err := plugin.ConfigHash(pluginContext2, "")
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(hash1).To(Equal(hash2))
	})

	t.Run("Should exclude resource requirements from calculating hash", func(t *testing.T) {
		g := NewGomegaWithT(t)

		pluginContext1 := newPluginContextWithConfigData(map[string]string{
			"foo":                           "bar",
			"polaris.resources.request.cpu": "50m",
		})
		pluginContext2 := newPluginContextWithConfigData(map[string]string{
			"foo":                           "bar",
			"polaris.resources.request.cpu": "60m",
		})

		plugin := polaris.NewPlugin(fixedClock)
		hash1, err := plugin.ConfigHash(pluginContext1, "")
		g.Expect(err).ToNot(HaveOccurred())

		hash2, err := plugin.ConfigHash(pluginContext2, "")
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(hash1).To(Equal(hash2))
	})
}
