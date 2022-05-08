package conftest_test

import (
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	"context"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/plugin/conftest"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/stretchr/testify/require"
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

func TestConfig_GetPoliciesByKind(t *testing.T) {

	t.Run("Should return error when kinds are not defined for policy", func(t *testing.T) {
		g := NewGomegaWithT(t)
		config := conftest.Config{
			PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"conftest.library.kubernetes.rego":        "<REGO_A>",
					"conftest.library.utils.rego":             "<REGO_B>",
					"conftest.policy.access_to_host_pid.rego": "<REGO_C>",
				},
			},
		}
		_, err := config.GetPoliciesByKind("Pod")
		g.Expect(err).To(MatchError("kinds not defined for policy: conftest.policy.access_to_host_pid.rego"))
	})

	t.Run("Should return error when policy is not found", func(t *testing.T) {
		g := NewGomegaWithT(t)
		config := conftest.Config{
			PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"conftest.policy.access_to_host_pid.kinds": "Workload",
				},
			},
		}
		_, err := config.GetPoliciesByKind("Pod")
		g.Expect(err).To(MatchError("expected policy not found: conftest.policy.access_to_host_pid.rego"))
	})

	t.Run("Should return policies as Rego modules", func(t *testing.T) {

		g := NewGomegaWithT(t)
		config := conftest.Config{
			PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"conftest.imageRef": "openpolicyagent/conftest:v0.23.0",

					"conftest.resources.requests.cpu":    "50m",
					"conftest.resources.requests.memory": "50M",
					"conftest.resources.limits.cpu":      "300m",
					"conftest.resources.limits.memory":   "300M",

					"conftest.library.kubernetes.rego":                       "<REGO_A>",
					"conftest.library.utils.rego":                            "<REGO_B>",
					"conftest.policy.access_to_host_pid.rego":                "<REGO_C>",
					"conftest.policy.cpu_not_limited.rego":                   "<REGO_D>",
					"conftest.policy.configmap_with_sensitive_data.rego":     "<REGO_E>",
					"conftest.policy.configmap_with_secret_data.rego":        "<REGO_F>",
					"conftest.policy.object_without_recommended_labels.rego": "<REGO_G>",

					"conftest.policy.access_to_host_pid.kinds":                "Pod,ReplicaSet",
					"conftest.policy.cpu_not_limited.kinds":                   "Workload",
					"conftest.policy.configmap_with_sensitive_data.kinds":     "ConfigMap",
					"conftest.policy.configmap_with_secret_data.kinds":        "ConfigMap",
					"conftest.policy.object_without_recommended_labels.kinds": "*",

					// This one should be skipped (no .rego suffix)
					"conftest.policy.privileged": "<REGO_E>",
					// This one should be skipped (no conftest.policy. prefix)
					"foo": "bar",
				},
			},
		}
		g.Expect(config.GetPoliciesByKind("Pod")).To(Equal(map[string]string{
			"conftest.policy.access_to_host_pid.rego":                "<REGO_C>",
			"conftest.policy.cpu_not_limited.rego":                   "<REGO_D>",
			"conftest.policy.object_without_recommended_labels.rego": "<REGO_G>",
		}))
		g.Expect(config.GetPoliciesByKind("ConfigMap")).To(Equal(map[string]string{
			"conftest.policy.configmap_with_sensitive_data.rego":     "<REGO_E>",
			"conftest.policy.configmap_with_secret_data.rego":        "<REGO_F>",
			"conftest.policy.object_without_recommended_labels.rego": "<REGO_G>",
		}))
	})
}

func TestConfig_GetResourceRequirements(t *testing.T) {
	testCases := []struct {
		name                 string
		config               conftest.Config
		expectedError        string
		expectedRequirements corev1.ResourceRequirements
	}{
		{
			name:          "Should return empty requirements by default",
			config:        conftest.Config{PluginConfig: trivyoperator.PluginConfig{}},
			expectedError: "",
			expectedRequirements: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{},
				Limits:   corev1.ResourceList{},
			},
		},
		{
			name: "Should return configured resource requirement",
			config: conftest.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"conftest.resources.requests.cpu":    "800m",
					"conftest.resources.requests.memory": "200M",
					"conftest.resources.limits.cpu":      "600m",
					"conftest.resources.limits.memory":   "700M",
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
			config: conftest.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"conftest.resources.requests.cpu": "roughly 100",
				},
			}},
			expectedError: "parsing resource definition conftest.resources.requests.cpu: roughly 100 quantities must match the regular expression '^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$'",
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

	testCases := []struct {
		name       string
		configData map[string]string
		obj        client.Object
		expected   bool
	}{
		{
			name: "Should return false if there are no policies",
			configData: map[string]string{
				"conftest.imageRef": "openpolicyagent/conftest:v0.30.0",
			},
			obj: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
			},
			expected: false,
		},
		{
			name: "Should return true if there is at least one policy",
			configData: map[string]string{
				"conftest.imageRef":                "openpolicyagent/conftest:v0.30.0",
				"conftest.policy.kubernetes.kinds": "Pod",
				"conftest.policy.kubernetes.rego": `package main

deny[res] {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot

  msg := "Containers must not run as root"

  res := {
    "msg": msg,
    "title": "Runs as root user"
  }
}
`},
			obj: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
			},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewGomegaWithT(t)

			client := fake.NewClientBuilder().WithObjects(
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:            "trivyoperator-conftest-config",
						Namespace:       "trivyoperator-ns",
						ResourceVersion: "0",
					},
					Data: tc.configData,
				}).Build()

			pluginContext := trivyoperator.NewPluginContext().
				WithName(conftest.Plugin).
				WithNamespace("trivyoperator-ns").
				WithServiceAccountName("trivyoperator-sa").
				WithClient(client).
				Get()

			instance := conftest.NewPlugin(ext.NewSimpleIDGenerator(), fixedClock)
			ready, _, err := instance.IsApplicable(pluginContext, tc.obj)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(ready).To(Equal(tc.expected))
		})
	}

}

func TestPlugin_Init(t *testing.T) {

	t.Run("Should create the default config", func(t *testing.T) {
		g := NewGomegaWithT(t)

		client := fake.NewClientBuilder().WithObjects().Build()

		instance := conftest.NewPlugin(ext.NewSimpleIDGenerator(), fixedClock)

		pluginContext := trivyoperator.NewPluginContext().
			WithName(conftest.Plugin).
			WithNamespace("trivyoperator-ns").
			WithServiceAccountName("trivyoperator-sa").
			WithClient(client).
			Get()
		err := instance.Init(pluginContext)
		g.Expect(err).ToNot(HaveOccurred())

		var cm corev1.ConfigMap
		err = client.Get(context.Background(), types.NamespacedName{
			Namespace: "trivyoperator-ns",
			Name:      "trivyoperator-conftest-config",
		}, &cm)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(cm).To(Equal(corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "trivyoperator-conftest-config",
				Namespace: "trivyoperator-ns",
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "trivyoperator",
				},
				ResourceVersion: "1",
			},
			Data: map[string]string{
				"conftest.imageRef":                  "openpolicyagent/conftest:v0.30.0",
				"conftest.resources.requests.cpu":    "50m",
				"conftest.resources.requests.memory": "50M",
				"conftest.resources.limits.cpu":      "300m",
				"conftest.resources.limits.memory":   "300M",
			},
		}))
	})

	t.Run("Should not overwrite existing config", func(t *testing.T) {
		g := NewGomegaWithT(t)

		client := fake.NewClientBuilder().WithObjects(
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "trivyoperator-conftest-config",
					Namespace:       "trivyoperator-ns",
					ResourceVersion: "0",
				},
				Data: map[string]string{
					"conftest.imageRef": "openpolicyagent/conftest:v0.30.0",
				},
			}).Build()

		pluginContext := trivyoperator.NewPluginContext().
			WithName(conftest.Plugin).
			WithNamespace("trivyoperator-ns").
			WithServiceAccountName("trivyoperator-sa").
			WithClient(client).
			Get()

		instance := conftest.NewPlugin(ext.NewSimpleIDGenerator(), fixedClock)
		err := instance.Init(pluginContext)
		g.Expect(err).ToNot(HaveOccurred())

		var cm corev1.ConfigMap
		err = client.Get(context.Background(), types.NamespacedName{
			Namespace: "trivyoperator-ns",
			Name:      "trivyoperator-conftest-config",
		}, &cm)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(cm).To(Equal(corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            "trivyoperator-conftest-config",
				Namespace:       "trivyoperator-ns",
				ResourceVersion: "0",
			},
			Data: map[string]string{
				"conftest.imageRef": "openpolicyagent/conftest:v0.30.0",
			},
		}))
	})
}

func TestPlugin_GetScanJobSpec(t *testing.T) {
	g := NewGomegaWithT(t)
	sequence := ext.NewSimpleIDGenerator()
	pluginContext := trivyoperator.NewPluginContext().
		WithName(conftest.Plugin).
		WithNamespace("trivyoperator-ns").
		WithServiceAccountName("trivyoperator-sa").
		WithClient(fake.NewClientBuilder().WithObjects(&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "trivyoperator-conftest-config",
				Namespace: "trivyoperator-ns",
			},
			Data: map[string]string{
				"conftest.imageRef": "openpolicyagent/conftest:v0.23.0",

				"conftest.resources.requests.cpu":    "50m",
				"conftest.resources.requests.memory": "50M",
				"conftest.resources.limits.cpu":      "300m",
				"conftest.resources.limits.memory":   "300M",

				"conftest.library.kubernetes.rego":        "<REGO>",
				"conftest.library.utils.rego":             "<REGO>",
				"conftest.policy.access_to_host_pid.rego": "<REGO>",
				"conftest.policy.cpu_not_limited.rego":    "<REGO>",

				"conftest.policy.access_to_host_pid.kinds": "*",
				"conftest.policy.cpu_not_limited.kinds":    "*",

				"conftest.policy.privileged": "<REGO>", // This one should be skipped (no .rego suffix)

				"foo": "bar", // This one should be skipped (no conftest.policy. prefix)
			},
		}).Build()).Get()

	instance := conftest.NewPlugin(sequence, fixedClock)

	jobSpec, secrets, err := instance.GetScanJobSpec(pluginContext, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:1.16",
				},
			},
		},
	})

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(jobSpec).To(MatchFields(IgnoreExtras, Fields{
		"ServiceAccountName":           Equal("trivyoperator-sa"),
		"AutomountServiceAccountToken": PointTo(BeFalse()),
		"RestartPolicy":                Equal(corev1.RestartPolicyNever),
		"Affinity":                     Equal(trivyoperator.LinuxNodeAffinity()),
		"Volumes": ConsistOf(
			MatchFields(IgnoreExtras, Fields{
				"Name": Equal("scan-configauditreport-789cbb5cc4-volume"),
				// We cannot inline assert here on other properties with the MatchFields matcher
				// because the value of the Secret field is the pointer to v1.SecretVolumeSource.
				// The MatchFields matcher only works with structs :-(
			}),
		),
		"Containers": ContainElements(
			MatchFields(IgnoreExtras, Fields{
				"Name":                     Equal("conftest"),
				"Image":                    Equal("openpolicyagent/conftest:v0.23.0"),
				"ImagePullPolicy":          Equal(corev1.PullIfNotPresent),
				"TerminationMessagePolicy": Equal(corev1.TerminationMessageFallbackToLogsOnError),
				"Resources": Equal(corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("300m"),
						corev1.ResourceMemory: resource.MustParse("300M"),
					},
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("50m"),
						corev1.ResourceMemory: resource.MustParse("50M"),
					},
				}),
				"VolumeMounts": ConsistOf(
					corev1.VolumeMount{
						Name:      "scan-configauditreport-789cbb5cc4-volume",
						MountPath: "/project/policy/kubernetes.rego",
						SubPath:   "kubernetes.rego",
						ReadOnly:  true,
					},
					corev1.VolumeMount{
						Name:      "scan-configauditreport-789cbb5cc4-volume",
						MountPath: "/project/policy/utils.rego",
						SubPath:   "utils.rego",
						ReadOnly:  true,
					},
					corev1.VolumeMount{
						Name:      "scan-configauditreport-789cbb5cc4-volume",
						MountPath: "/project/policy/access_to_host_pid.rego",
						SubPath:   "access_to_host_pid.rego",
						ReadOnly:  true,
					},
					corev1.VolumeMount{
						Name:      "scan-configauditreport-789cbb5cc4-volume",
						MountPath: "/project/policy/cpu_not_limited.rego",
						SubPath:   "cpu_not_limited.rego",
						ReadOnly:  true,
					},
					corev1.VolumeMount{
						Name:      "scan-configauditreport-789cbb5cc4-volume",
						MountPath: "/project/workload.yaml",
						SubPath:   "workload.yaml",
						ReadOnly:  true,
					},
				),
				"Command": Equal([]string{
					"sh",
				}),
				"Args": Equal([]string{
					"-c",
					"conftest test --no-fail --output json --all-namespaces --policy /project/policy /project/workload.yaml",
				}),
				"SecurityContext": Equal(&corev1.SecurityContext{
					Privileged:               pointer.BoolPtr(false),
					AllowPrivilegeEscalation: pointer.BoolPtr(false),
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"all"},
					},
					ReadOnlyRootFilesystem: pointer.BoolPtr(true),
				}),
			}),
		),
		"SecurityContext": Equal(&corev1.PodSecurityContext{}),
	}))
	g.Expect(*jobSpec.Volumes[0].VolumeSource.Secret).To(MatchFields(IgnoreExtras, Fields{
		"SecretName": Equal("scan-configauditreport-789cbb5cc4-volume"),
		"Items": ConsistOf(
			corev1.KeyToPath{
				Key:  "conftest.library.kubernetes.rego",
				Path: "kubernetes.rego",
			},
			corev1.KeyToPath{
				Key:  "conftest.library.utils.rego",
				Path: "utils.rego",
			},
			corev1.KeyToPath{
				Key:  "conftest.policy.access_to_host_pid.rego",
				Path: "access_to_host_pid.rego",
			},
			corev1.KeyToPath{
				Key:  "conftest.policy.cpu_not_limited.rego",
				Path: "cpu_not_limited.rego",
			},
			corev1.KeyToPath{
				Key:  "trivyoperator.workload.yaml",
				Path: "workload.yaml",
			},
		),
	}))
	g.Expect(secrets).To(ConsistOf(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scan-configauditreport-789cbb5cc4-volume",
				Namespace: "trivyoperator-ns",
			},
			StringData: map[string]string{
				"conftest.library.kubernetes.rego":        "<REGO>",
				"conftest.library.utils.rego":             "<REGO>",
				"conftest.policy.access_to_host_pid.rego": "<REGO>",
				"conftest.policy.cpu_not_limited.rego":    "<REGO>",
				"trivyoperator.workload.yaml": `metadata:
  creationTimestamp: null
  name: nginx
  namespace: default
spec:
  containers:
  - image: nginx:1.16
    name: nginx
    resources: {}
status: {}
`,
			},
		},
	))
}
func TestPlugin_ParseConfigAuditReportData(t *testing.T) {
	t.Run("data with Title", func(t *testing.T) {
		g := NewGomegaWithT(t)
		plugin := conftest.NewPlugin(ext.NewSimpleIDGenerator(), fixedClock)
		logsReaderByte, err := ioutil.ReadFile("./testdata/fixture/config_audit_log_reader_with_title.json")
		logsReader := ioutil.NopCloser(strings.NewReader(string(logsReaderByte)))
		pluginContext := trivyoperator.NewPluginContext().
			WithName(conftest.Plugin).
			WithNamespace("trivyoperator-ns").
			WithServiceAccountName("trivyoperator-sa").
			WithClient(fake.NewClientBuilder().WithObjects(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "trivyoperator-conftest-config",
					Namespace: "trivyoperator-ns",
				},
				Data: map[string]string{
					"conftest.imageRef": "openpolicyagent/conftest:v0.30.0",
				},
			}).Build()).
			Get()

		data, err := plugin.ParseConfigAuditReportData(pluginContext, logsReader)

		// When Conftest plugin is used with https://github.com/aquasecurity/appshield
		// Rego scripts the Check.ID is not unique. For example, for a Pod with multiple
		// containers the Check.ID will be duplicated for each container, but the
		// Check.Message will be different.
		groupChecksByMessages := func(element interface{}) string {
			return strings.Join(element.(v1alpha1.Check).Messages, ",")
		}

		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(data).To(MatchFields(IgnoreExtras, Fields{
			"UpdateTimestamp": Equal(metav1.NewTime(fixedTime)),
			"Scanner": Equal(v1alpha1.Scanner{
				Name:    "Conftest",
				Vendor:  "Open Policy Agent",
				Version: "v0.30.0",
			}),
			"Summary": Equal(v1alpha1.ConfigAuditSummary{
				CriticalCount: 6,
				LowCount:      0,
			}),
			"Checks": MatchAllElements(groupChecksByMessages, Elements{
				"container kubedns of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
					ID:       "Default capabilities: some containers do not drop all",
					Messages: []string{"container kubedns of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container dnsmasq of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
					ID:       "Default capabilities: some containers do not drop all",
					Messages: []string{"container dnsmasq of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container sidecar of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
					ID:       "Default capabilities: some containers do not drop all",
					Messages: []string{"container sidecar of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container prometheus-to-sd of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
					ID:       "Default capabilities: some containers do not drop all",
					Messages: []string{"container prometheus-to-sd of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container dnsmasq of deployment kube-dns in default namespace should set securityContext.readOnlyRootFilesystem to true": Equal(v1alpha1.Check{
					ID:       "Root file system is not read-only",
					Messages: []string{"container dnsmasq of deployment kube-dns in default namespace should set securityContext.readOnlyRootFilesystem to true"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container prometheus-to-sd of deployment kube-dns in default namespace should set resources.requests.cpu": Equal(v1alpha1.Check{
					// If the author of a Rego script does not provide the title property
					// in the rule's response, which is then returned as metadata.type
					// in Conftest output, the parser will fallback to a unique identifier.
					ID:       "00000000-0000-0000-0000-000000000001",
					Messages: []string{"container prometheus-to-sd of deployment kube-dns in default namespace should set resources.requests.cpu"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
			}),
			// Most Rego scripts do not return structured response object to indicate
			// container name. Therefore, the ContainerChecks map is empty.
			"ContainerChecks": Equal(map[string][]v1alpha1.Check{}),
			"PodChecks": MatchAllElements(groupChecksByMessages, Elements{
				"container kubedns of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
					ID:       "Default capabilities: some containers do not drop all",
					Messages: []string{"container kubedns of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container dnsmasq of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
					ID:       "Default capabilities: some containers do not drop all",
					Messages: []string{"container dnsmasq of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container sidecar of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
					ID:       "Default capabilities: some containers do not drop all",
					Messages: []string{"container sidecar of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container prometheus-to-sd of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
					ID:       "Default capabilities: some containers do not drop all",
					Messages: []string{"container prometheus-to-sd of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container dnsmasq of deployment kube-dns in default namespace should set securityContext.readOnlyRootFilesystem to true": Equal(v1alpha1.Check{
					ID:       "Root file system is not read-only",
					Messages: []string{"container dnsmasq of deployment kube-dns in default namespace should set securityContext.readOnlyRootFilesystem to true"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container prometheus-to-sd of deployment kube-dns in default namespace should set resources.requests.cpu": Equal(v1alpha1.Check{
					// If the author of a Rego script does not provide the title property
					// in the rule's response, which is then returned as metadata.type
					// in Conftest output, the parser will fallback to a unique identifier.
					ID:       "00000000-0000-0000-0000-000000000001",
					Messages: []string{"container prometheus-to-sd of deployment kube-dns in default namespace should set resources.requests.cpu"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
			}),
		}))
	})
	t.Run("data with title and id", func(t *testing.T) {

		g := NewGomegaWithT(t)
		plugin := conftest.NewPlugin(ext.NewSimpleIDGenerator(), fixedClock)
		logsReaderByte, err := ioutil.ReadFile("./testdata/fixture/config_audit_log_reader_with_title_id.json")
		logsReader := ioutil.NopCloser(strings.NewReader(string(logsReaderByte)))
		pluginContext := trivyoperator.NewPluginContext().
			WithName(conftest.Plugin).
			WithNamespace("trivyoperator-ns").
			WithServiceAccountName("trivyoperator-sa").
			WithClient(fake.NewClientBuilder().WithObjects(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "trivyoperator-conftest-config",
					Namespace: "trivyoperator-ns",
				},
				Data: map[string]string{
					"conftest.imageRef": "openpolicyagent/conftest:v0.30.0",
				},
			}).Build()).
			Get()

		data, err := plugin.ParseConfigAuditReportData(pluginContext, logsReader)

		// When Conftest plugin is used with https://github.com/aquasecurity/appshield
		// Rego scripts the Check.ID is not unique. For example, for a Pod with multiple
		// containers the Check.ID will be duplicated for each container, but the
		// Check.Message will be different.
		groupChecksByMessages := func(element interface{}) string {
			return strings.Join(element.(v1alpha1.Check).Messages, ",")
		}

		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(data).To(MatchFields(IgnoreExtras, Fields{
			"UpdateTimestamp": Equal(metav1.NewTime(fixedTime)),
			"Scanner": Equal(v1alpha1.Scanner{
				Name:    "Conftest",
				Vendor:  "Open Policy Agent",
				Version: "v0.30.0",
			}),
			"Summary": Equal(v1alpha1.ConfigAuditSummary{
				CriticalCount: 6,
				LowCount:      0,
			}),
			"Checks": MatchAllElements(groupChecksByMessages, Elements{
				"container kubedns of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
					ID:       "KSV003",
					Messages: []string{"container kubedns of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container dnsmasq of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
					ID:       "KSV003",
					Messages: []string{"container dnsmasq of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container sidecar of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
					ID:       "KSV003",
					Messages: []string{"container sidecar of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container prometheus-to-sd of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
					ID:       "KSV003",
					Messages: []string{"container prometheus-to-sd of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container dnsmasq of deployment kube-dns in default namespace should set securityContext.readOnlyRootFilesystem to true": Equal(v1alpha1.Check{
					ID:       "KSV014",
					Messages: []string{"container dnsmasq of deployment kube-dns in default namespace should set securityContext.readOnlyRootFilesystem to true"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container prometheus-to-sd of deployment kube-dns in default namespace should set resources.requests.cpu": Equal(v1alpha1.Check{
					// If the author of a Rego script does not provide the title property
					// in the rule's response, which is then returned as metadata.type
					// in Conftest output, the parser will fallback to a unique identifier.
					ID:       "00000000-0000-0000-0000-000000000001",
					Messages: []string{"container prometheus-to-sd of deployment kube-dns in default namespace should set resources.requests.cpu"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
			}),
			// Most Rego scripts do not return structured response object to indicate
			// container name. Therefore, the ContainerChecks map is empty.
			"ContainerChecks": Equal(map[string][]v1alpha1.Check{}),
			"PodChecks": MatchAllElements(groupChecksByMessages, Elements{
				"container kubedns of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
					ID:       "KSV003",
					Messages: []string{"container kubedns of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container dnsmasq of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
					ID:       "KSV003",
					Messages: []string{"container dnsmasq of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container sidecar of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
					ID:       "KSV003",
					Messages: []string{"container sidecar of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container prometheus-to-sd of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop": Equal(v1alpha1.Check{
					ID:       "KSV003",
					Messages: []string{"container prometheus-to-sd of deployment kube-dns in default namespace should add 'ALL' to securityContext.capabilities.drop"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container dnsmasq of deployment kube-dns in default namespace should set securityContext.readOnlyRootFilesystem to true": Equal(v1alpha1.Check{
					ID:       "KSV014",
					Messages: []string{"container dnsmasq of deployment kube-dns in default namespace should set securityContext.readOnlyRootFilesystem to true"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
				"container prometheus-to-sd of deployment kube-dns in default namespace should set resources.requests.cpu": Equal(v1alpha1.Check{
					// If the author of a Rego script does not provide the title property
					// in the rule's response, which is then returned as metadata.type
					// in Conftest output, the parser will fallback to a unique identifier.
					ID:       "00000000-0000-0000-0000-000000000001",
					Messages: []string{"container prometheus-to-sd of deployment kube-dns in default namespace should set resources.requests.cpu"},
					Success:  false,
					Severity: v1alpha1.SeverityCritical,
					Category: "Security",
				}),
			}),
		}))
	})
}
func TestPlugin_ConfigHash(t *testing.T) {

	newPluginContextWithConfigData := func(data map[string]string) trivyoperator.PluginContext {
		return trivyoperator.NewPluginContext().
			WithName("Conftest").
			WithNamespace("trivyoperator-ns").
			WithClient(fake.NewClientBuilder().
				WithObjects(&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "trivyoperator-conftest-config",
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
			"conftest.policy.policyA.rego":  "foo",
			"conftest.policy.policyA.kinds": "Pod",
		})
		pluginContext2 := newPluginContextWithConfigData(map[string]string{
			"conftest.policy.policyA.rego":  "bar",
			"conftest.policy.policyA.kinds": "Pod",
		})

		plugin := conftest.NewPlugin(ext.NewSimpleIDGenerator(), fixedClock)
		hash1, err := plugin.ConfigHash(pluginContext1, "Pod")
		g.Expect(err).ToNot(HaveOccurred())

		hash2, err := plugin.ConfigHash(pluginContext2, "Pod")
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

		plugin := conftest.NewPlugin(ext.NewSimpleIDGenerator(), fixedClock)
		hash1, err := plugin.ConfigHash(pluginContext1, "")
		g.Expect(err).ToNot(HaveOccurred())

		hash2, err := plugin.ConfigHash(pluginContext2, "")
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(hash1).To(Equal(hash2))
	})

	t.Run("Should exclude resource requirements from calculating hash", func(t *testing.T) {
		g := NewGomegaWithT(t)

		pluginContext1 := newPluginContextWithConfigData(map[string]string{
			"foo":                             "bar",
			"conftest.resources.requests.cpu": "50m",
		})
		pluginContext2 := newPluginContextWithConfigData(map[string]string{
			"foo":                             "bar",
			"conftest.resources.requests.cpu": "60m",
		})

		plugin := conftest.NewPlugin(ext.NewSimpleIDGenerator(), fixedClock)
		hash1, err := plugin.ConfigHash(pluginContext1, "")
		g.Expect(err).ToNot(HaveOccurred())

		hash2, err := plugin.ConfigHash(pluginContext2, "")
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(hash1).To(Equal(hash2))
	})
}

func TestPlugin_GetContainerName(t *testing.T) {
	g := NewGomegaWithT(t)

	plugin := conftest.NewPlugin(ext.NewSimpleIDGenerator(), fixedClock)
	g.Expect(plugin.GetContainerName()).To(Equal("conftest"))
}
