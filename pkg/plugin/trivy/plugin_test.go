package trivy_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/plugin/trivy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/stretchr/testify/assert"
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

const defaultDBRepository = "ghcr.io/aquasecurity/trivy-db"

func TestConfig_GetImageRef(t *testing.T) {
	testCases := []struct {
		name             string
		configData       trivy.Config
		expectedError    string
		expectedImageRef string
	}{
		{
			name:          "Should return error",
			configData:    trivy.Config{PluginConfig: trivyoperator.PluginConfig{}},
			expectedError: "property trivy.imageRef not set",
		},
		{
			name: "Should return image reference from config data",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.imageRef": "gcr.io/aquasecurity/trivy:0.8.0",
				},
			}},
			expectedImageRef: "gcr.io/aquasecurity/trivy:0.8.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			imageRef, err := tc.configData.GetImageRef()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedImageRef, imageRef)
			}
		})
	}
}

func TestConfig_GetMode(t *testing.T) {
	testCases := []struct {
		name          string
		configData    trivy.Config
		expectedError string
		expectedMode  trivy.Mode
	}{
		{
			name: "Should return Standalone",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.mode": "Standalone",
				},
			}},
			expectedMode: trivy.Standalone,
		},
		{
			name: "Should return ClientServer",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.mode": "ClientServer",
				},
			}},
			expectedMode: trivy.ClientServer,
		},
		{
			name:          "Should return error when value is not set",
			configData:    trivy.Config{PluginConfig: trivyoperator.PluginConfig{}},
			expectedError: "property trivy.mode not set",
		},
		{
			name: "Should return error when value is not allowed",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.mode": "P2P",
				},
			}},
			expectedError: "invalid value (P2P) of trivy.mode; allowed values (Standalone, ClientServer)",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mode, err := tc.configData.GetMode()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedMode, mode)
			}
		})
	}
}

func TestConfig_GetCommand(t *testing.T) {
	testCases := []struct {
		name            string
		configData      trivy.Config
		expectedError   string
		expectedCommand trivy.Command
	}{
		{
			name: "Should return image",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.command": "image",
				},
			}},
			expectedCommand: trivy.Image,
		},
		{
			name: "Should return image when value is not set",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{},
			}},
			expectedCommand: trivy.Image,
		},
		{
			name: "Should return filesystem",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.command": "filesystem",
				},
			}},
			expectedCommand: trivy.Filesystem,
		},
		{
			name: "Should return error when value is not allowed",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.command": "ls",
				},
			}},
			expectedError: "invalid value (ls) of trivy.command; allowed values (image, filesystem)",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			command, err := tc.configData.GetCommand()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedCommand, command)
			}
		})
	}
}

func TestConfig_GetResourceRequirements(t *testing.T) {
	testCases := []struct {
		name                 string
		config               trivy.Config
		expectedError        string
		expectedRequirements corev1.ResourceRequirements
	}{
		{
			name: "Should return empty requirements by default",
			config: trivy.Config{
				PluginConfig: trivyoperator.PluginConfig{},
			},
			expectedError: "",
			expectedRequirements: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{},
				Limits:   corev1.ResourceList{},
			},
		},
		{
			name: "Should return configured resource requirement",
			config: trivy.Config{
				PluginConfig: trivyoperator.PluginConfig{
					Data: map[string]string{
						"trivy.dbRepository":              defaultDBRepository,
						"trivy.resources.requests.cpu":    "800m",
						"trivy.resources.requests.memory": "200M",
						"trivy.resources.limits.cpu":      "600m",
						"trivy.resources.limits.memory":   "700M",
					},
				},
			},
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
			config: trivy.Config{
				PluginConfig: trivyoperator.PluginConfig{
					Data: map[string]string{
						"trivy.resources.requests.cpu": "roughly 100",
					},
				},
			},
			expectedError: "parsing resource definition trivy.resources.requests.cpu: roughly 100 quantities must match the regular expression '^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$'",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resourceRequirement, err := tc.config.GetResourceRequirements()
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedRequirements, resourceRequirement, tc.name)
			}
		})
	}
}

func TestConfig_IgnoreFileExists(t *testing.T) {
	testCases := []struct {
		name           string
		configData     trivy.Config
		expectedOutput bool
	}{
		{
			name: "Should return false",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}},
			expectedOutput: false,
		},
		{
			name: "Should return true",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
					"trivy.ignoreFile": `# Accept the risk
CVE-2018-14618

# No impact in our settings
CVE-2019-1543`,
				},
			}},
			expectedOutput: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exists := tc.configData.IgnoreFileExists()
			assert.Equal(t, tc.expectedOutput, exists)
		})
	}
}

func TestConfig_IgnoreUnfixed(t *testing.T) {
	testCases := []struct {
		name           string
		configData     trivy.Config
		expectedOutput bool
	}{
		{
			name: "Should return false",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}},
			expectedOutput: false,
		},
		{
			name: "Should return true",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo":                 "bar",
					"trivy.ignoreUnfixed": "true",
				},
			}},
			expectedOutput: true,
		},
		{
			name: "Should return false when set it as false",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo":                 "bar",
					"trivy.ignoreUnfixed": "false",
				},
			}},
			expectedOutput: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exists := tc.configData.IgnoreUnfixed()
			assert.Equal(t, tc.expectedOutput, exists)
		})
	}
}

func TestConfig_GetInsecureRegistries(t *testing.T) {
	testCases := []struct {
		name           string
		configData     trivy.Config
		expectedOutput map[string]bool
	}{
		{
			name: "Should return nil map when there is no key with trivy.insecureRegistry. prefix",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}},
			expectedOutput: make(map[string]bool),
		},
		{
			name: "Should return insecure registries in map",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo":                                "bar",
					"trivy.insecureRegistry.pocRegistry": "poc.myregistry.harbor.com.pl",
					"trivy.insecureRegistry.qaRegistry":  "qa.registry.aquasec.com",
				},
			}},
			expectedOutput: map[string]bool{
				"poc.myregistry.harbor.com.pl": true,
				"qa.registry.aquasec.com":      true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			insecureRegistries := tc.configData.GetInsecureRegistries()
			assert.Equal(t, tc.expectedOutput, insecureRegistries)
		})
	}
}

func TestConfig_GetNonSSLRegistries(t *testing.T) {
	testCases := []struct {
		name           string
		configData     trivy.Config
		expectedOutput map[string]bool
	}{
		{
			name: "Should return nil map when there is no key with trivy.nonSslRegistry. prefix",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}},
			expectedOutput: make(map[string]bool),
		},
		{
			name: "Should return insecure registries in map",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo":                              "bar",
					"trivy.nonSslRegistry.pocRegistry": "poc.myregistry.harbor.com.pl",
					"trivy.nonSslRegistry.qaRegistry":  "qa.registry.aquasec.com",
				},
			}},
			expectedOutput: map[string]bool{
				"poc.myregistry.harbor.com.pl": true,
				"qa.registry.aquasec.com":      true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nonSslRegistries := tc.configData.GetNonSSLRegistries()
			assert.Equal(t, tc.expectedOutput, nonSslRegistries)
		})
	}
}

func TestConfig_GetMirrors(t *testing.T) {
	testCases := []struct {
		name           string
		configData     trivy.Config
		expectedOutput map[string]string
	}{
		{
			name: "Should return empty map when there is no key with trivy.mirrors.registry. prefix",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}},
			expectedOutput: make(map[string]string),
		},
		{
			name: "Should return mirrors in a map",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.registry.mirror.docker.io": "mirror.io",
				},
			}},
			expectedOutput: map[string]string{"docker.io": "mirror.io"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedOutput, tc.configData.GetMirrors())
		})
	}
}

func TestPlugin_Init(t *testing.T) {

	t.Run("Should create the default config", func(t *testing.T) {
		client := fake.NewClientBuilder().WithObjects().Build()

		instance := trivy.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), client)

		pluginContext := trivyoperator.NewPluginContext().
			WithName(trivy.Plugin).
			WithNamespace("trivyoperator-ns").
			WithServiceAccountName("trivyoperator-sa").
			WithClient(client).
			Get()
		err := instance.Init(pluginContext)
		require.NoError(t, err)

		var cm corev1.ConfigMap
		err = client.Get(context.Background(), types.NamespacedName{
			Namespace: "trivyoperator-ns",
			Name:      "trivyoperator-trivy-config",
		}, &cm)
		require.NoError(t, err)
		assert.Equal(t, corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "trivyoperator-trivy-config",
				Namespace: "trivyoperator-ns",
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "trivyoperator",
				},
				ResourceVersion: "1",
			},
			Data: map[string]string{
				"trivy.imageRef":     "docker.io/aquasec/trivy:0.25.2",
				"trivy.severity":     "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
				"trivy.mode":         "Standalone",
				"trivy.timeout":      "5m0s",
				"trivy.dbRepository": defaultDBRepository,

				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			},
		}, cm)
	})

	t.Run("Should not overwrite existing config", func(t *testing.T) {
		client := fake.NewClientBuilder().WithObjects(
			&corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            "trivyoperator-trivy-config",
					Namespace:       "trivyoperator-ns",
					ResourceVersion: "1",
				},
				Data: map[string]string{
					"trivy.imageRef": "docker.io/aquasec/trivy:0.25.2",
					"trivy.severity": "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
					"trivy.mode":     "Standalone",
				},
			}).Build()

		instance := trivy.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), client)

		pluginContext := trivyoperator.NewPluginContext().
			WithName(trivy.Plugin).
			WithNamespace("trivyoperator-ns").
			WithServiceAccountName("trivyoperator-sa").
			WithClient(client).
			Get()
		err := instance.Init(pluginContext)
		require.NoError(t, err)

		var cm corev1.ConfigMap
		err = client.Get(context.Background(), types.NamespacedName{
			Namespace: "trivyoperator-ns",
			Name:      "trivyoperator-trivy-config",
		}, &cm)
		require.NoError(t, err)
		assert.Equal(t, corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            "trivyoperator-trivy-config",
				Namespace:       "trivyoperator-ns",
				ResourceVersion: "1",
			},
			Data: map[string]string{
				"trivy.imageRef": "docker.io/aquasec/trivy:0.25.2",
				"trivy.severity": "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
				"trivy.mode":     "Standalone",
			},
		}, cm)
	})
}

func TestPlugin_GetScanJobSpec(t *testing.T) {

	tmpVolume := corev1.Volume{
		Name: "tmp",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumDefault,
			},
		},
	}

	tmpVolumeMount := corev1.VolumeMount{
		Name:      "tmp",
		MountPath: "/tmp",
		ReadOnly:  false,
	}

	timeoutEnv := corev1.EnvVar{
		Name: "TRIVY_TIMEOUT",
		ValueFrom: &corev1.EnvVarSource{
			ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "trivyoperator-trivy-config",
				},
				Key:      "trivy.timeout",
				Optional: pointer.BoolPtr(true),
			},
		},
	}

	testCases := []struct {
		name string

		config       map[string]string
		workloadSpec client.Object

		expectedSecrets []corev1.Secret
		expectedJobSpec corev1.PodSpec
	}{
		{
			name: "Standalone mode without insecure registry",
			config: map[string]string{
				"trivy.imageRef":                  "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":                      string(trivy.Standalone),
				"trivy.dbRepository":              defaultDBRepository,
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			},
			workloadSpec: &appsv1.ReplicaSet{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ReplicaSet",
					APIVersion: "apps/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx-6799fc88d8",
					Namespace: "prod-ns",
				},
				Spec: appsv1.ReplicaSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "nginx",
									Image: "nginx:1.16",
								},
							},
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     trivyoperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "trivyoperator-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					tmpVolume,
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},

							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.githubToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--cache-dir", "/tmp/trivy/.cache",
							"image",
							"--download-db-only",
							"--db-repository", defaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--cache-dir", "/tmp/trivy/.cache",
							"--quiet",
							"image",
							"--skip-update",
							"--format", "json",
							"nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
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
		{
			name: "Standalone mode with insecure registry",
			config: map[string]string{
				"trivy.imageRef":                     "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":                         string(trivy.Standalone),
				"trivy.insecureRegistry.pocRegistry": "poc.myregistry.harbor.com.pl",
				"trivy.dbRepository":                 defaultDBRepository,

				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "poc.myregistry.harbor.com.pl/nginx:1.16",
						},
					},
				}},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     trivyoperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "trivyoperator-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					tmpVolume,
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.githubToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--cache-dir", "/tmp/trivy/.cache",
							"image",
							"--download-db-only",
							"--db-repository", defaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "TRIVY_INSECURE",
								Value: "true",
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--cache-dir", "/tmp/trivy/.cache",
							"--quiet",
							"image",
							"--skip-update",
							"--format", "json",
							"poc.myregistry.harbor.com.pl/nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
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
		{
			name: "Standalone mode with non-SSL registry",
			config: map[string]string{
				"trivy.imageRef":                   "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":                       string(trivy.Standalone),
				"trivy.nonSslRegistry.pocRegistry": "poc.myregistry.harbor.com.pl",
				"trivy.dbRepository":               defaultDBRepository,
				"trivy.resources.requests.cpu":     "100m",
				"trivy.resources.requests.memory":  "100M",
				"trivy.resources.limits.cpu":       "500m",
				"trivy.resources.limits.memory":    "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "poc.myregistry.harbor.com.pl/nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     trivyoperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "trivyoperator-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					tmpVolume,
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.githubToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--cache-dir", "/tmp/trivy/.cache",
							"image",
							"--download-db-only",
							"--db-repository", defaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "TRIVY_NON_SSL",
								Value: "true",
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--cache-dir", "/tmp/trivy/.cache",
							"--quiet",
							"image",
							"--skip-update",
							"--format", "json",
							"poc.myregistry.harbor.com.pl/nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
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
		{
			name: "Standalone mode with trivyignore file",
			config: map[string]string{
				"trivy.imageRef": "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":     string(trivy.Standalone),
				"trivy.ignoreFile": `# Accept the risk
CVE-2018-14618

# No impact in our settings
CVE-2019-1543`,
				"trivy.dbRepository":              defaultDBRepository,
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     trivyoperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "trivyoperator-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					tmpVolume,
					{
						Name: "ignorefile",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "trivyoperator-trivy-config",
								},
								Items: []corev1.KeyToPath{
									{
										Key:  "trivy.ignoreFile",
										Path: ".trivyignore",
									},
								},
							},
						},
					},
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.githubToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--cache-dir", "/tmp/trivy/.cache",
							"image",
							"--download-db-only",
							"--db-repository", defaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "TRIVY_IGNOREFILE",
								Value: "/etc/trivy/.trivyignore",
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--cache-dir", "/tmp/trivy/.cache",
							"--quiet",
							"image",
							"--skip-update",
							"--format", "json",
							"nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
							{
								Name:      "ignorefile",
								MountPath: "/etc/trivy/.trivyignore",
								SubPath:   ".trivyignore",
							},
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
		{
			name: "Standalone mode with mirror",
			config: map[string]string{
				"trivy.imageRef": "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":     string(trivy.Standalone),

				"trivy.dbRepository":              defaultDBRepository,
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",

				"trivy.registry.mirror.index.docker.io": "mirror.io",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     trivyoperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "trivyoperator-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					tmpVolume,
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},

							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.githubToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--cache-dir", "/tmp/trivy/.cache",
							"image",
							"--download-db-only",
							"--db-repository", defaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--cache-dir", "/tmp/trivy/.cache",
							"--quiet",
							"image",
							"--skip-update",
							"--format", "json",
							"mirror.io/library/nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							tmpVolumeMount,
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
		{
			name: "ClientServer mode without insecure registry",
			config: map[string]string{
				"trivy.imageRef":                  "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":                      string(trivy.ClientServer),
				"trivy.serverURL":                 "http://trivy.trivy:4954",
				"trivy.dbRepository":              defaultDBRepository,
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     trivyoperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "trivyoperator-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.serverTokenHeader",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.serverToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.serverCustomHeaders",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--quiet",
							"client",
							"--format",
							"json",
							"--remote",
							"http://trivy.trivy:4954",
							"nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode without insecure registry",
			config: map[string]string{
				"trivy.imageRef":                  "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":                      string(trivy.ClientServer),
				"trivy.serverURL":                 "http://trivy.trivy:4954",
				"trivy.dbRepository":              defaultDBRepository,
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     trivyoperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "trivyoperator-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.serverTokenHeader",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.serverToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.serverCustomHeaders",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--quiet",
							"client",
							"--format",
							"json",
							"--remote",
							"http://trivy.trivy:4954",
							"nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode with insecure server",
			config: map[string]string{
				"trivy.imageRef":                  "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":                      string(trivy.ClientServer),
				"trivy.serverURL":                 "https://trivy.trivy:4954",
				"trivy.serverInsecure":            "true",
				"trivy.dbRepository":              defaultDBRepository,
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "poc.myregistry.harbor.com.pl/nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     trivyoperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "trivyoperator-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.serverTokenHeader",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.serverToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.serverCustomHeaders",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "TRIVY_INSECURE",
								Value: "true",
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--quiet",
							"client",
							"--format",
							"json",
							"--remote",
							"https://trivy.trivy:4954",
							"poc.myregistry.harbor.com.pl/nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode with non-SSL registry",
			config: map[string]string{
				"trivy.imageRef":                   "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":                       string(trivy.ClientServer),
				"trivy.serverURL":                  "http://trivy.trivy:4954",
				"trivy.nonSslRegistry.pocRegistry": "poc.myregistry.harbor.com.pl",
				"trivy.dbRepository":               defaultDBRepository,
				"trivy.resources.requests.cpu":     "100m",
				"trivy.resources.requests.memory":  "100M",
				"trivy.resources.limits.cpu":       "500m",
				"trivy.resources.limits.memory":    "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "poc.myregistry.harbor.com.pl/nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     trivyoperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "trivyoperator-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.serverTokenHeader",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.serverToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.serverCustomHeaders",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "TRIVY_NON_SSL",
								Value: "true",
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--quiet",
							"client",
							"--format",
							"json",
							"--remote",
							"http://trivy.trivy:4954",
							"poc.myregistry.harbor.com.pl/nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode with trivyignore file",
			config: map[string]string{
				"trivy.imageRef":  "docker.io/aquasec/trivy:0.14.0",
				"trivy.mode":      string(trivy.ClientServer),
				"trivy.serverURL": "http://trivy.trivy:4954",
				"trivy.ignoreFile": `# Accept the risk
CVE-2018-14618

# No impact in our settings
CVE-2019-1543`,
				"trivy.dbRepository":              defaultDBRepository,
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.16",
						},
					},
				},
			},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     trivyoperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "trivyoperator-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					{
						Name: "ignorefile",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "trivyoperator-trivy-config",
								},
								Items: []corev1.KeyToPath{
									{
										Key:  "trivy.ignoreFile",
										Path: ".trivyignore",
									},
								},
							},
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.14.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.serverTokenHeader",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.serverToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.serverCustomHeaders",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name:  "TRIVY_IGNOREFILE",
								Value: "/etc/trivy/.trivyignore",
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--quiet",
							"client",
							"--format",
							"json",
							"--remote",
							"http://trivy.trivy:4954",
							"nginx:1.16",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "ignorefile",
								MountPath: "/etc/trivy/.trivyignore",
								SubPath:   ".trivyignore",
							},
						},
					},
				},
			},
		},
		{
			name: "Trivy fs scan command in Standalone mode",
			config: map[string]string{
				"trivy.imageRef":                  "docker.io/aquasec/trivy:0.25.2",
				"trivy.mode":                      string(trivy.Standalone),
				"trivy.command":                   string(trivy.Filesystem),
				"trivy.dbRepository":              defaultDBRepository,
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
			},
			workloadSpec: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx",
					Namespace: "prod-ns",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.9.1",
						},
					},
					NodeName: "kind-control-pane",
				}},
			expectedJobSpec: corev1.PodSpec{
				Affinity:                     trivyoperator.LinuxNodeAffinity(),
				RestartPolicy:                corev1.RestartPolicyNever,
				ServiceAccountName:           "trivyoperator-sa",
				AutomountServiceAccountToken: pointer.BoolPtr(false),
				Volumes: []corev1.Volume{
					{
						Name: trivy.FsSharedVolumeName,
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{
								Medium: corev1.StorageMediumDefault,
							},
						},
					},
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/aquasec/trivy:0.25.2",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Command: []string{
							"cp",
							"-v",
							"/usr/local/bin/trivy",
							trivy.SharedVolumeLocationOfTrivy,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      trivy.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/trivyoperator",
							},
						},
					},
					{
						Name:                     "00000000-0000-0000-0000-000000000002",
						Image:                    "docker.io/aquasec/trivy:0.25.2",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},

							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.githubToken",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--download-db-only",
							"--cache-dir",
							"/var/trivyoperator/trivy-db",
							"--db-repository", defaultDBRepository,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      trivy.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/trivyoperator",
							},
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "nginx:1.9.1",
						ImagePullPolicy:          corev1.PullNever,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivyoperator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.BoolPtr(true),
									},
								},
							},
						},
						Command: []string{
							trivy.SharedVolumeLocationOfTrivy,
						},
						Args: []string{
							"--skip-update",
							"--cache-dir",
							"/var/trivyoperator/trivy-db",
							"--quiet",
							"fs",
							"--format",
							"json",
							"/",
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("100M"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("500M"),
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      trivy.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/trivyoperator",
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.BoolPtr(false),
							AllowPrivilegeEscalation: pointer.BoolPtr(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.BoolPtr(true),
							RunAsUser:              pointer.Int64(0),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
				NodeName:        "kind-control-pane",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeclient := fake.NewClientBuilder().WithObjects(
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "trivyoperator-trivy-config",
						Namespace: "trivyoperator-ns",
					},
					Data: tc.config,
				},
			).Build()
			pluginContext := trivyoperator.NewPluginContext().
				WithName(trivy.Plugin).
				WithNamespace("trivyoperator-ns").
				WithServiceAccountName("trivyoperator-sa").
				WithClient(fakeclient).
				Get()
			instance := trivy.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), fakeclient)
			jobSpec, secrets, err := instance.GetScanJobSpec(pluginContext, tc.workloadSpec, nil)
			require.NoError(t, err)
			assert.Empty(t, secrets)
			assert.Equal(t, tc.expectedJobSpec, jobSpec)
		})
	}

	testCases = []struct {
		name            string
		config          map[string]string
		workloadSpec    client.Object
		expectedSecrets []corev1.Secret
		expectedJobSpec corev1.PodSpec
	}{{
		name: "Trivy fs scan command in Standalone mode",
		config: map[string]string{
			"trivy.imageRef":                  "docker.io/aquasec/trivy:0.22.0",
			"trivy.mode":                      string(trivy.Standalone),
			"trivy.command":                   string(trivy.Filesystem),
			"trivy.dbRepository":              defaultDBRepository,
			"trivy.resources.requests.cpu":    "100m",
			"trivy.resources.requests.memory": "100M",
			"trivy.resources.limits.cpu":      "500m",
			"trivy.resources.limits.memory":   "500M",
		},
		workloadSpec: &corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx",
				Namespace: "prod-ns",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "nginx",
						Image: "nginx:1.9.1",
					},
				},
				NodeName:           "kind-control-pane",
				ServiceAccountName: "nginx-sa",
			}},
		expectedJobSpec: corev1.PodSpec{
			Affinity:                     trivyoperator.LinuxNodeAffinity(),
			RestartPolicy:                corev1.RestartPolicyNever,
			ServiceAccountName:           "trivyoperator-sa",
			AutomountServiceAccountToken: pointer.BoolPtr(false),
			Volumes: []corev1.Volume{
				{
					Name: trivy.FsSharedVolumeName,
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							Medium: corev1.StorageMediumDefault,
						},
					},
				},
			},
			InitContainers: []corev1.Container{
				{
					Name:                     "00000000-0000-0000-0000-000000000001",
					Image:                    "docker.io/aquasec/trivy:0.22.0",
					ImagePullPolicy:          corev1.PullIfNotPresent,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Command: []string{
						"cp",
						"-v",
						"/usr/local/bin/trivy",
						trivy.SharedVolumeLocationOfTrivy,
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("100m"),
							corev1.ResourceMemory: resource.MustParse("100M"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("500m"),
							corev1.ResourceMemory: resource.MustParse("500M"),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      trivy.FsSharedVolumeName,
							ReadOnly:  false,
							MountPath: "/var/trivyoperator",
						},
					},
				},
				{
					Name:                     "00000000-0000-0000-0000-000000000002",
					Image:                    "docker.io/aquasec/trivy:0.22.0",
					ImagePullPolicy:          corev1.PullIfNotPresent,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Env: []corev1.EnvVar{
						{
							Name: "HTTP_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivyoperator-trivy-config",
									},
									Key:      "trivy.httpProxy",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
						{
							Name: "HTTPS_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivyoperator-trivy-config",
									},
									Key:      "trivy.httpsProxy",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
						{
							Name: "NO_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivyoperator-trivy-config",
									},
									Key:      "trivy.noProxy",
									Optional: pointer.BoolPtr(true),
								},
							},
						},

						{
							Name: "GITHUB_TOKEN",
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivyoperator-trivy-config",
									},
									Key:      "trivy.githubToken",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
					},
					Command: []string{
						"trivy",
					},
					Args: []string{
						"--download-db-only",
						"--cache-dir",
						"/var/trivyoperator/trivy-db",
						"--db-repository", defaultDBRepository,
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("100m"),
							corev1.ResourceMemory: resource.MustParse("100M"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("500m"),
							corev1.ResourceMemory: resource.MustParse("500M"),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      trivy.FsSharedVolumeName,
							ReadOnly:  false,
							MountPath: "/var/trivyoperator",
						},
					},
				},
			},
			Containers: []corev1.Container{
				{
					Name:                     "nginx",
					Image:                    "nginx:1.9.1",
					ImagePullPolicy:          corev1.PullIfNotPresent,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Env: []corev1.EnvVar{
						{
							Name: "TRIVY_SEVERITY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivyoperator-trivy-config",
									},
									Key:      "trivy.severity",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
						{
							Name: "TRIVY_SKIP_FILES",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivyoperator-trivy-config",
									},
									Key:      "trivy.skipFiles",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
						{
							Name: "TRIVY_SKIP_DIRS",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivyoperator-trivy-config",
									},
									Key:      "trivy.skipDirs",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
						{
							Name: "HTTP_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivyoperator-trivy-config",
									},
									Key:      "trivy.httpProxy",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
						{
							Name: "HTTPS_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivyoperator-trivy-config",
									},
									Key:      "trivy.httpsProxy",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
						{
							Name: "NO_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivyoperator-trivy-config",
									},
									Key:      "trivy.noProxy",
									Optional: pointer.BoolPtr(true),
								},
							},
						},
					},
					Command: []string{
						trivy.SharedVolumeLocationOfTrivy,
					},
					Args: []string{
						"--skip-update",
						"--cache-dir",
						"/var/trivyoperator/trivy-db",
						"--quiet",
						"fs",
						"--format",
						"json",
						"/",
					},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("100m"),
							corev1.ResourceMemory: resource.MustParse("100M"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("500m"),
							corev1.ResourceMemory: resource.MustParse("500M"),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      trivy.FsSharedVolumeName,
							ReadOnly:  false,
							MountPath: "/var/trivyoperator",
						},
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged:               pointer.BoolPtr(false),
						AllowPrivilegeEscalation: pointer.BoolPtr(false),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"all"},
						},
						ReadOnlyRootFilesystem: pointer.BoolPtr(true),
						RunAsUser:              pointer.Int64(0),
					},
				},
			},
			SecurityContext: &corev1.PodSecurityContext{},
		},
	}}
	// Test cases when trivyoperator is enabled with option to run job in the namespace of workload
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeclient := fake.NewClientBuilder().WithObjects(
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "trivyoperator-trivy-config",
						Namespace: "trivyoperator-ns",
					},
					Data: tc.config,
				},
			).Build()
			pluginContext := trivyoperator.NewPluginContext().
				WithName(trivy.Plugin).
				WithNamespace("trivyoperator-ns").
				WithServiceAccountName("trivyoperator-sa").
				WithClient(fakeclient).
				WithTrivyOperatorConfig(map[string]string{trivyoperator.KeyVulnerabilityScansInSameNamespace: "true"}).
				Get()
			instance := trivy.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), fakeclient)
			jobSpec, secrets, err := instance.GetScanJobSpec(pluginContext, tc.workloadSpec, nil)
			require.NoError(t, err)
			assert.Empty(t, secrets)
			assert.Equal(t, tc.expectedJobSpec, jobSpec)
		})
	}
}

var (
	sampleReportAsString = `{
		"SchemaVersion": 2,
		"Results":[{
		"Target": "alpine:3.10.2 (alpine 3.10.2)",
		"Type": "alpine",
		"Vulnerabilities": [
			{
				"VulnerabilityID": "CVE-2019-1549",
				"PkgName": "openssl",
				"InstalledVersion": "1.1.1c-r0",
				"FixedVersion": "1.1.1d-r0",
				"Title": "openssl: information disclosure in fork()",
				"Description": "Usually this long long description of CVE-2019-1549",
				"Severity": "MEDIUM",
				"PrimaryURL": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1549",
				"References": [
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1549"
				]
			},
			{
				"VulnerabilityID": "CVE-2019-1547",
				"PkgName": "openssl",
				"InstalledVersion": "1.1.1c-r0",
				"FixedVersion": "1.1.1d-r0",
				"Title": "openssl: side-channel weak encryption vulnerability",
				"Severity": "LOW",
				"PrimaryURL": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1547",
				"References": [
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1547"
				]
			}
		]
	}]}`

	sampleReport = v1alpha1.VulnerabilityReportData{
		UpdateTimestamp: metav1.NewTime(fixedTime),
		Scanner: v1alpha1.Scanner{
			Name:    "Trivy",
			Vendor:  "Aqua Security",
			Version: "0.9.1",
		},
		Registry: v1alpha1.Registry{
			Server: "index.docker.io",
		},
		Artifact: v1alpha1.Artifact{
			Repository: "library/alpine",
			Tag:        "3.10.2",
		},
		Summary: v1alpha1.VulnerabilitySummary{
			CriticalCount: 0,
			MediumCount:   1,
			LowCount:      1,
			NoneCount:     0,
			UnknownCount:  0,
		},
		Vulnerabilities: []v1alpha1.Vulnerability{
			{
				VulnerabilityID:  "CVE-2019-1549",
				Resource:         "openssl",
				InstalledVersion: "1.1.1c-r0",
				FixedVersion:     "1.1.1d-r0",
				Severity:         v1alpha1.SeverityMedium,
				Title:            "openssl: information disclosure in fork()",
				PrimaryLink:      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1549",
				Links:            []string{},
			},
			{
				VulnerabilityID:  "CVE-2019-1547",
				Resource:         "openssl",
				InstalledVersion: "1.1.1c-r0",
				FixedVersion:     "1.1.1d-r0",
				Severity:         v1alpha1.SeverityLow,
				Title:            "openssl: side-channel weak encryption vulnerability",
				PrimaryLink:      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1547",
				Links:            []string{},
			},
		},
	}
)

func TestPlugin_ParseVulnerabilityReportData(t *testing.T) {
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "trivyoperator-trivy-config",
			Namespace: "trivyoperator-ns",
		},
		Data: map[string]string{
			"trivy.imageRef": "aquasec/trivy:0.9.1",
		},
	}

	testCases := []struct {
		name           string
		imageRef       string
		input          string
		expectedError  error
		expectedReport v1alpha1.VulnerabilityReportData
	}{
		{
			name:           "Should convert vulnerability report in JSON format when input is quiet",
			imageRef:       "alpine:3.10.2",
			input:          sampleReportAsString,
			expectedError:  nil,
			expectedReport: sampleReport,
		},
		{
			name:          "Should convert vulnerability report in JSON format when OS is not detected",
			imageRef:      "core.harbor.domain/library/nginx@sha256:d20aa6d1cae56fd17cd458f4807e0de462caf2336f0b70b5eeb69fcaaf30dd9c",
			input:         `null`,
			expectedError: nil,
			expectedReport: v1alpha1.VulnerabilityReportData{
				UpdateTimestamp: metav1.NewTime(fixedTime),
				Scanner: v1alpha1.Scanner{
					Name:    "Trivy",
					Vendor:  "Aqua Security",
					Version: "0.9.1",
				},
				Registry: v1alpha1.Registry{
					Server: "core.harbor.domain",
				},
				Artifact: v1alpha1.Artifact{
					Repository: "library/nginx",
					Digest:     "sha256:d20aa6d1cae56fd17cd458f4807e0de462caf2336f0b70b5eeb69fcaaf30dd9c",
				},
				Summary: v1alpha1.VulnerabilitySummary{
					CriticalCount: 0,
					HighCount:     0,
					MediumCount:   0,
					LowCount:      0,
					NoneCount:     0,
					UnknownCount:  0,
				},
				Vulnerabilities: []v1alpha1.Vulnerability{},
			},
		},
		{
			name:          "Should return error when image reference cannot be parsed",
			imageRef:      ":",
			input:         "null",
			expectedError: errors.New("could not parse reference: :"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithObjects(config).Build()
			ctx := trivyoperator.NewPluginContext().
				WithName("Trivy").
				WithNamespace("trivyoperator-ns").
				WithServiceAccountName("trivyoperator-sa").
				WithClient(fakeClient).
				Get()
			instance := trivy.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), fakeClient)
			report, err := instance.ParseVulnerabilityReportData(ctx, tc.imageRef, io.NopCloser(strings.NewReader(tc.input)))
			switch {
			case tc.expectedError == nil:
				require.NoError(t, err)
				assert.Equal(t, tc.expectedReport, report)
			default:
				assert.EqualError(t, err, tc.expectedError.Error())
			}
		})
	}

}

func TestGetScoreFromCVSS(t *testing.T) {
	testCases := []struct {
		name          string
		cvss          map[string]*trivy.CVSS
		expectedScore *float64
	}{
		{
			name: "Should return vendor score when vendor v3 score exist",
			cvss: map[string]*trivy.CVSS{
				"nvd": {
					V3Score: pointer.Float64Ptr(8.1),
				},
				"redhat": {
					V3Score: pointer.Float64Ptr(8.3),
				},
			},
			expectedScore: pointer.Float64Ptr(8.3),
		},
		{
			name: "Should return nvd score when vendor v3 score is nil",
			cvss: map[string]*trivy.CVSS{
				"nvd": {
					V3Score: pointer.Float64Ptr(8.1),
				},
				"redhat": {
					V3Score: nil,
				},
			},
			expectedScore: pointer.Float64Ptr(8.1),
		},
		{
			name: "Should return nvd score when vendor doesn't exist",
			cvss: map[string]*trivy.CVSS{
				"nvd": {
					V3Score: pointer.Float64Ptr(8.1),
				},
			},
			expectedScore: pointer.Float64Ptr(8.1),
		},
		{
			name: "Should return nil when vendor and nvd both v3 scores are nil",
			cvss: map[string]*trivy.CVSS{
				"nvd": {
					V3Score: nil,
				},
				"redhat": {
					V3Score: nil,
				},
			},
			expectedScore: nil,
		},
		{
			name:          "Should return nil when cvss doesn't exist",
			cvss:          map[string]*trivy.CVSS{},
			expectedScore: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			score := trivy.GetScoreFromCVSS(tc.cvss)
			assert.Equal(t, tc.expectedScore, score)
		})
	}
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
