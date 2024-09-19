package trivy

import (
	"context"
	"time"

	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"

	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	fixedTime  = time.Now()
	fixedClock = ext.NewFixedClock(fixedTime)
)

func TestConfig_GetImageRef(t *testing.T) {
	testCases := []struct {
		name             string
		configData       Config
		expectedError    string
		expectedImageRef string
	}{
		{
			name:          "Should return error",
			configData:    Config{PluginConfig: trivyoperator.PluginConfig{}},
			expectedError: "property trivy.repository not set",
		},
		{
			name: "Should return error",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"tag": "0.8.0",
				},
			}},
			expectedError: "property trivy.repository not set",
		},
		{
			name: "Should return error",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.repository": "gcr.io/aquasecurity/trivy",
				},
			}},
			expectedError: "property trivy.tag not set",
		},
		{
			name: "Should return image reference from config data",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.repository": "gcr.io/aquasecurity/trivy",
					"trivy.tag":        "0.8.0",
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

func TestConfig_GetAdditionalVulnerabilityReportFields(t *testing.T) {
	testCases := []struct {
		name             string
		configData       Config
		additionalFields vulnerabilityreport.AdditionalFields
	}{
		{
			name:             "no additional fields are set",
			configData:       Config{PluginConfig: trivyoperator.PluginConfig{}},
			additionalFields: vulnerabilityreport.AdditionalFields{},
		},
		{
			name: "all additional fields are set",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.additionalVulnerabilityReportFields": "PackageType,PkgPath,Class,Target,Links,Description,CVSS,SeveritySource,DataSource",
				},
			}},
			additionalFields: vulnerabilityreport.AdditionalFields{Description: true, Links: true, CVSS: true, Class: true, PackageType: true, PkgPath: true, Target: true, SeveritySource: true, DataSource: true},
		},
		{
			name: "some additional fields are set",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.additionalVulnerabilityReportFields": "PackageType,Target,Links,CVSS",
				},
			}},
			additionalFields: vulnerabilityreport.AdditionalFields{Links: true, CVSS: true, PackageType: true, Target: true},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addFields := tc.configData.GetAdditionalVulnerabilityReportFields()
			assert.True(t, addFields.Description == tc.additionalFields.Description)
			assert.True(t, addFields.CVSS == tc.additionalFields.CVSS)
			assert.True(t, addFields.Target == tc.additionalFields.Target)
			assert.True(t, addFields.PackageType == tc.additionalFields.PackageType)
			assert.True(t, addFields.Class == tc.additionalFields.Class)
			assert.True(t, addFields.Links == tc.additionalFields.Links)
			assert.True(t, addFields.SeveritySource == tc.additionalFields.SeveritySource)
			assert.True(t, addFields.DataSource == tc.additionalFields.DataSource)
		})
	}
}

func TestConfig_GetMode(t *testing.T) {
	testCases := []struct {
		name          string
		configData    Config
		expectedError string
		expectedMode  Mode
	}{
		{
			name: "Should return Standalone",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.mode": string(Standalone),
				},
			}},
			expectedMode: Standalone,
		},
		{
			name: "Should return ClientServer",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.mode": string(ClientServer),
				},
			}},
			expectedMode: ClientServer,
		},
		{
			name:         "Should return error when value is not set",
			configData:   Config{PluginConfig: trivyoperator.PluginConfig{}},
			expectedMode: Standalone,
		},
		{
			name: "Should return error when value is not allowed",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.mode": "P2P",
				},
			}},
			expectedMode: Standalone,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mode := tc.configData.GetMode()
			assert.Equal(t, tc.expectedMode, mode)
		})
	}
}

func TestGetSlow(t *testing.T) {
	testCases := []struct {
		name       string
		configData Config
		want       bool
	}{
		{
			name: "slow param set to true",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.slow": "true",
				},
			}},
			want: true,
		},
		{
			name: "slow param set to false",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.slow": "false",
				},
			}},
			want: false,
		},
		{
			name: "slow param set to no valid value",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.slow": "false2",
				},
			}},
			want: true,
		},
		{
			name: "slow param set to no  value",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{},
			}},
			want: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.configData.GetSlow()
			assert.Equal(t, got, tc.want)

		})
	}
}
func TestConfig_GetCommand(t *testing.T) {
	testCases := []struct {
		name            string
		configData      Config
		expectedError   string
		expectedCommand Command
	}{
		{
			name: "Should return image",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.command": "image",
				},
			}},
			expectedCommand: Image,
		},
		{
			name: "Should return image when value is not set",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{},
			}},
			expectedCommand: Image,
		},
		{
			name: "Should return filesystem",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.command": "filesystem",
				},
			}},
			expectedCommand: Filesystem,
		},
		{
			name: "Should return rootfs",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.command": "rootfs",
				},
			}},
			expectedCommand: Rootfs,
		},
		{
			name: "Should return error when value is not allowed",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.command": "ls",
				},
			}},
			expectedCommand: Image,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			command := tc.configData.GetCommand()
			assert.Equal(t, tc.expectedCommand, command)

		})
	}
}

func TestVulnType(t *testing.T) {
	testCases := []struct {
		name       string
		configData Config
		want       string
	}{
		{
			name: "valid vuln type os",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.vulnType": "os",
				},
			}},
			want: "os",
		},
		{
			name: "valid vuln type library",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.vulnType": "library",
				},
			}},
			want: "library",
		},
		{
			name: "empty vuln type",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.vulnType": "",
				},
			}},
			want: "",
		},
		{
			name: "non valid vuln type",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.vulnType": "aaa",
				},
			}},
			want: "",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.configData.GetVulnType()
			assert.Equal(t, got, tc.want)

		})
	}
}

func TestConfig_GetResourceRequirements(t *testing.T) {
	testCases := []struct {
		name                 string
		config               Config
		expectedError        string
		expectedRequirements corev1.ResourceRequirements
	}{
		{
			name: "Should return empty requirements by default",
			config: Config{
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
			config: Config{
				PluginConfig: trivyoperator.PluginConfig{
					Data: map[string]string{
						"trivy.dbRepository":                         DefaultDBRepository,
						"trivy.javaDbRepository":                     DefaultJavaDBRepository,
						"trivy.resources.requests.cpu":               "800m",
						"trivy.resources.requests.memory":            "200Mi",
						"trivy.resources.requests.ephemeral-storage": "500Mi",
						"trivy.resources.limits.cpu":                 "600m",
						"trivy.resources.limits.memory":              "700Mi",
						"trivy.resources.limits.ephemeral-storage":   "1Gi",
					},
				},
			},
			expectedError: "",
			expectedRequirements: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:              resource.MustParse("800m"),
					corev1.ResourceMemory:           resource.MustParse("200Mi"),
					corev1.ResourceEphemeralStorage: resource.MustParse("500Mi"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:              resource.MustParse("600m"),
					corev1.ResourceMemory:           resource.MustParse("700Mi"),
					corev1.ResourceEphemeralStorage: resource.MustParse("1Gi"),
				},
			},
		},
		{
			name: "Should return error if resource is not parseable",
			config: Config{
				PluginConfig: trivyoperator.PluginConfig{
					Data: map[string]string{
						"trivy.resources.requests.cpu": "roughly 100",
					},
				},
			},
			expectedError: "parsing resource definition trivy.resources.requests.cpu: roughly 100 quantities must match the regular expression '^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$'",
		},
		{
			name: "Should return error if memory value is invalid",
			config: Config{
				PluginConfig: trivyoperator.PluginConfig{
					Data: map[string]string{
						"trivy.resources.requests.memory": "100InvalidUnit",
					},
				},
			},
			expectedError: "parsing resource definition trivy.resources.requests.memory: 100InvalidUnit quantities must match the regular expression '^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$'",
		},
		{
			name: "Should return error if parsed memory value does not match original value",
			config: Config{
				PluginConfig: trivyoperator.PluginConfig{
					Data: map[string]string{
						"trivy.resources.requests.memory": "1288490188800m",
					},
				},
			},
			expectedError: "invalid value 1288490188800m for key trivy.resources.requests.memory, should be specified in units like Ki, Mi, Gi, etc",
		},
		{
			name: "Should return error if CPU value is negative",
			config: Config{
				PluginConfig: trivyoperator.PluginConfig{
					Data: map[string]string{
						"trivy.resources.requests.cpu": "-500m",
					},
				},
			},
			expectedError: "CPU value -500m must be a positive number",
		},
		{
			name: "Should return error if memory value is negative",
			config: Config{
				PluginConfig: trivyoperator.PluginConfig{
					Data: map[string]string{
						"trivy.resources.requests.memory": "-200Mi",
					},
				},
			},
			expectedError: "trivy.resources.requests.memory value -200Mi must be a positive number",
		},
		{
			name: "Should return error if ephemeral storage value is negative",
			config: Config{
				PluginConfig: trivyoperator.PluginConfig{
					Data: map[string]string{
						"trivy.resources.requests.ephemeral-storage": "-1Gi",
					},
				},
			},
			expectedError: "trivy.resources.requests.ephemeral-storage value -1Gi must be a positive number",
		},
		{
			name: "Should return error if ephemeral storage value is invalid",
			config: Config{
				PluginConfig: trivyoperator.PluginConfig{
					Data: map[string]string{
						"trivy.resources.requests.ephemeral-storage": "500InvalidUnit",
					},
				},
			},
			expectedError: "parsing resource definition trivy.resources.requests.ephemeral-storage: 500InvalidUnit quantities must match the regular expression '^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$'",
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
		configData     Config
		expectedOutput bool
	}{
		{
			name: "Should return false",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}},
			expectedOutput: false,
		},
		{
			name: "Should return true",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
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
		configData     Config
		expectedOutput bool
	}{
		{
			name: "Should return false",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}},
			expectedOutput: false,
		},
		{
			name: "Should return true",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo":                 "bar",
					"trivy.ignoreUnfixed": "true",
				},
			}},
			expectedOutput: true,
		},
		{
			name: "Should return false when set it as false",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
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

func TestConfig_OfflineScan(t *testing.T) {
	testCases := []struct {
		name           string
		configData     Config
		expectedOutput bool
	}{
		{
			name: "Should return false",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}},
			expectedOutput: false,
		},
		{
			name: "Should return true",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo":               "bar",
					"trivy.offlineScan": "true",
				},
			}},
			expectedOutput: true,
		},
		{
			name: "Should return false when set it as false",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo":               "bar",
					"trivy.offlineScan": "false",
				},
			}},
			expectedOutput: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exists := tc.configData.OfflineScan()
			assert.Equal(t, tc.expectedOutput, exists)
		})
	}
}

func TestConfig_dbRepositoryInsecure(t *testing.T) {
	testCases := []struct {
		name           string
		configData     Config
		expectedOutput bool
	}{
		{
			name: "good value Should return false",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.dbRepositoryInsecure": "false",
				},
			}},
			expectedOutput: false,
		},
		{
			name: "good value Should return true",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.dbRepositoryInsecure": "true",
				},
			}},
			expectedOutput: true,
		},
		{
			name: "bad value Should return false",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.dbRepositoryInsecure": "true1",
				},
			}},
			expectedOutput: false,
		},
		{
			name: "no value Should return false",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{},
			}},
			expectedOutput: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exists := tc.configData.GetDBRepositoryInsecure()
			assert.Equal(t, tc.expectedOutput, exists)
		})
	}
}

func TestConfig_GetInsecureRegistries(t *testing.T) {
	testCases := []struct {
		name           string
		configData     Config
		expectedOutput map[string]bool
	}{
		{
			name: "Should return nil map when there is no key with insecureRegistry. prefix",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}},
			expectedOutput: make(map[string]bool),
		},
		{
			name: "Should return insecure registries in map",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
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
		configData     Config
		expectedOutput map[string]bool
	}{
		{
			name: "Should return nil map when there is no key with nonSslRegistry. prefix",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}},
			expectedOutput: make(map[string]bool),
		},
		{
			name: "Should return insecure registries in map",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
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
		configData     Config
		expectedOutput map[string]string
	}{
		{
			name: "Should return empty map when there is no key with mirrors.registry. prefix",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}},
			expectedOutput: make(map[string]string),
		},
		{
			name: "Should return mirrors in a map",
			configData: Config{PluginConfig: trivyoperator.PluginConfig{
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
		testClient := fake.NewClientBuilder().WithObjects().Build()
		or := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})

		pluginContext := trivyoperator.NewPluginContext().
			WithName(Plugin).
			WithNamespace("trivyoperator-ns").
			WithServiceAccountName("trivyoperator-sa").
			WithClient(testClient).
			Get()
		p := NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &or)
		err := p.Init(pluginContext)
		assert.NoError(t, err)
		var cm corev1.ConfigMap
		err = testClient.Get(context.Background(), types.NamespacedName{
			Namespace: "trivyoperator-ns",
			Name:      "trivy-operator-trivy-config",
		}, &cm)
		require.NoError(t, err)
		assert.Equal(t, corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "trivy-operator-trivy-config",
				Namespace: "trivyoperator-ns",
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "trivyoperator",
				},
				ResourceVersion: "1",
			},
			Data: map[string]string{
				"trivy.repository":                DefaultImageRepository,
				"trivy.tag":                       "0.52.2",
				"trivy.severity":                  DefaultSeverity,
				"trivy.slow":                      "true",
				"trivy.mode":                      string(Standalone),
				"trivy.timeout":                   "5m0s",
				"trivy.dbRepository":              DefaultDBRepository,
				"trivy.javaDbRepository":          DefaultJavaDBRepository,
				"trivy.useBuiltinRegoPolicies":    "true",
				"trivy.supportedConfigAuditKinds": SupportedConfigAuditKinds,
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100Mi",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500Mi",
			},
		}, cm)
	})

	t.Run("Should not overwrite existing config", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithObjects(
			&corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            "trivy-operator-trivy-config",
					Namespace:       "trivyoperator-ns",
					ResourceVersion: "1",
				},
				Data: map[string]string{
					"trivy.repository": "gcr.io/aquasecurity/trivy",
					"trivy.tag":        "0.35.0",
					"trivy.severity":   DefaultSeverity,
					"trivy.mode":       string(Standalone),
				},
			}).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})

		pluginContext := trivyoperator.NewPluginContext().
			WithName(Plugin).
			WithNamespace("trivyoperator-ns").
			WithServiceAccountName("trivyoperator-sa").
			WithClient(testClient).
			Get()

		p := NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &resolver)
		err := p.Init(pluginContext)
		assert.NoError(t, err)
		var cm corev1.ConfigMap
		err = testClient.Get(context.Background(), types.NamespacedName{
			Namespace: "trivyoperator-ns",
			Name:      "trivy-operator-trivy-config",
		}, &cm)
		require.NoError(t, err)
		assert.Equal(t, corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            "trivy-operator-trivy-config",
				Namespace:       "trivyoperator-ns",
				ResourceVersion: "1",
			},
			Data: map[string]string{
				"trivy.repository": "gcr.io/aquasecurity/trivy",
				"trivy.tag":        "0.35.0",
				"trivy.severity":   DefaultSeverity,
				"trivy.mode":       string(Standalone),
			},
		}, cm)
	})
}

func TestPlugin_FindIgnorePolicyKey(t *testing.T) {
	workload := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "name-01234abcd",
			Namespace: "namespace",
		},
	}
	testCases := []struct {
		name        string
		configData  map[string]string
		expectedKey string
	}{
		{
			name: "empty",
			configData: map[string]string{
				"other": "",
			},
			expectedKey: "",
		},
		{
			name: "fallback",
			configData: map[string]string{
				"other":              "",
				"trivy.ignorePolicy": "",
			},
			expectedKey: "trivy.ignorePolicy",
		},
		{
			name: "fallback namespace",
			configData: map[string]string{
				"other":                        "",
				"trivy.ignorePolicy":           "",
				"trivy.ignorePolicy.namespace": "",
			},
			expectedKey: "trivy.ignorePolicy.namespace",
		},
		{
			name: "fallback namespace workload",
			configData: map[string]string{
				"other":                               "",
				"trivy.ignorePolicy":                  "",
				"trivy.ignorePolicy.namespace":        "",
				"trivy.ignorePolicy.namespace.name-.": "",
			},
			expectedKey: "trivy.ignorePolicy.namespace.name-.",
		},
		{
			name: "fallback namespace other-workload",
			configData: map[string]string{
				"other":                        "",
				"trivy.ignorePolicy":           "",
				"trivy.ignorePolicy.namespace": "",
				"trivy.ignorePolicy.namespace.name-other-.": "",
			},
			expectedKey: "trivy.ignorePolicy.namespace",
		},
		{
			name: "fallback other-namespace other-workload",
			configData: map[string]string{
				"other":                              "",
				"trivy.ignorePolicy":                 "",
				"trivy.ignorePolicy.namespace-other": "",
				"trivy.ignorePolicy.namespace-other.name-other-.": "",
			},
			expectedKey: "trivy.ignorePolicy",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := Config{
				trivyoperator.PluginConfig{
					Data: tc.configData,
				},
			}
			assert.Equal(t, tc.expectedKey, config.FindIgnorePolicyKey(workload))
		})
	}
}

func TestPlugin_GetIncludeDevDeps(t *testing.T) {
	testCases := []struct {
		name       string
		configData map[string]string
		want       bool
	}{
		{
			name: "includeDevDeps enabled",
			configData: map[string]string{
				"trivy.includeDevDeps": "true",
			},
			want: true,
		},
		{
			name: "includeDevDeps not set",
			configData: map[string]string{
				"trivy.includeDevDeps": "false",
			},
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := Config{
				trivyoperator.PluginConfig{
					Data: tc.configData,
				},
			}
			got := config.GetIncludeDevDeps()
			assert.Equal(t, got, tc.want)
		})
	}
}

func TestPlugin_GetSbomSources(t *testing.T) {
	testCases := []struct {
		name       string
		configData map[string]string
		want       string
	}{
		{
			name:       "GetSbomSources not set",
			configData: map[string]string{},
			want:       "",
		},
		{
			name: "GetSbomSources with oci and rekor",
			configData: map[string]string{
				"trivy.sbomSources": "oci,rekor",
			},
			want: "oci,rekor",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := Config{
				trivyoperator.PluginConfig{
					Data: tc.configData,
				},
			}
			got := config.GetSbomSources()
			assert.Equal(t, got, tc.want)
		})
	}
}
