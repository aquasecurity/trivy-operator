package trivy_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/plugins/trivy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	bz "github.com/dsnet/compress/bzip2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/batch/v1"
	"k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	pointer "k8s.io/utils/pointer"
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
			expectedError: "property trivy.repository not set",
		},
		{
			name: "Should return error",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.tag": "0.8.0",
				},
			}},
			expectedError: "property trivy.repository not set",
		},
		{
			name: "Should return error",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.repository": "gcr.io/aquasecurity/trivy",
				},
			}},
			expectedError: "property trivy.tag not set",
		},
		{
			name: "Should return image reference from config data",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
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
		configData       trivy.Config
		additionalFields trivy.AdditionalFields
	}{
		{
			name:             "no additional fields are set",
			configData:       trivy.Config{PluginConfig: trivyoperator.PluginConfig{}},
			additionalFields: trivy.AdditionalFields{},
		},
		{
			name: "all additional fields are set",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.additionalVulnerabilityReportFields": "PackageType,Class,Target,Links,Description,CVSS",
				},
			}},
			additionalFields: trivy.AdditionalFields{Description: true, Links: true, CVSS: true, Class: true, PackageType: true, Target: true},
		},
		{
			name: "some additional fields are set",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.additionalVulnerabilityReportFields": "PackageType,Target,Links,CVSS",
				},
			}},
			additionalFields: trivy.AdditionalFields{Links: true, CVSS: true, PackageType: true, Target: true},
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

func TestGetSlow(t *testing.T) {
	testCases := []struct {
		name       string
		configData trivy.Config
		want       bool
	}{
		{
			name: "slow param set to true",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.tag":  "0.35.0",
					"trivy.slow": "true",
				},
			}},
			want: true,
		},
		{
			name: "slow param set to false",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.tag":  "0.35.0",
					"trivy.slow": "false",
				},
			}},
			want: false,
		},
		{
			name: "slow param set to no valid value",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.tag":  "0.35.0",
					"trivy.slow": "false2",
				},
			}},
			want: true,
		},
		{
			name: "slow param set to true and trivy tag is less then 0.35.0",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.slow": "true",
					"trivy.tag":  "0.33.0",
				},
			}},
			want: false,
		},
		{
			name: "slow param set to true and trivy tag is bigger then 0.35.0",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.slow": "true",
					"trivy.tag":  "0.36.0",
				},
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
			expectedError: "invalid value (ls) of trivy.command; allowed values (image, filesystem, rootfs)",
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

func TestConfig_OfflineScan(t *testing.T) {
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
					"foo":               "bar",
					"trivy.offlineScan": "true",
				},
			}},
			expectedOutput: true,
		},
		{
			name: "Should return false when set it as false",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
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
		configData     trivy.Config
		expectedOutput bool
	}{
		{
			name: "good value Should return false",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.dbRepositoryInsecure": "false",
				},
			}},
			expectedOutput: false,
		},
		{
			name: "good value Should return true",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.dbRepositoryInsecure": "true",
				},
			}},
			expectedOutput: true,
		},
		{
			name: "bad value Should return false",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
				Data: map[string]string{
					"trivy.dbRepositoryInsecure": "true1",
				},
			}},
			expectedOutput: false,
		},
		{
			name: "no value Should return false",
			configData: trivy.Config{PluginConfig: trivyoperator.PluginConfig{
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
		testClient := fake.NewClientBuilder().WithObjects().Build()
		or := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		instance := trivy.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &or)

		pluginContext := trivyoperator.NewPluginContext().
			WithName(trivy.Plugin).
			WithNamespace("trivyoperator-ns").
			WithServiceAccountName("trivyoperator-sa").
			WithClient(testClient).
			Get()
		err := instance.Init(pluginContext)
		require.NoError(t, err)

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
				Name:      "trivy-operator-trivy-config",
				Namespace: "trivyoperator-ns",
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "trivyoperator",
				},
				ResourceVersion: "1",
			},
			Data: map[string]string{
				"trivy.repository":                "ghcr.io/aquasecurity/trivy",
				"trivy.tag":                       "0.35.0",
				"trivy.severity":                  "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
				"trivy.slow":                      "true",
				"trivy.mode":                      "Standalone",
				"trivy.timeout":                   "5m0s",
				"trivy.dbRepository":              defaultDBRepository,
				"trivy.useBuiltinRegoPolicies":    "true",
				"trivy.supportedConfigAuditKinds": trivy.SupportedConfigAuditKinds,
				"trivy.resources.requests.cpu":    "100m",
				"trivy.resources.requests.memory": "100M",
				"trivy.resources.limits.cpu":      "500m",
				"trivy.resources.limits.memory":   "500M",
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
					"trivy.severity":   "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
					"trivy.mode":       "Standalone",
				},
			}).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		instance := trivy.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &resolver)

		pluginContext := trivyoperator.NewPluginContext().
			WithName(trivy.Plugin).
			WithNamespace("trivyoperator-ns").
			WithServiceAccountName("trivyoperator-sa").
			WithClient(testClient).
			Get()
		err := instance.Init(pluginContext)
		require.NoError(t, err)

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
				"trivy.severity":   "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
				"trivy.mode":       "Standalone",
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
					Name: "trivy-operator-trivy-config",
				},
				Key:      "trivy.timeout",
				Optional: pointer.Bool(true),
			},
		},
	}

	testCases := []struct {
		name string

		config              map[string]string
		trivyOperatorConfig map[string]string
		workloadSpec        client.Object

		expectedSecrets []corev1.Secret
		expectedJobSpec corev1.PodSpec
	}{
		{
			name: "Standalone mode without insecure registry",
			trivyOperatorConfig: map[string]string{
				trivyoperator.KeyVulnerabilityScannerEnabled:  "true",
				trivyoperator.KeyExposedSecretsScannerEnabled: "true",
				trivyoperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"trivy.repository":                "docker.io/aquasec/trivy",
				"trivy.tag":                       "0.35.0",
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
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: pointer.Bool(false),
				Volumes: []corev1.Volume{
					tmpVolume, getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/aquasec/trivy:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},

							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.githubToken",
										Optional: pointer.Bool(true),
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
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.offlineScan",
										Optional: pointer.Bool(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"trivy image --slow 'nginx:1.16' --security-checks vuln,secret --cache-dir /tmp/trivy/.cache --quiet --skip-update --format json > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
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
							tmpVolumeMount, getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "Standalone mode with insecure registry",
			trivyOperatorConfig: map[string]string{
				trivyoperator.KeyVulnerabilityScannerEnabled:  "false",
				trivyoperator.KeyExposedSecretsScannerEnabled: "true",
				trivyoperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"trivy.repository":                   "docker.io/aquasec/trivy",
				"trivy.tag":                          "0.35.0",
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
				AutomountServiceAccountToken: pointer.Bool(false),
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				Volumes: []corev1.Volume{
					tmpVolume, getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/aquasec/trivy:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.githubToken",
										Optional: pointer.Bool(true),
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
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.offlineScan",
										Optional: pointer.Bool(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name:  "TRIVY_INSECURE",
								Value: "true",
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"trivy image --slow 'poc.myregistry.harbor.com.pl/nginx:1.16' --security-checks secret --cache-dir /tmp/trivy/.cache --quiet --skip-update --format json > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
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
							tmpVolumeMount, getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "Standalone mode with non-SSL registry",
			trivyOperatorConfig: map[string]string{
				trivyoperator.KeyVulnerabilityScannerEnabled:  "true",
				trivyoperator.KeyExposedSecretsScannerEnabled: "false",
				trivyoperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"trivy.repository":                 "docker.io/aquasec/trivy",
				"trivy.tag":                        "0.35.0",
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
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: pointer.Bool(false),
				Volumes: []corev1.Volume{
					tmpVolume, getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/aquasec/trivy:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.githubToken",
										Optional: pointer.Bool(true),
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
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.offlineScan",
										Optional: pointer.Bool(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name:  "TRIVY_NON_SSL",
								Value: "true",
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"trivy image --slow 'poc.myregistry.harbor.com.pl/nginx:1.16' --security-checks vuln --cache-dir /tmp/trivy/.cache --quiet --skip-update --format json > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
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
							tmpVolumeMount, getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "Standalone mode with trivyignore file",
			trivyOperatorConfig: map[string]string{
				trivyoperator.KeyVulnerabilityScannerEnabled:  "true",
				trivyoperator.KeyExposedSecretsScannerEnabled: "true",
				trivyoperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"trivy.repository": "docker.io/aquasec/trivy",
				"trivy.tag":        "0.35.0",
				"trivy.mode":       string(trivy.Standalone),
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
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: pointer.Bool(false),
				Volumes: []corev1.Volume{
					tmpVolume, getScanResultVolume(),
					{
						Name: "ignorefile",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "trivy-operator-trivy-config",
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
						Image:                    "docker.io/aquasec/trivy:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.githubToken",
										Optional: pointer.Bool(true),
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
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.offlineScan",
										Optional: pointer.Bool(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name:  "TRIVY_IGNOREFILE",
								Value: "/etc/trivy/.trivyignore",
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"trivy image --slow 'nginx:1.16' --security-checks vuln,secret --cache-dir /tmp/trivy/.cache --quiet --skip-update --format json > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
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
							tmpVolumeMount, getScanResultVolumeMount(),
							{
								Name:      "ignorefile",
								MountPath: "/etc/trivy/.trivyignore",
								SubPath:   ".trivyignore",
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "Standalone mode with mirror",
			trivyOperatorConfig: map[string]string{
				trivyoperator.KeyVulnerabilityScannerEnabled:  "true",
				trivyoperator.KeyExposedSecretsScannerEnabled: "true",
				trivyoperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"trivy.repository": "docker.io/aquasec/trivy",
				"trivy.tag":        "0.35.0",
				"trivy.mode":       string(trivy.Standalone),

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
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: pointer.Bool(false),
				Volumes: []corev1.Volume{
					tmpVolume, getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/aquasec/trivy:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},

							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.githubToken",
										Optional: pointer.Bool(true),
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
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.offlineScan",
										Optional: pointer.Bool(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"trivy image --slow 'mirror.io/library/nginx:1.16' --security-checks vuln,secret --cache-dir /tmp/trivy/.cache --quiet --skip-update --format json > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
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
							tmpVolumeMount, getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
			},
		},
		{
			name: "ClientServer mode without insecure registry",
			trivyOperatorConfig: map[string]string{
				trivyoperator.KeyVulnerabilityScannerEnabled:  "true",
				trivyoperator.KeyExposedSecretsScannerEnabled: "true",
				trivyoperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"trivy.repository":                "docker.io/aquasec/trivy",
				"trivy.tag":                       "0.35.0",
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
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: pointer.Bool(false),
				Volumes: []corev1.Volume{getTmpVolume(),
					getScanResultVolume(),
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.offlineScan",
										Optional: pointer.Bool(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverTokenHeader",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverToken",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverCustomHeaders",
										Optional: pointer.Bool(true),
									},
								},
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"trivy image --slow 'nginx:1.16' --security-checks vuln,secret --quiet --format json --server 'http://trivy.trivy:4954' > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
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
						VolumeMounts: []corev1.VolumeMount{getTmpVolumeMount(), getScanResultVolumeMount()},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode without insecure registry",
			trivyOperatorConfig: map[string]string{
				trivyoperator.KeyVulnerabilityScannerEnabled:  "true",
				trivyoperator.KeyExposedSecretsScannerEnabled: "true",
				trivyoperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"trivy.repository":                "docker.io/aquasec/trivy",
				"trivy.tag":                       "0.35.0",
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
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				ServiceAccountName:           "trivyoperator-sa",
				AutomountServiceAccountToken: pointer.Bool(false),
				Volumes: []corev1.Volume{getTmpVolume(),
					getScanResultVolume(),
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.offlineScan",
										Optional: pointer.Bool(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverTokenHeader",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverToken",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverCustomHeaders",
										Optional: pointer.Bool(true),
									},
								},
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"trivy image --slow 'nginx:1.16' --security-checks vuln,secret --quiet --format json --server 'http://trivy.trivy:4954' > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
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
						VolumeMounts: []corev1.VolumeMount{getTmpVolumeMount(), getScanResultVolumeMount()},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode with insecure server",
			trivyOperatorConfig: map[string]string{
				trivyoperator.KeyVulnerabilityScannerEnabled:  "true",
				trivyoperator.KeyExposedSecretsScannerEnabled: "true",
				trivyoperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"trivy.repository":                "docker.io/aquasec/trivy",
				"trivy.tag":                       "0.35.0",
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
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: pointer.Bool(false),
				Volumes: []corev1.Volume{getTmpVolume(),
					getScanResultVolume(),
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.offlineScan",
										Optional: pointer.Bool(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverTokenHeader",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverToken",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverCustomHeaders",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name:  "TRIVY_INSECURE",
								Value: "true",
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"trivy image --slow 'poc.myregistry.harbor.com.pl/nginx:1.16' --security-checks vuln,secret --quiet --format json --server 'https://trivy.trivy:4954' > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
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
						VolumeMounts: []corev1.VolumeMount{getTmpVolumeMount(), getScanResultVolumeMount()},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode with non-SSL registry",
			trivyOperatorConfig: map[string]string{
				trivyoperator.KeyVulnerabilityScannerEnabled:  "true",
				trivyoperator.KeyExposedSecretsScannerEnabled: "false",
				trivyoperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"trivy.repository":                 "docker.io/aquasec/trivy",
				"trivy.tag":                        "0.35.0",
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
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: pointer.Bool(false),
				Volumes: []corev1.Volume{getTmpVolume(),
					getScanResultVolume(),
				},
				Containers: []corev1.Container{
					{
						Name:                     "nginx",
						Image:                    "docker.io/aquasec/trivy:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.offlineScan",
										Optional: pointer.Bool(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverTokenHeader",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverToken",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverCustomHeaders",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name:  "TRIVY_NON_SSL",
								Value: "true",
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"trivy image --slow 'poc.myregistry.harbor.com.pl/nginx:1.16' --security-checks vuln --quiet --format json --server 'http://trivy.trivy:4954' > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
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
						VolumeMounts: []corev1.VolumeMount{getTmpVolumeMount(), getScanResultVolumeMount()},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
						},
					},
				},
			},
		},
		{
			name: "ClientServer mode with trivyignore file",
			trivyOperatorConfig: map[string]string{
				trivyoperator.KeyVulnerabilityScannerEnabled:  "false",
				trivyoperator.KeyExposedSecretsScannerEnabled: "true",
				trivyoperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"trivy.repository": "docker.io/aquasec/trivy",
				"trivy.tag":        "0.35.0",
				"trivy.mode":       string(trivy.ClientServer),
				"trivy.serverURL":  "http://trivy.trivy:4954",
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
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: pointer.Bool(false),

				Volumes: []corev1.Volume{getTmpVolume(), getScanResultVolume(),
					{
						Name: "ignorefile",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "trivy-operator-trivy-config",
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
						Image:                    "docker.io/aquasec/trivy:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SEVERITY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_IGNORE_UNFIXED",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.ignoreUnfixed",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_OFFLINE_SCAN",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.offlineScan",
										Optional: pointer.Bool(true),
									},
								},
							},
							timeoutEnv,
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverTokenHeader",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverToken",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverCustomHeaders",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name:  "TRIVY_IGNOREFILE",
								Value: "/etc/trivy/.trivyignore",
							},
						},
						Command: []string{
							"/bin/sh",
						},
						Args: []string{
							"-c",
							"trivy image --slow 'nginx:1.16' --security-checks secret --quiet --format json --server 'http://trivy.trivy:4954' > /tmp/scan/result_nginx.json &&  bzip2 -c /tmp/scan/result_nginx.json | base64",
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
						VolumeMounts: []corev1.VolumeMount{getTmpVolumeMount(), getScanResultVolumeMount(),
							{
								Name:      "ignorefile",
								MountPath: "/etc/trivy/.trivyignore",
								SubPath:   ".trivyignore",
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
						},
					},
				},
			},
		},
		{
			name: "Trivy fs scan command in Standalone mode",
			trivyOperatorConfig: map[string]string{
				trivyoperator.KeyVulnerabilityScannerEnabled:  "true",
				trivyoperator.KeyExposedSecretsScannerEnabled: "true",
				trivyoperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"trivy.repository":                "docker.io/aquasec/trivy",
				"trivy.tag":                       "0.35.0",
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
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: pointer.Bool(false),
				Volumes: []corev1.Volume{
					{
						Name: trivy.FsSharedVolumeName,
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{
								Medium: corev1.StorageMediumDefault,
							},
						},
					},
					{
						Name: "tmp",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{
								Medium: corev1.StorageMediumDefault,
							},
						},
					},
					getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/aquasec/trivy:0.35.0",
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
							{
								Name:      "tmp",
								MountPath: "/tmp",
								ReadOnly:  false,
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
						},
					},
					{
						Name:                     "00000000-0000-0000-0000-000000000002",
						Image:                    "docker.io/aquasec/trivy:0.35.0",
						ImagePullPolicy:          corev1.PullIfNotPresent,
						TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
						Env: []corev1.EnvVar{
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},

							{
								Name: "GITHUB_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.githubToken",
										Optional: pointer.Bool(true),
									},
								},
							},
						},
						Command: []string{
							"trivy",
						},
						Args: []string{
							"--cache-dir",
							"/var/trivyoperator/trivy-db",
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
							{
								Name:      trivy.FsSharedVolumeName,
								ReadOnly:  false,
								MountPath: "/var/trivyoperator",
							},
							{
								Name:      "tmp",
								MountPath: "/tmp",
								ReadOnly:  false,
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
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
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
						},
						Command: []string{
							trivy.SharedVolumeLocationOfTrivy,
						},
						Args: []string{
							"--cache-dir",
							"/var/trivyoperator/trivy-db",
							"--quiet",
							"fs",
							"--security-checks",
							"vuln,secret",
							"--skip-update",
							"--format",
							"json",
							"/",
							"--slow",
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
							{
								Name:      "tmp",
								MountPath: "/tmp",
								ReadOnly:  false,
							},
							getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
						},
					},
				},
				SecurityContext: &corev1.PodSecurityContext{},
				NodeName:        "kind-control-pane",
			},
		},
		{
			name: "Trivy fs scan command in ClientServer mode",
			trivyOperatorConfig: map[string]string{
				trivyoperator.KeyVulnerabilityScannerEnabled:  "true",
				trivyoperator.KeyExposedSecretsScannerEnabled: "true",
				trivyoperator.KeyScanJobcompressLogs:          "true",
			},
			config: map[string]string{
				"trivy.repository":                "docker.io/aquasec/trivy",
				"trivy.tag":                       "0.35.0",
				"trivy.mode":                      string(trivy.ClientServer),
				"trivy.serverURL":                 "http://trivy.trivy:4954",
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
				ImagePullSecrets:             []corev1.LocalObjectReference{},
				AutomountServiceAccountToken: pointer.Bool(false),
				Volumes: []corev1.Volume{
					{
						Name: trivy.FsSharedVolumeName,
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{
								Medium: corev1.StorageMediumDefault,
							},
						},
					},
					{
						Name: "tmp",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{
								Medium: corev1.StorageMediumDefault,
							},
						},
					},
					getScanResultVolume(),
				},
				InitContainers: []corev1.Container{
					{
						Name:                     "00000000-0000-0000-0000-000000000001",
						Image:                    "docker.io/aquasec/trivy:0.35.0",
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
							{
								Name:      "tmp",
								MountPath: "/tmp",
								ReadOnly:  false,
							},
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
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
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.severity",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_FILES",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipFiles",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_SKIP_DIRS",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.skipDirs",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTP_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "HTTPS_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.httpsProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "NO_PROXY",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.noProxy",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN_HEADER",
								ValueFrom: &corev1.EnvVarSource{
									ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverTokenHeader",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_TOKEN",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverToken",
										Optional: pointer.Bool(true),
									},
								},
							},
							{
								Name: "TRIVY_CUSTOM_HEADERS",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-trivy-config",
										},
										Key:      "trivy.serverCustomHeaders",
										Optional: pointer.Bool(true),
									},
								},
							},
						},
						Command: []string{
							trivy.SharedVolumeLocationOfTrivy,
						},
						Args: []string{
							"--cache-dir",
							"/var/trivyoperator/trivy-db",
							"--quiet",
							"fs",
							"--security-checks",
							"vuln,secret",
							"--skip-update",
							"--format",
							"json",
							"/",
							"--server",
							"http://trivy.trivy:4954",
							"--slow",
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
							{
								Name:      "tmp",
								MountPath: "/tmp",
								ReadOnly:  false,
							},
							getScanResultVolumeMount(),
						},
						SecurityContext: &corev1.SecurityContext{
							Privileged:               pointer.Bool(false),
							AllowPrivilegeEscalation: pointer.Bool(false),
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"all"},
							},
							ReadOnlyRootFilesystem: pointer.Bool(true),
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
						Name:      "trivy-operator-trivy-config",
						Namespace: "trivyoperator-ns",
					},
					Data: tc.config,
				}, &v1.CronJob{}).Build()
			pluginContext := trivyoperator.NewPluginContext().
				WithName(trivy.Plugin).
				WithNamespace("trivyoperator-ns").
				WithServiceAccountName("trivyoperator-sa").
				WithTrivyOperatorConfig(tc.trivyOperatorConfig).
				WithClient(fakeclient).
				Get()
			resolver := kube.NewObjectResolver(fakeclient, &kube.CompatibleObjectMapper{})
			instance := trivy.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &resolver)
			securityContext := &corev1.SecurityContext{
				Privileged:               pointer.Bool(false),
				AllowPrivilegeEscalation: pointer.Bool(false),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"all"},
				},
				ReadOnlyRootFilesystem: pointer.Bool(true),
			}
			jobSpec, secrets, err := instance.GetScanJobSpec(pluginContext, tc.workloadSpec, nil, securityContext)
			require.NoError(t, err)
			assert.Empty(t, secrets)
			assert.Equal(t, tc.expectedJobSpec, jobSpec)
		})
	}

	testCases = []struct {
		name                string
		config              map[string]string
		trivyOperatorConfig map[string]string
		workloadSpec        client.Object
		expectedSecrets     []corev1.Secret
		expectedJobSpec     corev1.PodSpec
	}{{
		name: "Trivy fs scan command in Standalone mode",
		trivyOperatorConfig: map[string]string{
			trivyoperator.KeyVulnerabilityScannerEnabled:       "true",
			trivyoperator.KeyExposedSecretsScannerEnabled:      "true",
			trivyoperator.KeyVulnerabilityScansInSameNamespace: "true",
		},
		config: map[string]string{
			"trivy.repository":                "docker.io/aquasec/trivy",
			"trivy.tag":                       "0.35.0",
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
			ImagePullSecrets:             []corev1.LocalObjectReference{},
			AutomountServiceAccountToken: pointer.Bool(false),
			Volumes: []corev1.Volume{
				{
					Name: trivy.FsSharedVolumeName,
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							Medium: corev1.StorageMediumDefault,
						},
					},
				},
				{
					Name: "tmp",
					VolumeSource: corev1.VolumeSource{
						EmptyDir: &corev1.EmptyDirVolumeSource{
							Medium: corev1.StorageMediumDefault,
						},
					},
				},
				getScanResultVolume(),
			},
			InitContainers: []corev1.Container{
				{
					Name:                     "00000000-0000-0000-0000-000000000001",
					Image:                    "docker.io/aquasec/trivy:0.35.0",
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
						{
							Name:      "tmp",
							MountPath: "/tmp",
							ReadOnly:  false,
						},
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged:               pointer.Bool(false),
						AllowPrivilegeEscalation: pointer.Bool(false),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"all"},
						},
						ReadOnlyRootFilesystem: pointer.Bool(true),
						RunAsUser:              pointer.Int64(0),
					},
				},
				{
					Name:                     "00000000-0000-0000-0000-000000000002",
					Image:                    "docker.io/aquasec/trivy:0.35.0",
					ImagePullPolicy:          corev1.PullIfNotPresent,
					TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
					Env: []corev1.EnvVar{
						{
							Name: "HTTP_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivy-operator-trivy-config",
									},
									Key:      "trivy.httpProxy",
									Optional: pointer.Bool(true),
								},
							},
						},
						{
							Name: "HTTPS_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivy-operator-trivy-config",
									},
									Key:      "trivy.httpsProxy",
									Optional: pointer.Bool(true),
								},
							},
						},
						{
							Name: "NO_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivy-operator-trivy-config",
									},
									Key:      "trivy.noProxy",
									Optional: pointer.Bool(true),
								},
							},
						},
						{
							Name: "GITHUB_TOKEN",
							ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivy-operator-trivy-config",
									},
									Key:      "trivy.githubToken",
									Optional: pointer.Bool(true),
								},
							},
						},
					},
					Command: []string{
						"trivy",
					},
					Args: []string{
						"--cache-dir",
						"/var/trivyoperator/trivy-db",
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
						{
							Name:      trivy.FsSharedVolumeName,
							ReadOnly:  false,
							MountPath: "/var/trivyoperator",
						},
						{
							Name:      "tmp",
							MountPath: "/tmp",
							ReadOnly:  false,
						},
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged:               pointer.Bool(false),
						AllowPrivilegeEscalation: pointer.Bool(false),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"all"},
						},
						ReadOnlyRootFilesystem: pointer.Bool(true),
						RunAsUser:              pointer.Int64(0),
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
										Name: "trivy-operator-trivy-config",
									},
									Key:      "trivy.severity",
									Optional: pointer.Bool(true),
								},
							},
						},
						{
							Name: "TRIVY_SKIP_FILES",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivy-operator-trivy-config",
									},
									Key:      "trivy.skipFiles",
									Optional: pointer.Bool(true),
								},
							},
						},
						{
							Name: "TRIVY_SKIP_DIRS",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivy-operator-trivy-config",
									},
									Key:      "trivy.skipDirs",
									Optional: pointer.Bool(true),
								},
							},
						},
						{
							Name: "HTTP_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivy-operator-trivy-config",
									},
									Key:      "trivy.httpProxy",
									Optional: pointer.Bool(true),
								},
							},
						},
						{
							Name: "HTTPS_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivy-operator-trivy-config",
									},
									Key:      "trivy.httpsProxy",
									Optional: pointer.Bool(true),
								},
							},
						},
						{
							Name: "NO_PROXY",
							ValueFrom: &corev1.EnvVarSource{
								ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "trivy-operator-trivy-config",
									},
									Key:      "trivy.noProxy",
									Optional: pointer.Bool(true),
								},
							},
						},
					},
					Command: []string{
						trivy.SharedVolumeLocationOfTrivy,
					},
					Args: []string{
						"--cache-dir",
						"/var/trivyoperator/trivy-db",
						"--quiet",
						"fs",
						"--security-checks",
						"vuln,secret",
						"--skip-update",
						"--format",
						"json",
						"/",
						"--slow",
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
						{
							Name:      "tmp",
							MountPath: "/tmp",
							ReadOnly:  false,
						},
						getScanResultVolumeMount(),
					},
					SecurityContext: &corev1.SecurityContext{
						Privileged:               pointer.Bool(false),
						AllowPrivilegeEscalation: pointer.Bool(false),
						Capabilities: &corev1.Capabilities{
							Drop: []corev1.Capability{"all"},
						},
						ReadOnlyRootFilesystem: pointer.Bool(true),
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
						Name:      "trivy-operator-trivy-config",
						Namespace: "trivyoperator-ns",
					},
					Data: tc.config,
				}, &v1beta1.CronJob{}).Build()
			pluginContext := trivyoperator.NewPluginContext().
				WithName(trivy.Plugin).
				WithNamespace("trivyoperator-ns").
				WithServiceAccountName("trivyoperator-sa").
				WithClient(fakeclient).
				WithTrivyOperatorConfig(tc.trivyOperatorConfig).
				Get()
			resolver := kube.NewObjectResolver(fakeclient, &kube.CompatibleObjectMapper{})
			instance := trivy.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &resolver)
			securityContext := &corev1.SecurityContext{
				Privileged:               pointer.Bool(false),
				AllowPrivilegeEscalation: pointer.Bool(false),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"all"},
				},
				ReadOnlyRootFilesystem: pointer.Bool(true),
				// Root expected for standalone mode - the user would need to know this
				RunAsUser: pointer.Int64(0),
			}
			jobSpec, secrets, err := instance.GetScanJobSpec(pluginContext, tc.workloadSpec, nil, securityContext)
			require.NoError(t, err)
			assert.Empty(t, secrets)
			assert.Equal(t, tc.expectedJobSpec, jobSpec)
		})
	}
}

var (
	sampleVulnerabilityReport = v1alpha1.VulnerabilityReportData{
		UpdateTimestamp: metav1.NewTime(fixedTime),
		Scanner: v1alpha1.Scanner{
			Name:    v1alpha1.ScannerNameTrivy,
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

	sampleExposedSecretReport = v1alpha1.ExposedSecretReportData{
		UpdateTimestamp: metav1.NewTime(fixedTime),
		Scanner: v1alpha1.Scanner{
			Name:    v1alpha1.ScannerNameTrivy,
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
		Summary: v1alpha1.ExposedSecretSummary{
			CriticalCount: 1,
			HighCount:     1,
			MediumCount:   0,
			LowCount:      0,
		},
		Secrets: []v1alpha1.ExposedSecret{
			{
				RuleID:   "stripe-access-token",
				Category: "Stripe",
				Severity: "HIGH",
				Title:    "Stripe",
				Match:    "publishable_key: *****",
			},
			{
				RuleID:   "stripe-access-token",
				Category: "Stripe",
				Severity: "CRITICAL",
				Title:    "Stripe",
				Match:    "secret_key: *****",
			},
		},
	}

	emptyVulnerabilityReport = v1alpha1.VulnerabilityReportData{
		UpdateTimestamp: metav1.NewTime(fixedTime),
		Scanner: v1alpha1.Scanner{
			Name:    v1alpha1.ScannerNameTrivy,
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
			HighCount:     0,
			MediumCount:   0,
			LowCount:      0,
			NoneCount:     0,
			UnknownCount:  0,
		},
		Vulnerabilities: []v1alpha1.Vulnerability{},
	}

	emptyExposedSecretReport = v1alpha1.ExposedSecretReportData{
		UpdateTimestamp: metav1.NewTime(fixedTime),
		Scanner: v1alpha1.Scanner{
			Name:    v1alpha1.ScannerNameTrivy,
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
		Summary: v1alpha1.ExposedSecretSummary{
			CriticalCount: 0,
			HighCount:     0,
			MediumCount:   0,
			LowCount:      0,
		},
		Secrets: []v1alpha1.ExposedSecret{},
	}
)

func TestPlugin_ParseReportData(t *testing.T) {
	config := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "trivy-operator-trivy-config",
			Namespace: "trivyoperator-ns",
		},
		Data: map[string]string{
			"trivy.repository": "aquasec/trivy",
			"trivy.tag":        "0.9.1",
		},
	}

	testCases := []struct {
		name                        string
		imageRef                    string
		input                       string
		expectedError               error
		expectedVulnerabilityReport v1alpha1.VulnerabilityReportData
		expectedExposedSecretReport v1alpha1.ExposedSecretReportData
		compressed                  string
	}{
		{
			name:                        "Should convert both vulnerability and exposedsecret report in JSON format when input is quiet",
			imageRef:                    "alpine:3.10.2",
			input:                       getReportAsString("full_report.json"),
			expectedError:               nil,
			expectedVulnerabilityReport: sampleVulnerabilityReport,
			expectedExposedSecretReport: sampleExposedSecretReport,
			compressed:                  "true",
		},
		{
			name:                        "Should convert both vulnerability and exposedsecret report in JSON format when input is quiet",
			imageRef:                    "alpine:3.10.2",
			input:                       getReportAsStringnonCompressed("full_report.json"),
			expectedError:               nil,
			expectedVulnerabilityReport: sampleVulnerabilityReport,
			expectedExposedSecretReport: sampleExposedSecretReport,
			compressed:                  "false",
		},
		{
			name:                        "Should convert vulnerability report in JSON format when OS is not detected",
			imageRef:                    "alpine:3.10.2",
			input:                       `null`,
			expectedError:               fmt.Errorf("bzip2 data invalid: bad magic value"),
			expectedVulnerabilityReport: emptyVulnerabilityReport,
			expectedExposedSecretReport: emptyExposedSecretReport,
			compressed:                  "true",
		},
		{
			name:                        "Should only parse vulnerability report",
			imageRef:                    "alpine:3.10.2",
			input:                       getReportAsString("vulnerability_report.json"),
			expectedError:               nil,
			expectedVulnerabilityReport: sampleVulnerabilityReport,
			expectedExposedSecretReport: emptyExposedSecretReport,
			compressed:                  "true",
		},
		{
			name:                        "Should only parse exposedsecret report",
			imageRef:                    "alpine:3.10.2",
			input:                       getReportAsString("exposedsecret_report.json"),
			expectedError:               nil,
			expectedVulnerabilityReport: emptyVulnerabilityReport,
			expectedExposedSecretReport: sampleExposedSecretReport,
			compressed:                  "true",
		},
		{
			name:          "Should return error when image reference cannot be parsed",
			imageRef:      ":",
			input:         "null",
			expectedError: errors.New("could not parse reference: :"),
			compressed:    "false",
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
				WithTrivyOperatorConfig(map[string]string{"scanJob.compressLogs": tc.compressed}).
				Get()

			resolver := kube.NewObjectResolver(fakeClient, &kube.CompatibleObjectMapper{})
			instance := trivy.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &resolver)
			vulnReport, secretReport, err := instance.ParseReportData(ctx, tc.imageRef, io.NopCloser(strings.NewReader(tc.input)))
			switch {
			case tc.expectedError == nil:
				require.NoError(t, err)
				assert.Equal(t, tc.expectedVulnerabilityReport, vulnReport)
				assert.Equal(t, tc.expectedExposedSecretReport, secretReport)
			default:
				assert.EqualError(t, err, tc.expectedError.Error())
			}
		})
	}

}

func TestGetScoreFromCVSS(t *testing.T) {
	testCases := []struct {
		name          string
		cvss          dbtypes.VendorCVSS
		expectedScore *float64
	}{
		{
			name: "Should return vendor score when vendor v3 score exist",
			cvss: dbtypes.VendorCVSS{
				"nvd": {
					V3Score: 8.1,
				},
				"redhat": {
					V3Score: 8.3,
				},
			},
			expectedScore: pointer.Float64(8.3),
		},
		{
			name: "Should return nvd score when vendor v3 score is nil",
			cvss: dbtypes.VendorCVSS{
				"nvd": {
					V3Score: 8.1,
				},
				"redhat": {
					V3Score: 0.0,
				},
			},
			expectedScore: pointer.Float64(8.1),
		},
		{
			name: "Should return nvd score when vendor doesn't exist",
			cvss: dbtypes.VendorCVSS{
				"nvd": {
					V3Score: 8.1,
				},
			},
			expectedScore: pointer.Float64(8.1),
		},
		{
			name: "Should return nil when vendor and nvd both v3 scores are nil",
			cvss: dbtypes.VendorCVSS{
				"nvd": {
					V3Score: 0.0,
				},
				"redhat": {
					V3Score: 0.0,
				},
			},
			expectedScore: nil,
		},
		{
			name:          "Should return nil when cvss doesn't exist",
			cvss:          dbtypes.VendorCVSS{},
			expectedScore: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			score := trivy.GetScoreFromCVSS(trivy.GetCvssV3(tc.cvss))
			assert.Equal(t, tc.expectedScore, score)
		})
	}
}

func TestGetCVSSV3(t *testing.T) {
	testCases := []struct {
		name     string
		cvss     dbtypes.VendorCVSS
		expected map[string]*trivy.CVSS
	}{
		{
			name: "Should return vendor score when vendor v3 score exist",
			cvss: dbtypes.VendorCVSS{
				"nvd": {
					V3Score: 8.1,
				},
				"redhat": {
					V3Score: 8.3,
				},
			},
			expected: map[string]*trivy.CVSS{
				"nvd":    {V3Score: pointer.Float64(8.1)},
				"redhat": {V3Score: pointer.Float64(8.3)},
			},
		},
		{
			name: "Should return nil when vendor and nvd both v3 scores are nil",
			cvss: dbtypes.VendorCVSS{
				"nvd": {
					V3Score: 0.0,
				},
				"redhat": {
					V3Score: 0.0,
				},
			},
			expected: map[string]*trivy.CVSS{
				"nvd":    {V3Score: nil},
				"redhat": {V3Score: nil},
			},
		},
		{
			name:     "Should return nil when cvss doesn't exist",
			cvss:     dbtypes.VendorCVSS{},
			expected: map[string]*trivy.CVSS{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			score := trivy.GetCvssV3(tc.cvss)
			assert.True(t, reflect.DeepEqual(tc.expected, score))
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

func TestGetContainers(t *testing.T) {
	workloadSpec := &appsv1.ReplicaSet{
		Spec: appsv1.ReplicaSetSpec{
			Template: corev1.PodTemplateSpec{

				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{Name: "init1", Image: "busybox:1.34.1"},
						{Name: "init2", Image: "busybox:1.34.1"},
					},
					Containers: []corev1.Container{
						{Name: "container1", Image: "busybox:1.34.1"},
						{Name: "container2", Image: "busybox:1.34.1"},
					},
					EphemeralContainers: []corev1.EphemeralContainer{
						{
							EphemeralContainerCommon: corev1.EphemeralContainerCommon{
								Name: "ephemeral1", Image: "busybox:1.34.1",
							},
						},
						{
							EphemeralContainerCommon: corev1.EphemeralContainerCommon{
								Name: "ephemeral2", Image: "busybox:1.34.1",
							},
						},
					},
				},
			},
		},
	}

	testCases := []struct {
		name       string
		configData map[string]string
	}{
		{
			name: "Standalone mode with image command",
			configData: map[string]string{
				"trivy.dbRepository": defaultDBRepository,
				"trivy.repository":   "gcr.io/aquasec/trivy",
				"trivy.tag":          "0.35.0",
				"trivy.mode":         string(trivy.Standalone),
				"trivy.command":      string(trivy.Image),
			},
		},
		{
			name: "ClientServer mode with image command",
			configData: map[string]string{
				"trivy.serverURL":    "http://trivy.trivy:4954",
				"trivy.dbRepository": defaultDBRepository,
				"trivy.repository":   "gcr.io/aquasec/trivy",
				"trivy.tag":          "0.35.0",
				"trivy.mode":         string(trivy.ClientServer),
				"trivy.command":      string(trivy.Image),
			},
		},
		{
			name: "Standalone mode with filesystem command",
			configData: map[string]string{
				"trivy.serverURL":    "http://trivy.trivy:4954",
				"trivy.dbRepository": defaultDBRepository,
				"trivy.repository":   "docker.io/aquasec/trivy",
				"trivy.tag":          "0.35.0",
				"trivy.mode":         string(trivy.Standalone),
				"trivy.command":      string(trivy.Filesystem),
			},
		},
	}

	expectedContainers := []string{
		"container1",
		"container2",
		"ephemeral1",
		"ephemeral2",
		"init1",
		"init2",
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeclient := fake.NewClientBuilder().WithObjects(
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "trivy-operator-trivy-config",
						Namespace: "trivyoperator-ns",
					},
					Data: tc.configData,
				},
			).Build()

			pluginContext := trivyoperator.NewPluginContext().
				WithName(trivy.Plugin).
				WithNamespace("trivyoperator-ns").
				WithServiceAccountName("trivyoperator-sa").
				WithClient(fakeclient).
				WithTrivyOperatorConfig(map[string]string{trivyoperator.KeyVulnerabilityScansInSameNamespace: "true"}).
				Get()
			resolver := kube.NewObjectResolver(fakeclient, &kube.CompatibleObjectMapper{})
			instance := trivy.NewPlugin(fixedClock, ext.NewSimpleIDGenerator(), &resolver)
			jobSpec, _, err := instance.GetScanJobSpec(pluginContext, workloadSpec, nil, nil)
			assert.NoError(t, err)

			containers := make([]string, 0)

			for _, c := range jobSpec.Containers {
				containers = append(containers, c.Name)
			}

			sort.Strings(containers)

			assert.Equal(t, expectedContainers, containers)
		})
	}
}

func getReportAsString(fixture string) string {
	f, err := os.Open("./testdata/fixture/" + fixture)
	if err != nil {
		log.Fatal(err)
	}

	b, err := io.ReadAll(f)
	if err != nil {
		log.Fatal(err)
	}
	value, err := writeBzip2AndEncode(b)
	if err != nil {
		log.Fatal(err)
	}
	return value
}
func getReportAsStringnonCompressed(fixture string) string {
	f, err := os.Open("./testdata/fixture/" + fixture)
	if err != nil {
		log.Fatal(err)
	}

	b, err := io.ReadAll(f)
	if err != nil {
		log.Fatal(err)
	}
	return string(b)
}

func getScanResultVolume() corev1.Volume {
	return corev1.Volume{
		Name: "scanresult",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumDefault,
			},
		},
	}
}
func getTmpVolume() corev1.Volume {
	return corev1.Volume{
		Name: "tmp",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumDefault,
			},
		},
	}
}

func getScanResultVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      "scanresult",
		ReadOnly:  false,
		MountPath: "/tmp/scan",
	}
}

func getTmpVolumeMount() corev1.VolumeMount {
	return corev1.VolumeMount{
		Name:      "tmp",
		ReadOnly:  false,
		MountPath: "/tmp",
	}
}

func writeBzip2AndEncode(data []byte) (string, error) {
	var in bytes.Buffer
	w, err := bz.NewWriter(&in, &bz.WriterConfig{})
	if err != nil {
		return "", err
	}
	_, err = w.Write(data)
	if err != nil {
		return "", err
	}
	err = w.Close()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(in.Bytes()), nil
}
