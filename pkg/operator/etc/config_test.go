package etc_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
)

func TestOperator_GetTargetNamespaces(t *testing.T) {
	testCases := []struct {
		name                     string
		operator                 etc.Config
		expectedTargetNamespaces []string
	}{
		{
			name: "Should return all namespaces",
			operator: etc.Config{
				TargetNamespaces: "",
			},
			expectedTargetNamespaces: []string{},
		},
		{
			name: "Should return single namespace",
			operator: etc.Config{
				TargetNamespaces: "operators",
			},
			expectedTargetNamespaces: []string{"operators"},
		},
		{
			name: "Should return multiple namespaces",
			operator: etc.Config{
				TargetNamespaces: "foo,bar,baz",
			},
			expectedTargetNamespaces: []string{"foo", "bar", "baz"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedTargetNamespaces, tc.operator.GetTargetNamespaces())
		})
	}
}

func TestOperator_ResolveInstallMode(t *testing.T) {
	testCases := []struct {
		name string

		operator            etc.Config
		expectedInstallMode etc.InstallMode
		expectedError       string
	}{
		{
			name: "Should resolve OwnNamespace",
			operator: etc.Config{
				Namespace:        "operators",
				TargetNamespaces: "operators",
			},
			expectedInstallMode: etc.OwnNamespace,
			expectedError:       "",
		},
		{
			name: "Should resolve SingleNamespace",
			operator: etc.Config{
				Namespace:        "operators",
				TargetNamespaces: "foo",
			},
			expectedInstallMode: etc.SingleNamespace,
			expectedError:       "",
		},
		{
			name: "Should resolve MultiNamespace",
			operator: etc.Config{
				Namespace:        "operators",
				TargetNamespaces: "foo,bar,baz",
			},
			expectedInstallMode: etc.MultiNamespace,
			expectedError:       "",
		},
		{
			name: "Should resolve AllNamespaces",
			operator: etc.Config{
				Namespace:        "operators",
				TargetNamespaces: "",
			},
			expectedInstallMode: etc.AllNamespaces,
			expectedError:       "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			installMode, _, _, err := tc.operator.ResolveInstallMode()
			switch tc.expectedError {
			case "":
				require.NoError(t, err)
				assert.Equal(t, tc.expectedInstallMode, installMode)
			default:
				require.EqualError(t, err, tc.expectedError)
			}
		})
	}
}

func TestOperator_GetWebhookBroadcastCustomHeaders(t *testing.T) {
	testCases := []struct {
		name                                  string
		operator                              etc.Config
		expectedWebhookBroadcastCustomHeaders http.Header
	}{
		{
			name: "Should return single custom header",
			operator: etc.Config{
				WebhookBroadcastCustomHeaders: "x-api-key:trivy",
			},
			expectedWebhookBroadcastCustomHeaders: http.Header{"X-Api-Key": {"trivy"}},
		},
		{
			name: "Should return multiple custom headers",
			operator: etc.Config{
				WebhookBroadcastCustomHeaders: "x-api-key:trivy,X-Api-User:trivy-operator,X-API-TOKEN:trivy-token",
			},
			expectedWebhookBroadcastCustomHeaders: http.Header{"X-Api-Key": {"trivy"}, "X-Api-User": {"trivy-operator"}, "X-Api-Token": {"trivy-token"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedWebhookBroadcastCustomHeaders, tc.operator.GetWebhookBroadcastCustomHeaders())
		})
	}
}

func TestOperator_GetTargetWorkloads(t *testing.T) {
	testCases := []struct {
		name                    string
		operator                etc.Config
		expectedTargetWorkloads []string
	}{
		{
			name: "Should return all target workloads",
			operator: etc.Config{
				TargetWorkloads: "Pod,ReplicaSet,ReplicationController,StatefulSet,DaemonSet,CronJob,Job",
			},
			expectedTargetWorkloads: []string{"pod", "replicaset", "replicationcontroller", "statefulset", "daemonset", "cronjob", "job"},
		},
		{
			name: "Should return single workload",
			operator: etc.Config{
				TargetWorkloads: "Pod",
			},
			expectedTargetWorkloads: []string{"pod"},
		},
		{
			name: "Should return multiple workloads",
			operator: etc.Config{
				TargetWorkloads: "Pod,Job,StatefulSet",
			},
			expectedTargetWorkloads: []string{"pod", "job", "statefulset"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedTargetWorkloads, tc.operator.GetTargetWorkloads())
		})
	}
}

func TestOperator_GetPrivateRegistryScanSecretsNames(t *testing.T) {
	testCases := []struct {
		name                     string
		operator                 etc.Config
		expectedNameSpaceSecrets map[string]string
	}{
		{
			name: "Should return namespace with multi secrets",
			operator: etc.Config{
				PrivateRegistryScanSecretsNames: "{\"mynamespace\":\"mySecrets,anotherSecret\"}",
			},
			expectedNameSpaceSecrets: map[string]string{"mynamespace": "mySecrets,anotherSecret"},
		},
		{
			name: "Should return namespace with singlt secrets",
			operator: etc.Config{
				PrivateRegistryScanSecretsNames: "{\"mynamespace\":\"mySecrets\"}",
			},
			expectedNameSpaceSecrets: map[string]string{"mynamespace": "mySecrets"},
		},
		{
			name: "Should return empty map",
			operator: etc.Config{
				PrivateRegistryScanSecretsNames: "{}",
			},
			expectedNameSpaceSecrets: make(map[string]string),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			secrets, err := tc.operator.GetPrivateRegistryScanSecretsNames()
			require.NoError(t, err)
			assert.Equal(t, tc.expectedNameSpaceSecrets, secrets)
		})
	}
}
