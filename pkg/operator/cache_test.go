package operator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

func configMapWithSecretData(name string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Data: map[string]string{
			"password":               "SuperSecret123",
			"application.properties": "username=admin\npassword=SuperSecret123\nnormal_setting=true\n",
		},
		BinaryData: map[string][]byte{
			"keystore.jks": []byte("binary-secret"),
		},
	}
}

// TestCacheTransform_KeepsStrippingConfigMapData guards the memory optimization:
// the fix for the config-audit regression must not start caching ConfigMap
// contents cluster-wide. Config-audit instead re-reads the contents of the
// ConfigMaps it scans from the API server - see
// (*configauditreport/controller.ResourceController).restoreConfigMapData, and
// the envtest regression spec in tests/envtest.
func TestCacheTransform_KeepsStrippingConfigMapData(t *testing.T) {
	tests := []struct {
		name      string
		configMap string
		wantData  bool
	}{
		{
			name:      "ordinary ConfigMap contents are dropped",
			configMap: "kap-configmap-secret-test",
			wantData:  false,
		},
		{
			name:      "policies ConfigMap keeps its contents",
			configMap: trivyoperator.PoliciesConfigMapName,
			wantData:  true,
		},
		{
			name:      "trivy config ConfigMap keeps its contents",
			configMap: trivyoperator.TrivyConfigMapName,
			wantData:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := CacheTransform()(configMapWithSecretData(tc.configMap))
			require.NoError(t, err)

			got, ok := out.(*corev1.ConfigMap)
			require.True(t, ok)

			if tc.wantData {
				assert.Equal(t, "SuperSecret123", got.Data["password"])
				assert.Equal(t, []byte("binary-secret"), got.BinaryData["keystore.jks"])
			} else {
				assert.Nil(t, got.Data)
				assert.Nil(t, got.BinaryData)
			}

			// Identity is never stripped; the config-audit report is keyed on it.
			assert.Equal(t, tc.configMap, got.Name)
			assert.Equal(t, "default", got.Namespace)
		})
	}
}

func TestCacheTransform_StripsManagedFieldsAndLastAppliedConfiguration(t *testing.T) {
	cm := configMapWithSecretData(trivyoperator.TrivyConfigMapName)
	cm.ManagedFields = []metav1.ManagedFieldsEntry{
		{Manager: "kubectl", Operation: metav1.ManagedFieldsOperationApply},
	}
	cm.Annotations = map[string]string{
		lastAppliedConfigurationAnnotation: "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\"}",
		"keep-me":                          "yes",
	}

	out, err := CacheTransform()(cm)
	require.NoError(t, err)

	got := out.(*corev1.ConfigMap)
	assert.Empty(t, got.ManagedFields)
	assert.NotContains(t, got.Annotations, lastAppliedConfigurationAnnotation)
	assert.Equal(t, "yes", got.Annotations["keep-me"])
}

func TestCacheTransform_LeavesOtherKindsAlone(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "default"},
		Data:       map[string][]byte{"password": []byte("SuperSecret123")},
	}

	out, err := CacheTransform()(secret)
	require.NoError(t, err)
	assert.Equal(t, []byte("SuperSecret123"), out.(*corev1.Secret).Data["password"],
		"ConfigMap stripping must not leak into other types")
}

// TestCacheTransform_ThroughSharedInformer drives the transform through a real
// client-go shared informer - the machinery controller-runtime's cache is built
// on - so that the cached representation, not just the function, is asserted.
func TestCacheTransform_ThroughSharedInformer(t *testing.T) {
	tests := []struct {
		name      string
		configMap string
		wantData  bool
	}{
		{"ordinary ConfigMap", "kap-configmap-secret-test", false},
		{"policies ConfigMap", trivyoperator.PoliciesConfigMapName, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientset := fake.NewClientset(configMapWithSecretData(tc.configMap))

			factory := informers.NewSharedInformerFactoryWithOptions(
				clientset,
				0,
				informers.WithNamespace("default"),
				informers.WithTransform(CacheTransform()),
			)
			informer := factory.Core().V1().ConfigMaps().Informer()

			stop := make(chan struct{})
			defer close(stop)
			factory.Start(stop)

			require.Eventually(t, informer.HasSynced, 10*time.Second, 10*time.Millisecond,
				"informer did not sync")

			obj, exists, err := informer.GetStore().GetByKey("default/" + tc.configMap)
			require.NoError(t, err)
			require.True(t, exists, "ConfigMap not found in informer store")

			cached := obj.(*corev1.ConfigMap)
			if tc.wantData {
				assert.Equal(t, "SuperSecret123", cached.Data["password"])
			} else {
				assert.Nil(t, cached.Data)
				assert.Nil(t, cached.BinaryData)
			}
		})
	}
}

// TestCacheTransform_ReconcileDoesNotPolluteTheStore proves the invariant the
// config-audit ConfigMap fix depends on: enriching the reconcile-local ConfigMap
// with contents read from the API server cannot push those contents into the
// shared informer store, so the memory optimization survives repeated
// reconciles.
//
// See (*configauditreport/controller.ResourceController).restoreConfigMapData
// and its unit tests for the production code path.
func TestCacheTransform_ReconcileDoesNotPolluteTheStore(t *testing.T) {
	const name = "kap-configmap-secret-test"

	clientset := fake.NewClientset(configMapWithSecretData(name))
	factory := informers.NewSharedInformerFactoryWithOptions(
		clientset,
		0,
		informers.WithNamespace("default"),
		informers.WithTransform(CacheTransform()),
	)
	informer := factory.Core().V1().ConfigMaps().Informer()

	stop := make(chan struct{})
	defer close(stop)
	factory.Start(stop)

	require.Eventually(t, informer.HasSynced, 10*time.Second, 10*time.Millisecond,
		"informer did not sync")

	readStore := func() *corev1.ConfigMap {
		obj, exists, err := informer.GetStore().GetByKey("default/" + name)
		require.NoError(t, err)
		require.True(t, exists)
		return obj.(*corev1.ConfigMap)
	}

	require.Nil(t, readStore().Data, "precondition: the cache stores no ConfigMap data")

	// live is what the API server returns; config-audit reads it through the
	// manager's uncached APIReader.
	live := configMapWithSecretData(name)

	for i := range 3 {
		// Mimic controller-runtime's CacheReader.Get: deep copy the stored object,
		// then copy the struct into a freshly allocated object.
		out := &corev1.ConfigMap{}
		*out = *readStore().DeepCopy()

		out.Data = live.Data
		out.BinaryData = live.BinaryData

		assert.Equal(t, "SuperSecret123", out.Data["password"],
			"reconcile %d: the scanned object must carry the ConfigMap data", i)
		assert.Nil(t, readStore().Data, "reconcile %d polluted the informer store", i)
		assert.Nil(t, readStore().BinaryData, "reconcile %d polluted the informer store", i)
	}

	// Same guarantee with the deep copy skipped, i.e. as if the cache were
	// configured with UnsafeDisableDeepCopy.
	out := &corev1.ConfigMap{}
	*out = *readStore()
	out.Data = live.Data
	out.BinaryData = live.BinaryData

	assert.Nil(t, readStore().Data)
	assert.Nil(t, readStore().BinaryData)
}
