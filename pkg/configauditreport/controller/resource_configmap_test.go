package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// failingReader fails the test if it is used. It proves that
// restoreConfigMapData does not hit the API server for resources that do not
// need it.
type failingReader struct {
	t *testing.T
}

func (f failingReader) Get(_ context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	f.t.Fatal("APIReader must not be called for this resource")
	return nil
}

func (f failingReader) List(_ context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	f.t.Fatal("APIReader must not be called for this resource")
	return nil
}

func liveConfigMap(name string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Data: map[string]string{
			"password":               "SuperSecret123",
			"application.properties": "username=admin\npassword=SuperSecret123\nnormal_setting=true\n",
		},
		BinaryData: map[string][]byte{"keystore.jks": []byte("binary-secret")},
	}
}

func apiReaderWith(t *testing.T, objs ...client.Object) client.Reader {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

// TestRestoreConfigMapData_DoesNotMutateTheCachedObject is the aliasing
// guarantee the fix depends on: config-audit enriches only its own reconcile
// object, so the shared informer cache keeps storing ConfigMaps without
// contents and the memory optimization survives repeated reconciles.
func TestRestoreConfigMapData_DoesNotMutateTheCachedObject(t *testing.T) {
	const name = "kap-configmap-secret-test"

	// stored is what the informer holds after pkg/operator.CacheTransform ran.
	stored := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
	}

	r := &ResourceController{APIReader: apiReaderWith(t, liveConfigMap(name))}
	key := client.ObjectKey{Namespace: "default", Name: name}

	for i := range 3 {
		// Mimic controller-runtime's CacheReader.Get: deep copy the stored
		// object, then copy the struct into a freshly allocated object.
		out := &corev1.ConfigMap{}
		*out = *stored.DeepCopy()

		require.NoError(t, r.restoreConfigMapData(context.Background(), key, out))

		assert.Equal(t, "SuperSecret123", out.Data["password"],
			"reconcile %d: the scanned object must carry the ConfigMap data", i)
		assert.Contains(t, out.Data["application.properties"], "password=SuperSecret123")
		assert.Equal(t, []byte("binary-secret"), out.BinaryData["keystore.jks"])

		assert.Nil(t, stored.Data, "reconcile %d polluted the cached object", i)
		assert.Nil(t, stored.BinaryData, "reconcile %d polluted the cached object", i)
	}
}

// TestRestoreConfigMapData_SafeWithoutDeepCopy covers the same guarantee if the
// cache were ever configured with UnsafeDisableDeepCopy: the fields are rebound
// on a separate struct rather than mutated through a shared map.
func TestRestoreConfigMapData_SafeWithoutDeepCopy(t *testing.T) {
	const name = "kap-configmap-secret-test"

	stored := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
	}

	r := &ResourceController{APIReader: apiReaderWith(t, liveConfigMap(name))}

	out := &corev1.ConfigMap{}
	*out = *stored // no deep copy

	require.NoError(t, r.restoreConfigMapData(context.Background(),
		client.ObjectKey{Namespace: "default", Name: name}, out))

	assert.Equal(t, "SuperSecret123", out.Data["password"])
	assert.Nil(t, stored.Data)
	assert.Nil(t, stored.BinaryData)
}

func TestRestoreConfigMapData_LeavesOtherResourcesAlone(t *testing.T) {
	r := &ResourceController{APIReader: failingReader{t: t}}

	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "nginx", Namespace: "default"},
	}
	require.NoError(t, r.restoreConfigMapData(context.Background(),
		client.ObjectKey{Namespace: "default", Name: "nginx"}, deploy))
	assert.Equal(t, "nginx", deploy.Name)
}

func TestRestoreConfigMapData_NoAPIReaderIsANoOp(t *testing.T) {
	r := &ResourceController{}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: "default"},
	}
	require.NoError(t, r.restoreConfigMapData(context.Background(),
		client.ObjectKey{Namespace: "default", Name: "cm"}, cm))
	assert.Nil(t, cm.Data)
}

func TestRestoreConfigMapData_PropagatesNotFound(t *testing.T) {
	r := &ResourceController{APIReader: apiReaderWith(t)}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "gone", Namespace: "default"},
	}
	err := r.restoreConfigMapData(context.Background(),
		client.ObjectKey{Namespace: "default", Name: "gone"}, cm)

	require.Error(t, err)
	assert.True(t, apierrors.IsNotFound(err),
		"the reconciler relies on IsNotFound to skip deleted ConfigMaps")
}
