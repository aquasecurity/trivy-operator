package trivyoperator_test

import (
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetPluginConfigMapName(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	name := trivyoperator.GetPluginConfigMapName("Conftest")
	g.Expect(name).To(gomega.Equal("trivyoperator-conftest-config"))
}

func TestPluginContext_GetConfig(t *testing.T) {

	t.Run("Should return PluginConfig from ConfigMap", func(t *testing.T) {
		g := gomega.NewGomegaWithT(t)

		client := fake.NewClientBuilder().
			WithScheme(trivyoperator.NewScheme()).
			WithObjects(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "trivyoperator-polaris-config",
					Namespace: "trivyoperator-ns",
				},
				Data: map[string]string{
					"foo": "bar",
				},
			}).
			Build()

		pluginContext := trivyoperator.NewPluginContext().
			WithName("polaris").
			WithNamespace("trivyoperator-ns").
			WithClient(client).
			Get()

		cm, err := pluginContext.GetConfig()

		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(cm).To(gomega.Equal(
			trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
			}))
	})

	t.Run("Should return PluginConfig from ConfigMap and Secret", func(t *testing.T) {
		g := gomega.NewGomegaWithT(t)

		client := fake.NewClientBuilder().
			WithScheme(trivyoperator.NewScheme()).
			WithObjects(&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "trivyoperator-polaris-config",
					Namespace: "trivyoperator-ns",
				},
				Data: map[string]string{
					"foo": "bar",
				},
			}, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "trivyoperator-polaris-config",
					Namespace: "trivyoperator-ns",
				},
				Data: map[string][]byte{
					"secret": []byte("pa$$word"),
				},
			}).
			Build()

		pluginContext := trivyoperator.NewPluginContext().
			WithName("polaris").
			WithNamespace("trivyoperator-ns").
			WithClient(client).
			Get()

		cm, err := pluginContext.GetConfig()

		g.Expect(err).ToNot(gomega.HaveOccurred())
		g.Expect(cm).To(gomega.Equal(
			trivyoperator.PluginConfig{
				Data: map[string]string{
					"foo": "bar",
				},
				SecretData: map[string][]byte{
					"secret": []byte("pa$$word"),
				},
			}))
	})
}
