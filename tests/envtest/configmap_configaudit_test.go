package operator_test

import (
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Regression coverage for ConfigMap contents being stripped from the shared
// informer cache before config-audit evaluated them, which made every check
// that reads ConfigMap data pass vacuously.
//
// The whole production path is exercised here: the object goes through the real
// controller-runtime cache (with the operator's own transform installed in
// suite_test.go), through the config-audit ResourceController, through
// policy.Policies.Eval and into Rego.
var _ = Describe("ConfigAudit on ConfigMap contents", func() {
	const (
		cmNamespace = "default"
		cmName      = "kap-configmap-secret-test"
		reportName  = "configmap-" + cmName
		checkID     = "KSV109"
		timeout     = time.Second * 45
		interval    = time.Millisecond * 250
	)

	findCheck := func(checks []v1alpha1.Check, id string) *v1alpha1.Check {
		for i := range checks {
			if checks[i].ID == id {
				return &checks[i]
			}
		}
		return nil
	}

	It("should report a failed check for a ConfigMap that stores a secret", func() {
		configMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cmName,
				Namespace: cmNamespace,
			},
			Data: map[string]string{
				"password":               "SuperSecret123",
				"application.properties": "username=admin\npassword=SuperSecret123\nnormal_setting=true\n",
			},
		}
		Expect(k8sClient.Create(ctx, configMap)).Should(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, configMap)
		})

		key := client.ObjectKeyFromObject(configMap)

		By("confirming the API server holds the ConfigMap data")
		fromAPI := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, key, fromAPI)).Should(Succeed())
		Expect(fromAPI.Data).Should(HaveKeyWithValue("password", "SuperSecret123"))

		By("confirming the shared cache still strips the ConfigMap data")
		// This is the memory optimization the operator relies on, and the reason
		// config-audit has to read the contents from the API server. If this
		// assertion ever fails the optimization has been dropped, and the
		// regression this spec guards can no longer occur for the reason it did.
		cached := &corev1.ConfigMap{}
		Eventually(func(g Gomega) {
			g.Expect(cachedClient.Get(ctx, key, cached)).Should(Succeed())
			g.Expect(cached.Data).Should(BeNil())
		}, timeout, interval).Should(Succeed())

		By("waiting for the ConfigAuditReport")
		report := &v1alpha1.ConfigAuditReport{}
		Eventually(func() error {
			return k8sClient.Get(ctx, client.ObjectKey{Namespace: cmNamespace, Name: reportName}, report)
		}, timeout, interval).Should(Succeed())

		By("asserting the ConfigMap data reached Rego")
		check := findCheck(report.Report.Checks, checkID)
		Expect(check).ShouldNot(BeNil(),
			"check %s missing from the report; config-audit did not evaluate the ConfigMap", checkID)
		Expect(check.Success).Should(BeFalse(),
			"check %s passed, which means Rego saw no ConfigMap data", checkID)
		Expect(strings.Join(check.Messages, " ")).Should(ContainSubstring("password"),
			"the finding must name the offending ConfigMap key")

		By("confirming the reconcile did not push the data into the shared cache")
		// restoreConfigMapData enriches only the reconcile-local object, which
		// controller-runtime's CacheReader hands out as a deep copy. The store
		// must still hold a ConfigMap without contents, on this read and on
		// every later one, or the memory optimization has been defeated.
		for range 2 {
			afterReconcile := &corev1.ConfigMap{}
			Expect(cachedClient.Get(ctx, key, afterReconcile)).Should(Succeed())
			Expect(afterReconcile.Data).Should(BeNil(),
				"the reconcile leaked ConfigMap data into the informer cache")
			Expect(afterReconcile.BinaryData).Should(BeNil(),
				"the reconcile leaked ConfigMap binaryData into the informer cache")
		}

		By("confirming it still holds after a further update triggers another reconcile")
		updated := &corev1.ConfigMap{}
		Expect(k8sClient.Get(ctx, key, updated)).Should(Succeed())
		updated.Data["another.properties"] = "token=abc123"
		Expect(k8sClient.Update(ctx, updated)).Should(Succeed())

		Eventually(func(g Gomega) {
			// the API server keeps the new key ...
			fromAPIAgain := &corev1.ConfigMap{}
			g.Expect(k8sClient.Get(ctx, key, fromAPIAgain)).Should(Succeed())
			g.Expect(fromAPIAgain.Data).Should(HaveKey("another.properties"))

			// ... while the cache still holds nothing.
			afterUpdate := &corev1.ConfigMap{}
			g.Expect(cachedClient.Get(ctx, key, afterUpdate)).Should(Succeed())
			g.Expect(afterUpdate.Data).Should(BeNil())
			g.Expect(afterUpdate.BinaryData).Should(BeNil())
		}, timeout, interval).Should(Succeed())
	})

	It("should keep caching the contents of the operator's own ConfigMaps", func() {
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "configmap-cache-regression"},
		}
		Expect(k8sClient.Create(ctx, namespace)).Should(Succeed())

		cases := []struct {
			name     string
			wantData bool
		}{
			{name: trivyoperator.PoliciesConfigMapName, wantData: true},
			{name: trivyoperator.TrivyConfigMapName, wantData: true},
			{name: "some-application-config", wantData: false},
		}

		for _, tc := range cases {
			configMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      tc.name,
					Namespace: namespace.Name,
				},
				Data:       map[string]string{"password": "SuperSecret123"},
				BinaryData: map[string][]byte{"keystore.jks": []byte("binary-secret")},
			}
			Expect(k8sClient.Create(ctx, configMap)).Should(Succeed())

			key := client.ObjectKeyFromObject(configMap)
			wantData := tc.wantData

			cached := &corev1.ConfigMap{}
			Eventually(func(g Gomega) {
				g.Expect(cachedClient.Get(ctx, key, cached)).Should(Succeed())
				if wantData {
					g.Expect(cached.Data).Should(HaveKeyWithValue("password", "SuperSecret123"))
					g.Expect(cached.BinaryData).Should(HaveKeyWithValue("keystore.jks", []byte("binary-secret")))
				} else {
					g.Expect(cached.Data).Should(BeNil())
					g.Expect(cached.BinaryData).Should(BeNil())
				}
			}, timeout, interval).Should(Succeed(), "unexpected cache behaviour for ConfigMap %s", tc.name)
		}
	})
})
