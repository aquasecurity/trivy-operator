package trivy_operator

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/tests/itest/helper"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Trivy ignoreFile integration", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})

	It("hides CVE-2025-47907 when set in .trivyignore", func() {
		const IgnoredCVE = "CVE-2025-47907"

		// Patch trivy-operator-trivy-config ConfigMap to include CVEToIgnore in trivy.ignoreFile
		operatorConfig, err := etc.GetOperatorConfig()
		Expect(err).ToNot(HaveOccurred())
		operatorNamespace, err := operatorConfig.GetOperatorNamespace()
		Expect(err).ToNot(HaveOccurred())

		cm := &corev1.ConfigMap{}
		Expect(kubeClient.Get(ctx, clientObjectKey(operatorNamespace, trivyoperator.TrivyConfigMapName), cm)).To(Succeed())

		// Merge with existing content if present; ensure CVEToIgnore is present as a separate line
		current := cm.Data["trivy.ignoreFile"]
		if !strings.Contains(current, IgnoredCVE) {
			if current != "" && !strings.HasSuffix(current, "\n") {
				current += "\n"
			}
		}
		cm.Data["trivy.ignoreFile"] = current

		By("Updating trivy.ignoreFile in ConfigMap")
		Expect(kubeClient.Update(ctx, cm)).To(Succeed())

		// Brief wait to reduce races where a scan could start before CM is observed by the controller
		time.Sleep(3 * time.Second)

		// Create an unmanaged Pod using kube-bench image and assert the ignored CVE is not reported
		pod := helper.NewPod().
			WithRandomName("trivyignore-kubebench").
			WithNamespace(inputs.PrimaryNamespace).
			WithContainer("kube-bench", "aquasec/kube-bench:v0.11.1", []string{"/bin/sh", "-c", "--"}, []string{"while true; do sleep 30; done;"}).
			Build()

		By("Creating kube-bench Pod")
		Expect(inputs.Create(ctx, pod)).To(Succeed())
		DeferCleanup(func() {
			_ = inputs.Delete(ctx, pod)
		})

		By("Waiting for VulnerabilityReport")
		Eventually(inputs.HasVulnerabilityReportOwnedBy(ctx, pod), inputs.AssertTimeout, inputs.PollingInterval).Should(BeTrue())

		vrList := &v1alpha1.VulnerabilityReportList{}
		Expect(kubeClient.List(ctx, vrList, clientListOptionsForOwner(pod.ObjectMeta, "Pod"))).To(Succeed())
		Expect(vrList.Items).ToNot(BeEmpty(), "expected at least one VulnerabilityReport for the pod")

		// The report must not include the ignored CVE ID
		for _, vr := range vrList.Items {
			for _, v := range vr.Report.Vulnerabilities {
				Expect(v.VulnerabilityID).ToNot(Equal(IgnoredCVE), fmt.Sprintf("unexpectedly found ignored CVE %s", IgnoredCVE))
			}
		}
	})
})

// clientListOptionsForOwner builds ListOptions that match a VulnerabilityReport owned by the given object.
func clientListOptionsForOwner(obj metav1.ObjectMeta, kind string) crclient.ListOption {
	sel := labels.Set{
		trivyoperator.LabelResourceNamespace: obj.Namespace,
		trivyoperator.LabelResourceKind:      kind,
		trivyoperator.LabelResourceName:      obj.Name,
	}
	return crclient.MatchingLabels(sel)
}

// clientObjectKey returns a NamespacedName tuple for use with client.Get.
func clientObjectKey(namespace, name string) types.NamespacedName {
	return types.NamespacedName{Namespace: namespace, Name: name}
}
