package kubebench_test

import (
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kubebench"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/pointer"
)

func TestBuilder(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	report, err := kubebench.NewBuilder(scheme.Scheme).
		Controller(&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: "control-plane",
			},
		}).
		Data(v1alpha1.CISKubeBenchReportData{}).Get()

	g.Expect(err).ToNot(gomega.HaveOccurred())
	g.Expect(report).To(gomega.Equal(v1alpha1.CISKubeBenchReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "control-plane",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "v1",
					Kind:               "Node",
					Name:               "control-plane",
					Controller:         pointer.BoolPtr(true),
					BlockOwnerDeletion: pointer.BoolPtr(false),
				},
			},
			Labels: map[string]string{
				trivyoperator.LabelResourceKind: "Node",
				trivyoperator.LabelResourceName: "control-plane",
			},
		},
		Report: v1alpha1.CISKubeBenchReportData{},
	}))
}
