package exposedsecretreport_test

import (
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/exposedsecretreport"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/pointer"
)

func TestReportBuilder(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	report, err := exposedsecretreport.NewReportBuilder(scheme.Scheme).
		Controller(&appsv1.ReplicaSet{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ReplicaSet",
				APIVersion: "apps/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "some-owner",
				Namespace: "qa",
			},
		}).
		Container("my-container").
		PodSpecHash("xyz").
		Data(v1alpha1.ExposedSecretReportData{}).
		Get()

	g.Expect(err).ToNot(gomega.HaveOccurred())
	g.Expect(report).To(gomega.Equal(v1alpha1.ExposedSecretReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replicaset-some-owner-my-container",
			Namespace: "qa",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "apps/v1",
					Kind:               "ReplicaSet",
					Name:               "some-owner",
					Controller:         pointer.BoolPtr(true),
					BlockOwnerDeletion: pointer.BoolPtr(false),
				},
			},
			Labels: map[string]string{
				trivyoperator.LabelResourceKind:      "ReplicaSet",
				trivyoperator.LabelResourceName:      "some-owner",
				trivyoperator.LabelResourceNamespace: "qa",
				trivyoperator.LabelContainerName:     "my-container",
				trivyoperator.LabelResourceSpecHash:  "xyz",
			},
		},
		Report: v1alpha1.ExposedSecretReportData{},
	}))
}
