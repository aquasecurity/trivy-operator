package exposedsecretreport_test

import (
	"testing"

	"github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/exposedsecretreport"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
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
				Name:        "some-owner",
				Namespace:   "qa",
				Labels:      labels.Set{"tier": "tier-1", "owner": "team-a"},
				Annotations: labels.Set{"test-annotation": "this is a test", "ignored-annotation": "should not be present"},
			},
		}).
		Container("my-container").
		PodSpecHash("xyz").
		Data(v1alpha1.ExposedSecretReportData{}).
		ResourceLabelsToInclude([]string{"tier"}).
		ResourceAnnotationsToInclude([]string{"test-annotation"}).
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
					Controller:         ptr.To[bool](true),
					BlockOwnerDeletion: ptr.To[bool](false),
				},
			},
			Labels: map[string]string{
				trivyoperator.LabelResourceKind:      "ReplicaSet",
				trivyoperator.LabelResourceName:      "some-owner",
				trivyoperator.LabelResourceNamespace: "qa",
				trivyoperator.LabelContainerName:     "my-container",
				trivyoperator.LabelResourceSpecHash:  "xyz",
				"tier":                               "tier-1",
			},
			Annotations: map[string]string{
				"test-annotation": "this is a test",
			},
		},
		Report: v1alpha1.ExposedSecretReportData{},
	}))
}
