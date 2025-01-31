package infraassessment_test

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/infraassessment"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"

	. "github.com/onsi/gomega"
)

func TestReportBuilder(t *testing.T) {

	t.Run("Should build report for namespaced resource", func(t *testing.T) {
		g := NewGomegaWithT(t)

		report, err := infraassessment.NewReportBuilder(scheme.Scheme).
			Controller(&appsv1.ReplicaSet{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ReplicaSet",
					APIVersion: "apps/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-owner",
					Namespace: "qa",
					Labels:    labels.Set{"tier": "tier-1", "owner": "team-a"},
				},
			}).
			ResourceSpecHash("xyz").
			PluginConfigHash("nop").
			Data(v1alpha1.InfraAssessmentReportData{}).
			ResourceLabelsToInclude([]string{"tier"}).
			GetReport()

		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(report).To(Equal(v1alpha1.InfraAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "replicaset-some-owner",
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
					trivyoperator.LabelResourceSpecHash:  "xyz",
					trivyoperator.LabelPluginConfigHash:  "nop",
					"tier":                               "tier-1",
				},
			},
			Report: v1alpha1.InfraAssessmentReportData{},
		}))
	})
}
