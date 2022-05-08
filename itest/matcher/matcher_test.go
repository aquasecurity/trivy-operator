package matcher_test

import (
	. "github.com/onsi/gomega"

	"testing"

	"github.com/aquasecurity/trivy-operator/itest/matcher"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
)

func TestVulnerabilityReportMatcher(t *testing.T) {

	t.Run("Should return error when actual is not VulnerabilityReport", func(t *testing.T) {
		g := NewGomegaWithT(t)
		instance := matcher.IsVulnerabilityReportForContainerOwnedBy("nginx", &corev1.Pod{})
		_, err := instance.Match("I AM INVALID ACTUAL")
		g.Expect(err).To(MatchError("matcher.vulnerabilityReportMatcher expects a v1alpha1.VulnerabilityReport"))
	})

	t.Run("Should return true when VulnerabilityReport matches", func(t *testing.T) {
		g := NewGomegaWithT(t)
		instance := matcher.IsVulnerabilityReportForContainerOwnedBy("nginx-container", &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-pod",
				Namespace: "default",
				UID:       "56d53a84-c81b-4620-81a1-e226c35d3983",
			},
		})
		success, err := instance.Match(v1alpha1.VulnerabilityReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod-nginx-pod-nginx-container",
				Namespace: "default",
				Labels: map[string]string{
					trivyoperator.LabelContainerName:     "nginx-container",
					trivyoperator.LabelResourceKind:      "Pod",
					trivyoperator.LabelResourceName:      "nginx-pod",
					trivyoperator.LabelResourceNamespace: "default",
				},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "v1",
						Kind:               "Pod",
						Name:               "nginx-pod",
						UID:                "56d53a84-c81b-4620-81a1-e226c35d3983",
						Controller:         pointer.BoolPtr(true),
						BlockOwnerDeletion: pointer.BoolPtr(false),
					},
				},
			},
			Report: v1alpha1.VulnerabilityReportData{
				Scanner: v1alpha1.Scanner{
					Name:    "Trivy",
					Vendor:  "Aqua Security",
					Version: "0.25.2",
				},
				Vulnerabilities: []v1alpha1.Vulnerability{},
			},
		})
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(success).To(BeTrue())
	})
}

func TestConfigAuditReportMatcher(t *testing.T) {

	t.Run("Should return error when actual is not ConfigAuditReport", func(t *testing.T) {
		g := NewGomegaWithT(t)
		instance := matcher.IsConfigAuditReportOwnedBy(&appsv1.ReplicaSet{})
		_, err := instance.Match("I AM INVALID ACTUAL")
		g.Expect(err).To(MatchError("matcher.configAuditReportMatcher expects a v1alpha1.ConfigAuditReport"))
	})

	t.Run("Should return true when ConfigAuditReport matches", func(t *testing.T) {
		g := NewGomegaWithT(t)
		instance := matcher.IsConfigAuditReportOwnedBy(&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-6d4cf56db6",
				Namespace: "default",
				UID:       "494b2727-5d52-4057-9a9b-8b508c753fea",
			},
		})
		success, err := instance.Match(v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "replicaset-nginx-6d4cf56db6",
				Namespace: "default",
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "ReplicaSet",
					trivyoperator.LabelResourceName:      "nginx-6d4cf56db6",
					trivyoperator.LabelResourceNamespace: "default",
				},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "apps/v1",
						Kind:               "ReplicaSet",
						Name:               "nginx-6d4cf56db6",
						UID:                "494b2727-5d52-4057-9a9b-8b508c753fea",
						Controller:         pointer.BoolPtr(true),
						BlockOwnerDeletion: pointer.BoolPtr(false),
					},
				},
			},
			Report: v1alpha1.ConfigAuditReportData{
				Scanner: v1alpha1.Scanner{
					Name:    "Trivy-Operator",
					Vendor:  "Aqua Security",
					Version: "dev",
				},
			},
		})
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(success).To(BeTrue())
	})
}
