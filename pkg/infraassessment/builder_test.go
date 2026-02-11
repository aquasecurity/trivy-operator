package infraassessment_test

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
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
					Name:        "some-owner",
					Namespace:   "qa",
					Labels:      labels.Set{"tier": "tier-1", "owner": "team-a"},
					Annotations: labels.Set{"test-annotation": "this is a test", "ignored-annotation": "should not be present"},
				},
			}).
			ResourceSpecHash("xyz").
			PluginConfigHash("nop").
			Data(v1alpha1.InfraAssessmentReportData{}).
			ResourceLabelsToInclude([]string{"tier"}).
			ResourceAnnotationsToInclude([]string{"test-annotation"}).
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
					trivyoperator.LabelK8SAppManagedBy:   trivyoperator.AppTrivyOperator,
					"tier":                               "tier-1",
				},
				Annotations: map[string]string{
					"test-annotation": "this is a test",
				},
			},
			Report: v1alpha1.InfraAssessmentReportData{},
		}))
	})

	t.Run("Should build cluster report for cluster scoped resource", func(t *testing.T) {
		g := NewGomegaWithT(t)

		report, err := infraassessment.NewReportBuilder(scheme.Scheme).
			Controller(&rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ClusterRole",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:   "system:controller:node-controller",
					Labels: labels.Set{"tier": "tier-1", "owner": "team-a"},
				},
			}).
			ResourceSpecHash("xyz").
			PluginConfigHash("nop").
			Data(v1alpha1.InfraAssessmentReportData{}).
			ResourceLabelsToInclude([]string{"tier"}).
			GetClusterReport()

		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(report).To(Equal(v1alpha1.ClusterInfraAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-6f69bb5b79",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "rbac.authorization.k8s.io/v1",
						Kind:               "ClusterRole",
						Name:               "system:controller:node-controller",
						Controller:         ptr.To[bool](true),
						BlockOwnerDeletion: ptr.To[bool](false),
					},
				},
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "ClusterRole",
					trivyoperator.LabelResourceNameHash:  "6f69bb5b79",
					trivyoperator.LabelResourceNamespace: "",
					trivyoperator.LabelResourceSpecHash:  "xyz",
					trivyoperator.LabelPluginConfigHash:  "nop",
					trivyoperator.LabelK8SAppManagedBy:   trivyoperator.AppTrivyOperator,
					"tier":                               "tier-1",
				},
				Annotations: map[string]string{
					trivyoperator.LabelResourceName: "system:controller:node-controller",
				},
			},
			Report: v1alpha1.InfraAssessmentReportData{},
		}))
	})

	t.Run("Should build report with additional labels", func(t *testing.T) {
		g := NewGomegaWithT(t)

		additionalLabels := map[string]string{
			"custom-label":    "custom-value",
			"environment":     "test",
			"managed-by-user": "admin",
		}

		report, err := infraassessment.NewReportBuilder(scheme.Scheme).
			Controller(&appsv1.Deployment{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Deployment",
					APIVersion: "apps/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-deployment",
					Namespace: "default",
					Labels:    labels.Set{"app": "nginx", "version": "1.16"},
				},
			}).
			ResourceSpecHash("abc123").
			PluginConfigHash("def456").
			Data(v1alpha1.InfraAssessmentReportData{}).
			ResourceLabelsToInclude([]string{"app"}).
			AdditionalReportLabels(additionalLabels).
			GetReport()

		g.Expect(err).ToNot(HaveOccurred())

		// Verify managed-by label is always present
		g.Expect(report.Labels).To(HaveKeyWithValue(trivyoperator.LabelK8SAppManagedBy, trivyoperator.AppTrivyOperator))

		// Verify additional labels are included
		for key, value := range additionalLabels {
			g.Expect(report.Labels).To(HaveKeyWithValue(key, value))
		}

		// Verify core trivy-operator labels are present
		g.Expect(report.Labels).To(HaveKeyWithValue(trivyoperator.LabelResourceKind, "Deployment"))
		g.Expect(report.Labels).To(HaveKeyWithValue(trivyoperator.LabelResourceName, "test-deployment"))
		g.Expect(report.Labels).To(HaveKeyWithValue(trivyoperator.LabelResourceNamespace, "default"))
		g.Expect(report.Labels).To(HaveKeyWithValue("app", "nginx")) // from ResourceLabelsToInclude
	})

	t.Run("Should build report without additional labels", func(t *testing.T) {
		g := NewGomegaWithT(t)

		report, err := infraassessment.NewReportBuilder(scheme.Scheme).
			Controller(&appsv1.DaemonSet{
				TypeMeta: metav1.TypeMeta{
					Kind:       "DaemonSet",
					APIVersion: "apps/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-daemonset",
					Namespace: "kube-system",
				},
			}).
			ResourceSpecHash("xyz789").
			Data(v1alpha1.InfraAssessmentReportData{}).
			GetReport()

		g.Expect(err).ToNot(HaveOccurred())

		// Even without additional labels, managed-by should be present
		g.Expect(report.Labels).To(HaveKeyWithValue(trivyoperator.LabelK8SAppManagedBy, trivyoperator.AppTrivyOperator))
		g.Expect(report.Labels).To(HaveKeyWithValue(trivyoperator.LabelResourceKind, "DaemonSet"))
		g.Expect(report.Labels).To(HaveKeyWithValue(trivyoperator.LabelResourceName, "test-daemonset"))
		g.Expect(report.Labels).To(HaveKeyWithValue(trivyoperator.LabelResourceNamespace, "kube-system"))
	})
}
