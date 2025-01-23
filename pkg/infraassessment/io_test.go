package infraassessment_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/infraassessment"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

func TestReadWriter(t *testing.T) {

	kubernetesScheme := trivyoperator.NewScheme()

	t.Run("Should create InfraAssessmentReport", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := infraassessment.NewReadWriter(&resolver)
		err := readWriter.WriteReport(context.TODO(), v1alpha1.InfraAssessmentReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "InfraAssessmentReport",
				APIVersion: "aquasecurity.github.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "role-app",
				Namespace: "qa",
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "Role",
					trivyoperator.LabelResourceName:      "app",
					trivyoperator.LabelResourceNamespace: "qa",
				},
			},
			Report: v1alpha1.InfraAssessmentReportData{
				Summary: v1alpha1.InfraAssessmentSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		})
		require.NoError(t, err)

		var found v1alpha1.InfraAssessmentReport
		err = testClient.Get(context.TODO(), types.NamespacedName{Namespace: "qa", Name: "role-app"}, &found)
		require.NoError(t, err)

		assert.Equal(t, v1alpha1.InfraAssessmentReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "InfraAssessmentReport",
				APIVersion: "aquasecurity.github.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "role-app",
				Namespace: "qa",
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "Role",
					trivyoperator.LabelResourceName:      "app",
					trivyoperator.LabelResourceNamespace: "qa",
				},
				ResourceVersion: "1",
			},
			Report: v1alpha1.InfraAssessmentReportData{
				Summary: v1alpha1.InfraAssessmentSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		}, found)
	})

	t.Run("Should update InfraAssessmentReport", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(&v1alpha1.InfraAssessmentReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "InfraAssessmentReport",
				APIVersion: "aquasecurity.github.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            "role-app",
				Namespace:       "qa",
				ResourceVersion: "0",
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "Role",
					trivyoperator.LabelResourceName:      "app",
					trivyoperator.LabelResourceNamespace: "qa",
					trivyoperator.LabelResourceSpecHash:  "h1",
				},
			},
			Report: v1alpha1.InfraAssessmentReportData{
				Summary: v1alpha1.InfraAssessmentSummary{
					LowCount:      8,
					CriticalCount: 3,
				},
			},
		}).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := infraassessment.NewReadWriter(&resolver)
		err := readWriter.WriteReport(context.TODO(), v1alpha1.InfraAssessmentReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "InfraAssessmentReport",
				APIVersion: "aquasecurity.github.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "role-app",
				Namespace: "qa",
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "Role",
					trivyoperator.LabelResourceName:      "app",
					trivyoperator.LabelResourceNamespace: "qa",
					trivyoperator.LabelResourceSpecHash:  "h2",
				},
			},
			Report: v1alpha1.InfraAssessmentReportData{
				Summary: v1alpha1.InfraAssessmentSummary{
					LowCount:      9,
					CriticalCount: 2,
				},
			},
		})
		require.NoError(t, err)

		var found v1alpha1.InfraAssessmentReport
		err = testClient.Get(context.TODO(), types.NamespacedName{Namespace: "qa", Name: "role-app"}, &found)
		require.NoError(t, err)

		assert.Equal(t, v1alpha1.InfraAssessmentReport{
			TypeMeta: metav1.TypeMeta{
				Kind:       "InfraAssessmentReport",
				APIVersion: "aquasecurity.github.io/v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "role-app",
				Namespace: "qa",
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "Role",
					trivyoperator.LabelResourceName:      "app",
					trivyoperator.LabelResourceNamespace: "qa",
					trivyoperator.LabelResourceSpecHash:  "h2",
				},
				ResourceVersion: "1",
			},
			Report: v1alpha1.InfraAssessmentReportData{
				Summary: v1alpha1.InfraAssessmentSummary{
					LowCount:      9,
					CriticalCount: 2,
				},
			},
		}, found)
	})

	t.Run("Should find InfraAssessmentReport by owner", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(
			&v1alpha1.InfraAssessmentReport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "my-namespace",
					Name:            "role-my-deploy-my",
					ResourceVersion: "0",
					Labels: map[string]string{
						trivyoperator.LabelResourceKind:      string(kube.KindDeployment),
						trivyoperator.LabelResourceName:      "role-my-deploy",
						trivyoperator.LabelResourceNamespace: "my-namespace",
					},
				},
				Report: v1alpha1.InfraAssessmentReportData{},
			}, &v1alpha1.InfraAssessmentReport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "my-namespace",
					Name:      "role-my-sts",
					Labels: map[string]string{
						trivyoperator.LabelResourceKind:      string(kube.KindStatefulSet),
						trivyoperator.LabelResourceName:      "role-my-sts",
						trivyoperator.LabelResourceNamespace: "my-namespace",
					},
				},
				Report: v1alpha1.InfraAssessmentReportData{},
			}).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := infraassessment.NewReadWriter(&resolver)
		found, err := readWriter.FindReportByOwner(context.TODO(), kube.ObjectRef{
			Kind:      kube.KindDeployment,
			Name:      "role-my-deploy",
			Namespace: "my-namespace",
		})
		require.NoError(t, err)
		assert.Equal(t, &v1alpha1.InfraAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "my-namespace",
				Name:            "role-my-deploy-my",
				ResourceVersion: "0",
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      string(kube.KindDeployment),
					trivyoperator.LabelResourceName:      "role-my-deploy",
					trivyoperator.LabelResourceNamespace: "my-namespace",
				},
			},
			Report: v1alpha1.InfraAssessmentReportData{},
		}, found)
	})

	t.Run("Should find InfraAssessmentReport by owner with special name", func(t *testing.T) {
		testClient := fake.NewClientBuilder().WithScheme(kubernetesScheme).WithObjects(
			&v1alpha1.InfraAssessmentReport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "kube-system",
					Name:            "role-79f88497",
					ResourceVersion: "0",
					Labels: map[string]string{
						trivyoperator.LabelResourceKind:      "Role",
						trivyoperator.LabelResourceNameHash:  "79f88497",
						trivyoperator.LabelResourceNamespace: "kube-system",
					},
					Annotations: map[string]string{
						trivyoperator.LabelResourceName: "system:controller:cloud-provider",
					},
				},
				Report: v1alpha1.InfraAssessmentReportData{},
			}, &v1alpha1.InfraAssessmentReport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       "kube-system",
					Name:            "role-868458b9d6",
					ResourceVersion: "0",
					Labels: map[string]string{
						trivyoperator.LabelResourceKind:      "Role",
						trivyoperator.LabelResourceNameHash:  "868458b9d6",
						trivyoperator.LabelResourceNamespace: "kube-system",
					},
					Annotations: map[string]string{
						trivyoperator.LabelResourceName: "system:controller:token-cleaner",
					},
				},
				Report: v1alpha1.InfraAssessmentReportData{},
			}).Build()
		resolver := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		readWriter := infraassessment.NewReadWriter(&resolver)
		found, err := readWriter.FindReportByOwner(context.TODO(), kube.ObjectRef{
			Kind:      kube.KindRole,
			Name:      "system:controller:token-cleaner",
			Namespace: "kube-system",
		})
		require.NoError(t, err)
		assert.Equal(t, &v1alpha1.InfraAssessmentReport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       "kube-system",
				Name:            "role-868458b9d6",
				ResourceVersion: "0",
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "Role",
					trivyoperator.LabelResourceNameHash:  "868458b9d6",
					trivyoperator.LabelResourceNamespace: "kube-system",
				},
				Annotations: map[string]string{
					trivyoperator.LabelResourceName: "system:controller:token-cleaner",
				},
			},
			Report: v1alpha1.InfraAssessmentReportData{},
		}, found)
	})
}
