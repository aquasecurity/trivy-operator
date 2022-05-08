package kubebench_test

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/kubebench"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReadWriter(t *testing.T) {
	kubernetesScheme := trivyoperator.NewScheme()

	t.Run("Should create CISKubeBenchReport", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(kubernetesScheme).Build()
		instance := kubebench.NewReadWriter(client)
		err := instance.Write(context.Background(), v1alpha1.CISKubeBenchReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "control-plane",
				Labels: map[string]string{
					trivyoperator.LabelResourceKind: string(kube.KindNode),
					trivyoperator.LabelResourceName: "control-plane",
				},
			},
			Report: v1alpha1.CISKubeBenchReportData{
				Scanner: v1alpha1.Scanner{
					Vendor:  "Aqua Security",
					Name:    "kube-bench",
					Version: "0.5.1",
				},
				Summary: v1alpha1.CISKubeBenchSummary{
					FailCount: 10,
					WarnCount: 5,
					InfoCount: 3,
					PassCount: 2,
				},
			},
		})
		require.NoError(t, err)

		found := &v1alpha1.CISKubeBenchReport{}
		err = client.Get(context.Background(), types.NamespacedName{Name: "control-plane"}, found)
		require.NoError(t, err)

		assert.Equal(t, &v1alpha1.CISKubeBenchReport{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "aquasecurity.github.io/v1alpha1",
				Kind:       "CISKubeBenchReport",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            "control-plane",
				ResourceVersion: "1",
				Labels: map[string]string{
					trivyoperator.LabelResourceKind: string(kube.KindNode),
					trivyoperator.LabelResourceName: "control-plane",
				},
			},
			Report: v1alpha1.CISKubeBenchReportData{
				Scanner: v1alpha1.Scanner{
					Vendor:  "Aqua Security",
					Name:    "kube-bench",
					Version: "0.5.1",
				},
				Summary: v1alpha1.CISKubeBenchSummary{
					FailCount: 10,
					WarnCount: 5,
					InfoCount: 3,
					PassCount: 2,
				},
			},
		}, found)
	})

	t.Run("Should update CISKubeBenchReport", func(t *testing.T) {
		client := fake.NewClientBuilder().
			WithScheme(kubernetesScheme).
			WithObjects(&v1alpha1.CISKubeBenchReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "control-plane",
					ResourceVersion: "0",
					Labels: map[string]string{
						trivyoperator.LabelResourceKind: string(kube.KindNode),
						trivyoperator.LabelResourceName: "control-plane",
					},
				},
				Report: v1alpha1.CISKubeBenchReportData{
					Scanner: v1alpha1.Scanner{
						Vendor:  "Aqua Security",
						Name:    "kube-bench",
						Version: "0.5.1",
					},
					Summary: v1alpha1.CISKubeBenchSummary{
						FailCount: 10,
						WarnCount: 5,
						InfoCount: 3,
						PassCount: 2,
					},
				},
			}).
			Build()
		instance := kubebench.NewReadWriter(client)
		err := instance.Write(context.Background(), v1alpha1.CISKubeBenchReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "control-plane",
				Labels: map[string]string{
					trivyoperator.LabelResourceKind: string(kube.KindNode),
					trivyoperator.LabelResourceName: "control-plane",
				},
			},
			Report: v1alpha1.CISKubeBenchReportData{
				Scanner: v1alpha1.Scanner{
					Vendor:  "Aqua Security",
					Name:    "kube-bench",
					Version: "0.5.1",
				},
				Summary: v1alpha1.CISKubeBenchSummary{
					FailCount: 20,
					WarnCount: 10,
					InfoCount: 6,
					PassCount: 4,
				},
			},
		})
		require.NoError(t, err)

		found := &v1alpha1.CISKubeBenchReport{}
		err = client.Get(context.Background(), types.NamespacedName{Name: "control-plane"}, found)
		require.NoError(t, err)

		assert.Equal(t, &v1alpha1.CISKubeBenchReport{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "aquasecurity.github.io/v1alpha1",
				Kind:       "CISKubeBenchReport",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "control-plane",
				Labels: map[string]string{
					trivyoperator.LabelResourceKind: string(kube.KindNode),
					trivyoperator.LabelResourceName: "control-plane",
				},
				ResourceVersion: "1",
			},
			Report: v1alpha1.CISKubeBenchReportData{
				Scanner: v1alpha1.Scanner{
					Vendor:  "Aqua Security",
					Name:    "kube-bench",
					Version: "0.5.1",
				},
				Summary: v1alpha1.CISKubeBenchSummary{
					FailCount: 20,
					WarnCount: 10,
					InfoCount: 6,
					PassCount: 4,
				},
			},
		}, found)
	})

	t.Run("Should find CISKubeBenchReport by owner node", func(t *testing.T) {
		client := fake.NewClientBuilder().
			WithScheme(kubernetesScheme).
			WithObjects(&v1alpha1.CISKubeBenchReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "control-plane",
					ResourceVersion: "1",
					Labels: map[string]string{
						trivyoperator.LabelResourceKind: string(kube.KindNode),
						trivyoperator.LabelResourceName: "control-plane",
					},
				},
				Report: v1alpha1.CISKubeBenchReportData{
					Scanner: v1alpha1.Scanner{
						Vendor:  "Aqua Security",
						Name:    "kube-bench",
						Version: "0.5.1",
					},
					Summary: v1alpha1.CISKubeBenchSummary{
						FailCount: 10,
						WarnCount: 5,
						InfoCount: 3,
						PassCount: 2,
					},
				},
			}, &v1alpha1.CISKubeBenchReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "worker",
					ResourceVersion: "1",
					Labels: map[string]string{
						trivyoperator.LabelResourceKind: string(kube.KindNode),
						trivyoperator.LabelResourceName: "worker",
					},
				},
				Report: v1alpha1.CISKubeBenchReportData{
					Scanner: v1alpha1.Scanner{
						Vendor:  "Aqua Security",
						Name:    "kube-bench",
						Version: "0.5.1",
					},
					Summary: v1alpha1.CISKubeBenchSummary{
						FailCount: 20,
						WarnCount: 10,
						InfoCount: 6,
						PassCount: 4,
					},
				},
			}).
			Build()
		instance := kubebench.NewReadWriter(client)

		found, err := instance.FindByOwner(context.Background(), kube.ObjectRef{Name: "worker"})
		require.NoError(t, err)

		assert.Equal(t, &v1alpha1.CISKubeBenchReport{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "aquasecurity.github.io/v1alpha1",
				Kind:       "CISKubeBenchReport",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            "worker",
				ResourceVersion: "1",
				Labels: map[string]string{
					trivyoperator.LabelResourceKind: string(kube.KindNode),
					trivyoperator.LabelResourceName: "worker",
				},
			},
			Report: v1alpha1.CISKubeBenchReportData{
				Scanner: v1alpha1.Scanner{
					Vendor:  "Aqua Security",
					Name:    "kube-bench",
					Version: "0.5.1",
				},
				Summary: v1alpha1.CISKubeBenchSummary{
					FailCount: 20,
					WarnCount: 10,
					InfoCount: 6,
					PassCount: 4,
				},
			},
		}, found)
	})

}
