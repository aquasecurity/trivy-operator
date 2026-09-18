package workload_test

import (
	"testing"

	"github.com/go-logr/logr"
	ocpappsv1 "github.com/openshift/api/apps/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/workload"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

const deploymentRevisionAnnotation = "deployment.kubernetes.io/revision"

func TestSkipProcessing_ReplicaSet(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   corev1.NamespaceDefault,
			Name:        "nginx",
			Annotations: map[string]string{deploymentRevisionAnnotation: "2"},
			UID:         "734c1370-2281-4946-9b5f-940b33f3e4b8",
		},
	}
	newReplicaSet := func(name, revision string) *appsv1.ReplicaSet {
		return &appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   corev1.NamespaceDefault,
				Name:        name,
				Annotations: map[string]string{deploymentRevisionAnnotation: revision},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1",
					Kind:       "Deployment",
					Name:       deployment.Name,
					UID:        deployment.UID,
					Controller: ptr.To(true),
				}},
			},
			Spec: appsv1.ReplicaSetSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "nginx", "pod-template-hash": name},
				},
			},
		}
	}
	newPod := func(rs *appsv1.ReplicaSet) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: corev1.NamespaceDefault,
				Name:      rs.Name + "-pod",
				Labels:    rs.Spec.Selector.MatchLabels,
			},
		}
	}
	newReport := func(rs *appsv1.ReplicaSet) *v1alpha1.VulnerabilityReport {
		return &v1alpha1.VulnerabilityReport{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:   corev1.NamespaceDefault,
				Name:        "replicaset-" + rs.Name + "-nginx",
				Annotations: map[string]string{v1alpha1.TTLReportAnnotation: "24h0m0s"},
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "ReplicaSet",
					trivyoperator.LabelResourceName:      rs.Name,
					trivyoperator.LabelResourceNamespace: rs.Namespace,
				},
			},
		}
	}

	oldReplicaSet := newReplicaSet("nginx-old", "1")
	currentReplicaSet := newReplicaSet("nginx-current", "2")

	testCases := []struct {
		name        string
		replicaSet  *appsv1.ReplicaSet
		pods        []client.Object
		wantSkip    bool
		wantTTLZero bool
	}{
		{
			name:        "inactive ReplicaSet without pods is skipped and its reports are marked for deletion",
			replicaSet:  oldReplicaSet,
			wantSkip:    true,
			wantTTLZero: true,
		},
		{
			name:        "inactive ReplicaSet with pods is skipped and its reports are marked for deletion",
			replicaSet:  oldReplicaSet,
			pods:        []client.Object{newPod(oldReplicaSet)},
			wantSkip:    true,
			wantTTLZero: true,
		},
		{
			name:       "active ReplicaSet without pods is skipped and its reports are kept",
			replicaSet: currentReplicaSet,
			wantSkip:   true,
		},
		{
			name:       "active ReplicaSet with pods is processed",
			replicaSet: currentReplicaSet,
			pods:       []client.Object{newPod(currentReplicaSet)},
			wantSkip:   false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			report := newReport(tc.replicaSet)
			objects := append([]client.Object{deployment, tc.replicaSet, report}, tc.pods...)
			c := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(objects...).Build()
			or := kube.NewObjectResolver(c, &kube.CompatibleObjectMapper{})

			skip, err := workload.SkipProcessing(t.Context(), tc.replicaSet, or, true, logr.Discard(), nil)
			require.NoError(t, err)
			assert.Equal(t, tc.wantSkip, skip)

			var got v1alpha1.VulnerabilityReport
			require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(report), &got))
			wantTTL := "24h0m0s"
			if tc.wantTTLZero {
				wantTTL = "0s"
			}
			assert.Equal(t, wantTTL, got.Annotations[v1alpha1.TTLReportAnnotation])
		})
	}
}

func TestSkipProcessing_ReplicationController(t *testing.T) {
	deploymentConfig := &ocpappsv1.DeploymentConfig{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corev1.NamespaceDefault,
			Name:      "busybox",
			UID:       "c8d2a77c-9a3e-4a0e-8e5f-4a2f2e5b3d10",
		},
		Status: ocpappsv1.DeploymentConfigStatus{LatestVersion: 2},
	}
	oldReplicationController := &corev1.ReplicationController{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   corev1.NamespaceDefault,
			Name:        "busybox-1",
			Annotations: map[string]string{"openshift.io/deployment-config.latest-version": "1"},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps.openshift.io/v1",
				Kind:       "DeploymentConfig",
				Name:       deploymentConfig.Name,
				UID:        deploymentConfig.UID,
				Controller: ptr.To(true),
			}},
		},
		Spec: corev1.ReplicationControllerSpec{
			Selector: map[string]string{"deployment": "busybox-1"},
		},
	}
	report := &v1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   corev1.NamespaceDefault,
			Name:        "replicationcontroller-busybox-1-busybox",
			Annotations: map[string]string{v1alpha1.TTLReportAnnotation: "24h0m0s"},
			Labels: map[string]string{
				trivyoperator.LabelResourceKind:      "ReplicationController",
				trivyoperator.LabelResourceName:      oldReplicationController.Name,
				trivyoperator.LabelResourceNamespace: oldReplicationController.Namespace,
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).
		WithObjects(deploymentConfig, oldReplicationController, report).Build()
	or := kube.NewObjectResolver(c, &kube.CompatibleObjectMapper{})

	skip, err := workload.SkipProcessing(t.Context(), oldReplicationController, or, true, logr.Discard(), nil)
	require.NoError(t, err)
	assert.True(t, skip)

	var got v1alpha1.VulnerabilityReport
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(report), &got))
	assert.Equal(t, "0s", got.Annotations[v1alpha1.TTLReportAnnotation])
}
