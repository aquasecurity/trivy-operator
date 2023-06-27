package kube_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	ocpappsv1 "github.com/openshift/api/apps/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestIsBuiltInWorkload(t *testing.T) {
	testCases := []struct {
		kind              string
		isBuiltInWorkload bool
	}{
		{
			kind:              "ReplicationController",
			isBuiltInWorkload: true,
		},
		{
			kind:              "ReplicaSet",
			isBuiltInWorkload: true,
		},
		{
			kind:              "StatefulSet",
			isBuiltInWorkload: true,
		},
		{
			kind:              "DaemonSet",
			isBuiltInWorkload: true,
		},
		{
			kind:              "Job",
			isBuiltInWorkload: true,
		},
		{
			kind:              "ArgoCD",
			isBuiltInWorkload: false,
		},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Should return %t when controller kind is %s", tc.isBuiltInWorkload, tc.kind), func(t *testing.T) {
			assert.Equal(t, tc.isBuiltInWorkload, kube.IsBuiltInWorkload(&metav1.OwnerReference{Kind: tc.kind}))
		})
	}
}

func TestIsWorkload(t *testing.T) {
	testCases := []struct {
		kind string
		want bool
	}{
		{
			kind: "Pod",
			want: true,
		},
		{
			kind: "Deployment",
			want: true,
		},
		{
			kind: "ReplicaSet",
			want: true,
		},
		{
			kind: "ReplicationController",
			want: true,
		},
		{
			kind: "StatefulSet",
			want: true,
		},
		{
			kind: "DaemonSet",
			want: true,
		},
		{
			kind: "Job",
			want: true,
		},
		{
			kind: "CronJob",
			want: true,
		},
		{
			kind: "ConfigMap",
			want: false,
		},
		{
			kind: "Ingress",
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.kind, func(t *testing.T) {
			assert.Equal(t, tc.want, kube.IsWorkload(tc.kind))
		})
	}
}

func TestIsClusterScopedKind(t *testing.T) {
	testCases := []struct {
		kind string
		want bool
	}{
		{
			kind: "Role",
			want: false,
		},
		{
			kind: "RoleBinding",
			want: false,
		},
		{
			kind: "ClusterRole",
			want: true,
		},
		{
			kind: "ClusterRoleBinding",
			want: true,
		},
		{
			kind: "CustomResourceDefinition",
			want: true,
		},
		{
			kind: "Pod",
			want: false,
		},
	}
	for _, tt := range testCases {
		t.Run(fmt.Sprintf("Should return %t when controller kind is %s", tt.want, tt.kind), func(t *testing.T) {
			assert.Equal(t, tt.want, kube.IsClusterScopedKind(tt.kind))
		})
	}
}

func TestObjectRefToLabels(t *testing.T) {
	testCases := []struct {
		name   string
		object kube.ObjectRef
		labels map[string]string
	}{
		{
			name: "Should map object with simple name",
			object: kube.ObjectRef{
				Kind:      kube.KindPod,
				Name:      "my-pod",
				Namespace: "production",
			},
			labels: map[string]string{
				trivyoperator.LabelResourceKind:      "Pod",
				trivyoperator.LabelResourceNamespace: "production",
				trivyoperator.LabelResourceName:      "my-pod",
			},
		},
		{
			name: "Should map object with name that is not a valid label",
			object: kube.ObjectRef{
				Kind: kube.KindClusterRole,
				Name: "system:controller:namespace-controller",
			},
			labels: map[string]string{
				trivyoperator.LabelResourceKind:      "ClusterRole",
				trivyoperator.LabelResourceNameHash:  kube.ComputeHash("system:controller:namespace-controller"),
				trivyoperator.LabelResourceNamespace: "",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.labels, kube.ObjectRefToLabels(tc.object))
		})
	}
}

func TestObjectToObjectMeta(t *testing.T) {
	testCases := []struct {
		name     string
		meta     metav1.ObjectMeta
		object   client.Object
		expected metav1.ObjectMeta
	}{
		{
			name: "Should map object with simple name",
			meta: metav1.ObjectMeta{},
			object: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Pod",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-pod",
					Namespace: "production",
				},
			},
			expected: metav1.ObjectMeta{
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "Pod",
					trivyoperator.LabelResourceName:      "my-pod",
					trivyoperator.LabelResourceNamespace: "production",
				},
			},
		},
		{
			name: "Should map object with name that is not a valid label",
			meta: metav1.ObjectMeta{},
			object: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "rbac.authorization.k8s.io/v1",
					Kind:       "ClusterRole",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "system:controller:node-controller",
				},
			},
			expected: metav1.ObjectMeta{
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "ClusterRole",
					trivyoperator.LabelResourceNameHash:  kube.ComputeHash("system:controller:node-controller"),
					trivyoperator.LabelResourceNamespace: "",
				},
				Annotations: map[string]string{
					trivyoperator.LabelResourceName: "system:controller:node-controller",
				},
			},
		},
		{
			name: "Should map object and merge labels and annotations",
			meta: metav1.ObjectMeta{
				Labels: map[string]string{
					"foo": "bar",
				},
				Annotations: map[string]string{
					"kee": "pass",
				},
			},
			object: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "rbac.authorization.k8s.io/v1",
					Kind:       "ClusterRole",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "system:controller:node-controller",
				},
			},
			expected: metav1.ObjectMeta{
				Labels: map[string]string{
					"foo": "bar",

					trivyoperator.LabelResourceKind:      "ClusterRole",
					trivyoperator.LabelResourceNameHash:  kube.ComputeHash("system:controller:node-controller"),
					trivyoperator.LabelResourceNamespace: "",
				},
				Annotations: map[string]string{
					"kee": "pass",

					trivyoperator.LabelResourceName: "system:controller:node-controller",
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := kube.ObjectToObjectMeta(tc.object, &tc.meta)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, tc.meta)
		})
	}
}

func TestContainerImages_AsJSON_And_FromJSON(t *testing.T) {
	containerImages := kube.ContainerImages{
		"nginx": "nginx:1.16",
		"redis": "core.harbor.domain:8443/library/redis:5",
	}
	value, err := containerImages.AsJSON()
	require.NoError(t, err)

	newContainerImages := kube.ContainerImages{}
	err = newContainerImages.FromJSON(value)
	require.NoError(t, err)
	assert.Equal(t, containerImages, newContainerImages)
}

func TestObjectRefFromKindAndObjectKey(t *testing.T) {
	partial := kube.ObjectRefFromKindAndObjectKey(kube.KindReplicaSet, client.ObjectKey{
		Namespace: "prod",
		Name:      "wordpress",
	})
	assert.Equal(t, kube.ObjectRef{
		Kind:      kube.KindReplicaSet,
		Name:      "wordpress",
		Namespace: "prod",
	}, partial)
}

func TestGetPodSpec(t *testing.T) {
	testCases := []struct {
		name            string
		object          client.Object
		expectedPodSpec corev1.PodSpec
		expectedError   string
	}{
		{
			name: "Should return PodSpec for Pod",
			object: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "pod",
							Image: "pod:1.3",
						},
					},
				},
			},
			expectedPodSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "pod",
						Image: "pod:1.3",
					},
				},
			},
		},
		{
			name: "Should return PodSpec for Deployment",
			object: &appsv1.Deployment{
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "deployment",
									Image: "deployment:2.4",
								},
							},
						},
					},
				},
			},
			expectedPodSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "deployment",
						Image: "deployment:2.4",
					},
				},
			},
		},
		{
			name: "Should return PodSpec for ReplicaSet",
			object: &appsv1.ReplicaSet{
				Spec: appsv1.ReplicaSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "replicaset",
									Image: "replicaset:3.17",
								},
							},
						},
					},
				},
			},
			expectedPodSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "replicaset",
						Image: "replicaset:3.17",
					},
				},
			},
		},
		{
			name: "Should return PodSpec for ReplicationController",
			object: &corev1.ReplicationController{
				Spec: corev1.ReplicationControllerSpec{
					Template: &corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "replicationcontroller",
									Image: "replicationcontroller:latest",
								},
							},
						},
					},
				},
			},
			expectedPodSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "replicationcontroller",
						Image: "replicationcontroller:latest",
					},
				},
			},
		},
		{
			name: "Should return PodSpec for StatefulSet",
			object: &appsv1.StatefulSet{
				Spec: appsv1.StatefulSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "statefulset",
									Image: "statefulset:8",
								},
							},
						},
					},
				},
			},
			expectedPodSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "statefulset",
						Image: "statefulset:8",
					},
				},
			},
		},
		{
			name: "Should return PodSpec for DaemonSet",
			object: &appsv1.DaemonSet{
				Spec: appsv1.DaemonSetSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "daemonset",
									Image: "daemonset:1.1",
								},
							},
						},
					},
				},
			},
			expectedPodSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "daemonset",
						Image: "daemonset:1.1",
					},
				},
			},
		},
		{
			name: "Should return PodSpec for CronJob",
			object: &batchv1beta1.CronJob{
				Spec: batchv1beta1.CronJobSpec{
					JobTemplate: batchv1beta1.JobTemplateSpec{
						Spec: batchv1.JobSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									Containers: []corev1.Container{
										{
											Name:  "cronjob",
											Image: "cronjob:5",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedPodSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "cronjob",
						Image: "cronjob:5",
					},
				},
			},
		},
		{
			name: "Should return PodSpec for CronJob",
			object: &batchv1.CronJob{
				Spec: batchv1.CronJobSpec{
					JobTemplate: batchv1.JobTemplateSpec{
						Spec: batchv1.JobSpec{
							Template: corev1.PodTemplateSpec{
								Spec: corev1.PodSpec{
									Containers: []corev1.Container{
										{
											Name:  "cronjob",
											Image: "cronjob:5",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedPodSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "cronjob",
						Image: "cronjob:5",
					},
				},
			},
		},
		{
			name: "Should return PodSpec for Job",
			object: &batchv1.Job{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "job",
									Image: "job:2.8.2",
								},
							},
						},
					},
				},
			},
			expectedPodSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "job",
						Image: "job:2.8.2",
					},
				},
			},
		},
		{
			name:          "Should return error for Service",
			object:        &corev1.Service{},
			expectedError: "unsupported workload: *v1.Service",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			podSpec, err := kube.GetPodSpec(tc.object)
			if tc.expectedError != "" {
				require.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedPodSpec, podSpec)
			}

		})
	}
}

func TestObjectResolver_RelatedReplicaSetName(t *testing.T) {
	kubClient := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx",
				Namespace: corev1.NamespaceDefault,
				Labels: map[string]string{
					"app": "nginx",
				},
				Annotations: map[string]string{
					"deployment.kubernetes.io/revision": "2",
				},
			},
			Spec: appsv1.DeploymentSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": "nginx",
					},
				},
			},
		},
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-7ff78f74b9",
				Namespace: corev1.NamespaceDefault,
				Labels: map[string]string{
					"app":               "nginx",
					"pod-template-hash": "7ff78f74b9",
				},
				Annotations: map[string]string{
					"deployment.kubernetes.io/revision": "1",
				},
			},
			Spec: appsv1.ReplicaSetSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app":               "nginx",
						"pod-template-hash": "7ff78f74b9",
					},
				},
			},
		},
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-549f5fcb58",
				Namespace: corev1.NamespaceDefault,
				Labels: map[string]string{
					"app":               "nginx",
					"pod-template-hash": "549f5fcb58",
				},
				Annotations: map[string]string{
					"deployment.kubernetes.io/revision": "2",
				},
			},
			Spec: appsv1.ReplicaSetSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app":               "nginx",
						"pod-template-hash": "549f5fcb58",
					},
				},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nginx-549f5fcb58-7cr5b",
				Namespace: corev1.NamespaceDefault,
				Labels: map[string]string{
					"app":               "nginx",
					"pod-hash-template": "549f5fcb58",
				},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "apps/v1",
						Kind:               "ReplicaSet",
						Name:               "nginx-549f5fcb58",
						Controller:         pointer.Bool(true),
						BlockOwnerDeletion: pointer.Bool(true),
					},
				},
			},
		},
	).Build()
	instance := kube.NewObjectResolver(kubClient, &kube.CompatibleObjectMapper{})

	t.Run("Should return error for unsupported kind", func(t *testing.T) {
		_, err := instance.RelatedReplicaSetName(context.Background(), kube.ObjectRef{
			Kind:      kube.KindStatefulSet,
			Name:      "statefulapp",
			Namespace: corev1.NamespaceDefault,
		})
		require.EqualError(t, err, "can only get related ReplicaSet for Deployment or Pod, not \"StatefulSet\"")
	})

	t.Run("Should return ReplicaSet name for the specified Deployment", func(t *testing.T) {
		name, err := instance.RelatedReplicaSetName(context.Background(), kube.ObjectRef{
			Kind:      kube.KindDeployment,
			Name:      "nginx",
			Namespace: corev1.NamespaceDefault,
		})
		require.NoError(t, err)
		assert.Equal(t, "nginx-549f5fcb58", name)
	})

	t.Run("Should return ReplicaSet name for the specified Deployment", func(t *testing.T) {
		name, err := instance.RelatedReplicaSetName(context.Background(), kube.ObjectRef{
			Kind:      kube.KindPod,
			Name:      "nginx-549f5fcb58-7cr5b",
			Namespace: corev1.NamespaceDefault,
		})
		require.NoError(t, err)
		assert.Equal(t, "nginx-549f5fcb58", name)
	})

}

func TestObjectRefFromObjectMeta(t *testing.T) {
	testCases := []struct {
		name          string
		object        metav1.ObjectMeta
		expected      kube.ObjectRef
		expectedError string
	}{
		{
			name: "Test Role",
			object: metav1.ObjectMeta{
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "Role",
					trivyoperator.LabelResourceNamespace: "kube-system",
					trivyoperator.LabelResourceNameHash:  kube.ComputeHash("system:admin"),
				},
				Annotations: map[string]string{
					trivyoperator.LabelResourceName: "system:admin",
				},
			},
			expected: kube.ObjectRef{Kind: kube.KindRole, Name: "system:admin", Namespace: "kube-system"},
		},
		{
			name: "Test RoleBinding",
			object: metav1.ObjectMeta{
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "RoleBinding",
					trivyoperator.LabelResourceNamespace: "kube-system",
					trivyoperator.LabelResourceNameHash:  kube.ComputeHash("system:admin:binding"),
				},
				Annotations: map[string]string{
					trivyoperator.LabelResourceName: "system:admin:binding",
				},
			},
			expected: kube.ObjectRef{Kind: kube.KindRoleBinding, Name: "system:admin:binding", Namespace: "kube-system"},
		},
		{
			name: "Kind ClusterRole",
			object: metav1.ObjectMeta{
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "ClusterRole",
					trivyoperator.LabelResourceNamespace: "",
					trivyoperator.LabelResourceNameHash:  kube.ComputeHash("system:netnode"),
				},
				Annotations: map[string]string{
					trivyoperator.LabelResourceName: "system:netnode",
				},
			},
			expected: kube.ObjectRef{Kind: kube.KindClusterRole, Name: "system:netnode"},
		},
		{
			name: "Kind ClusterRoleBinding",
			object: metav1.ObjectMeta{
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "ClusterRoleBinding",
					trivyoperator.LabelResourceNamespace: "",
					trivyoperator.LabelResourceNameHash:  kube.ComputeHash("system:netnode:binding"),
				},
				Annotations: map[string]string{
					trivyoperator.LabelResourceName: "system:netnode:binding",
				},
			},
			expected: kube.ObjectRef{Kind: kube.KindClusterRoleBindings, Name: "system:netnode:binding"},
		},
		{
			name: "Kind Pod",
			object: metav1.ObjectMeta{
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "Pod",
					trivyoperator.LabelResourceNamespace: "default",
					trivyoperator.LabelResourceName:      "nginx-pod",
				},
			},
			expected: kube.ObjectRef{Kind: kube.KindPod, Name: "nginx-pod", Namespace: "default"},
		},
		{
			name: "Kind Deployment",
			object: metav1.ObjectMeta{
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "Deployment",
					trivyoperator.LabelResourceNamespace: "default",
					trivyoperator.LabelResourceName:      "nginx-deployment",
				},
			},
			expected: kube.ObjectRef{Kind: kube.KindDeployment, Name: "nginx-deployment", Namespace: "default"},
		},
		{
			name: "Kind DaemonSet",
			object: metav1.ObjectMeta{
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "DaemonSet",
					trivyoperator.LabelResourceNamespace: "default",
					trivyoperator.LabelResourceName:      "nginx-ds",
				},
			},
			expected: kube.ObjectRef{Kind: kube.KindDaemonSet, Name: "nginx-ds", Namespace: "default"},
		},
		{
			name: fmt.Sprintf("Should return error when %s label is missing", trivyoperator.LabelResourceKind),
			object: metav1.ObjectMeta{
				Labels: map[string]string{
					trivyoperator.LabelResourceName:      "nginx",
					trivyoperator.LabelResourceNamespace: "default",
				},
			},
			expectedError: "required label does not exist: trivy-operator.resource.kind",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := kube.ObjectRefFromObjectMeta(tc.object)
			if tc.expectedError == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, actual)
			} else {
				require.EqualError(t, err, tc.expectedError)
			}
		})
	}

}

func TestGetActivePodsMatchingLabels(t *testing.T) {
	nginxReplicaSet := &appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "ReplicaSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corev1.NamespaceDefault,
			Name:      "nginx-6d4cf56db6",
			Labels: map[string]string{
				"app":               "nginx",
				"pod-template-hash": "6d4cf56db6",
			},
			Annotations: map[string]string{
				"deployment.kubernetes.io/desired-replicas": "1",
				"deployment.kubernetes.io/max-replicas":     "4",
				"deployment.kubernetes.io/revision":         "1",
			},
			UID: "ecfff877-784c-4f05-8b70-abe441ca1976",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "apps/v1",
					Kind:               "Deployment",
					Name:               "nginx",
					UID:                "734c1370-2281-4946-9b5f-940b33f3e4b8",
					Controller:         pointer.Bool(true),
					BlockOwnerDeletion: pointer.Bool(true),
				},
			},
		},
		Spec: appsv1.ReplicaSetSpec{
			Replicas: pointer.Int32(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":               "nginx",
					"pod-template-hash": "6d4cf56db6",
				},
			},
		},
	}
	nginxPod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corev1.NamespaceDefault,
			Name:      "nginx-6d4cf56db6-4kw2v",
			Labels: map[string]string{
				"app":               "nginx",
				"pod-template-hash": "6d4cf56db6",
			},
			UID: "44ca7a2a-29c5-4510-b503-0218bc9d3308",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "apps/v1",
					Kind:               "ReplicaSet",
					Name:               "nginx-6d4cf56db6",
					UID:                "ecfff877-784c-4f05-8b70-abe441ca1976",
					Controller:         pointer.Bool(true),
					BlockOwnerDeletion: pointer.Bool(true),
				},
			},
		},
	}

	testClient := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(
		nginxReplicaSet,
		nginxPod,
	).Build()

	t.Run("found active pods", func(t *testing.T) {
		ctx := context.TODO()
		or := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		pods, err := or.GetActivePodsMatchingLabels(ctx, nginxReplicaSet.Namespace, nginxReplicaSet.GetLabels())
		assert.NoError(t, err)
		assert.Equal(t, len(pods), 1)
	})
	t.Run("active pods not found", func(t *testing.T) {
		ctx := context.TODO()
		or := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
		pods, err := or.GetActivePodsMatchingLabels(ctx, nginxReplicaSet.Namespace, map[string]string{
			"app":               "nginx",
			"pod-template-hash": "6d4cf56db5"})
		assert.Equal(t, err, kube.ErrNoRunningPods)
		assert.Equal(t, len(pods), 0)
	})
}

func TestObjectResolver_ReportOwner(t *testing.T) {
	nginxDeploy := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corev1.NamespaceDefault,
			Name:      "nginx",
			Labels: map[string]string{
				"app": "nginx",
			},
			Annotations: map[string]string{
				"deployment.kubernetes.io/revision": "1",
			},
			UID: "734c1370-2281-4946-9b5f-940b33f3e4b8",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: pointer.Int32(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "nginx",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: corev1.NamespaceDefault,
					Name:      "nginx",
					Labels: map[string]string{
						"app": "nginx",
					},
					Annotations: map[string]string{
						"deployment.kubernetes.io/revision": "1",
					},
				},
			},
		},
	}
	nginxReplicaSet := &appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "ReplicaSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corev1.NamespaceDefault,
			Name:      "nginx-6d4cf56db6",
			Labels: map[string]string{
				"app":               "nginx",
				"pod-template-hash": "6d4cf56db6",
			},
			Annotations: map[string]string{
				"deployment.kubernetes.io/desired-replicas": "1",
				"deployment.kubernetes.io/max-replicas":     "4",
				"deployment.kubernetes.io/revision":         "1",
			},
			UID: "ecfff877-784c-4f05-8b70-abe441ca1976",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "apps/v1",
					Kind:               "Deployment",
					Name:               "nginx",
					UID:                "734c1370-2281-4946-9b5f-940b33f3e4b8",
					Controller:         pointer.Bool(true),
					BlockOwnerDeletion: pointer.Bool(true),
				},
			},
		},
		Spec: appsv1.ReplicaSetSpec{
			Replicas: pointer.Int32(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":               "nginx",
					"pod-template-hash": "6d4cf56db6",
				},
			},
		},
	}
	nginxPod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corev1.NamespaceDefault,
			Name:      "nginx-6d4cf56db6-4kw2v",
			Labels: map[string]string{
				"app":               "nginx",
				"pod-template-hash": "6d4cf56db6",
			},
			UID: "44ca7a2a-29c5-4510-b503-0218bc9d3308",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "apps/v1",
					Kind:               "ReplicaSet",
					Name:               "nginx-6d4cf56db6",
					UID:                "ecfff877-784c-4f05-8b70-abe441ca1976",
					Controller:         pointer.Bool(true),
					BlockOwnerDeletion: pointer.Bool(true),
				},
			},
		},
	}

	unmanagedPod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corev1.NamespaceDefault,
			Name:      "unmanaged",
			Labels: map[string]string{
				"run": "unmanaged",
			},
			UID: "10641566-209e-4e4d-ac58-a3f3895e0045",
		},
	}

	piJob := &batchv1.Job{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "batch/v1",
			Kind:       "Job",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corev1.NamespaceDefault,
			Name:      "pi",
			UID:       "ef340242-b677-485e-b506-2ac1dde48bca",
			Labels: map[string]string{
				"controller-uid": "ef340242-b677-485e-b506-2ac1dde48bca",
				"job-name":       "pi",
			},
		},
		Spec: batchv1.JobSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"controller-uid": "ef340242 - b677 - 485e-b506-2ac1dde48bca",
				},
			},
		},
	}
	piPod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corev1.NamespaceDefault,
			Name:      "pi-wnbbm",
			Labels: map[string]string{
				"controller-uid": "ef340242-b677-485e-b506-2ac1dde48bca",
				"job-name":       "pi",
			},
			UID: "3921e0cd-1852-4c1d-ab0a-9721f3f28276",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "batch/v1",
					Kind:               "Job",
					Name:               "pi",
					UID:                "ef340242-b677-485e-b506-2ac1dde48bca",
					Controller:         pointer.Bool(true),
					BlockOwnerDeletion: pointer.Bool(true),
				},
			},
		},
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corev1.NamespaceDefault,
			Name:      "test-config",
		},
		Data: map[string]string{
			"foo": "bar",
		},
	}

	testClient := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(
		nginxDeploy,
		nginxReplicaSet,
		nginxPod,
		unmanagedPod,
		piJob,
		piPod,
		cm,
	).Build()

	testCases := []struct {
		name     string
		resource client.Object
		owner    client.Object
	}{
		{
			name:     "Should return ReplicaSet for Deployment",
			resource: nginxDeploy,
			owner:    nginxReplicaSet,
		},
		{
			name:     "Should return ReplicaSet for ReplicaSet",
			resource: nginxReplicaSet,
			owner:    nginxReplicaSet,
		},
		{
			name:     "Should return ReplicaSet for Pod",
			resource: nginxPod,
			owner:    nginxReplicaSet,
		},
		{
			name:     "Should return Pod for unmanaged Pod",
			resource: unmanagedPod,
			owner:    unmanagedPod,
		},
		{
			name:     "Should return Job for unmanaged Job",
			resource: piJob,
			owner:    piJob,
		},
		{
			name:     "Should return Job for Pod",
			resource: piPod,
			owner:    piJob,
		},
		{
			name:     "Should return ConfigMap for ConfigMap",
			resource: cm,
			owner:    cm,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			or := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
			owner, err := or.ReportOwner(context.TODO(), tc.resource)
			require.NoError(t, err)
			assert.Equal(t, tc.owner, owner)
		})
	}
}

func TestObjectResolver_IsActiveReplicaSet(t *testing.T) {
	nginxDeploy := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corev1.NamespaceDefault,
			Name:      "nginx",
			Labels: map[string]string{
				"app": "nginx",
			},
			Annotations: map[string]string{
				"deployment.kubernetes.io/revision": "1",
			},
			UID: "734c1370-2281-4946-9b5f-940b33f3e4b8",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: pointer.Int32(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "nginx",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: corev1.NamespaceDefault,
					Name:      "nginx",
					Labels: map[string]string{
						"app": "nginx",
					},
					Annotations: map[string]string{
						"deployment.kubernetes.io/revision": "1",
					},
				},
			},
		},
	}
	nginxReplicaSet := &appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "ReplicaSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corev1.NamespaceDefault,
			Name:      "nginx-6d4cf56db6",
			Labels: map[string]string{
				"app":               "nginx",
				"pod-template-hash": "6d4cf56db6",
			},
			Annotations: map[string]string{
				"deployment.kubernetes.io/desired-replicas": "1",
				"deployment.kubernetes.io/max-replicas":     "4",
				"deployment.kubernetes.io/revision":         "1",
			},
			UID: "ecfff877-784c-4f05-8b70-abe441ca1976",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "apps/v1",
					Kind:               "Deployment",
					Name:               "nginx",
					UID:                "734c1370-2281-4946-9b5f-940b33f3e4b8",
					Controller:         pointer.Bool(true),
					BlockOwnerDeletion: pointer.Bool(true),
				},
			},
		},
		Spec: appsv1.ReplicaSetSpec{
			Replicas: pointer.Int32(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":               "nginx",
					"pod-template-hash": "6d4cf56db6",
				},
			},
		},
	}
	notActiveNginxReplicaSet := &appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "ReplicaSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corev1.NamespaceDefault,
			Name:      "nginx-f88799b98",
			Labels: map[string]string{
				"app":               "nginx",
				"pod-template-hash": "f88799b98",
			},
			Annotations: map[string]string{
				"deployment.kubernetes.io/desired-replicas": "1",
				"deployment.kubernetes.io/max-replicas":     "4",
				"deployment.kubernetes.io/revision":         "2",
			},
			UID: "6fd87db4-d557-4b84-92b7-653c3f4e5c7d",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "apps/v1",
					Kind:               "Deployment",
					Name:               "nginx",
					UID:                "734c1370-2281-4946-9b5f-940b33f3e4b8",
					Controller:         pointer.Bool(true),
					BlockOwnerDeletion: pointer.Bool(true),
				},
			},
		},
		Spec: appsv1.ReplicaSetSpec{
			Replicas: pointer.Int32(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":               "nginx",
					"pod-template-hash": "f88799b98",
				},
			},
		},
	}
	standAloneNginxReplicaSet := &appsv1.ReplicaSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "ReplicaSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corev1.NamespaceDefault,
			Name:      "nginx-d54df7dc7",
			Labels: map[string]string{
				"app":               "nginx",
				"pod-template-hash": "d54df7dc7",
			},
			Annotations: map[string]string{
				"deployment.kubernetes.io/desired-replicas": "1",
				"deployment.kubernetes.io/max-replicas":     "4",
			},
			UID: "0eed5ccf-4518-4ae7-933e-cafded6cf356",
		},
		Spec: appsv1.ReplicaSetSpec{
			Replicas: pointer.Int32(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":               "nginx",
					"pod-template-hash": "d54df7dc7",
				},
			},
		},
	}
	testClient := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(
		nginxDeploy,
		nginxReplicaSet,
		notActiveNginxReplicaSet,
	).Build()
	testCases := []struct {
		name     string
		resource *appsv1.ReplicaSet
		result   bool
	}{
		{
			name:     "activeReplicaset",
			resource: nginxReplicaSet,
			result:   true,
		},
		{
			name:     "noneActiveReplicaset",
			resource: notActiveNginxReplicaSet,
			result:   false,
		},
		{
			name:     "standAloneReplicaset",
			resource: standAloneNginxReplicaSet,
			result:   true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			or := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
			controller := metav1.GetControllerOf(tc.resource)
			isActive, err := or.IsActiveReplicaSet(context.TODO(), tc.resource, controller)
			require.NoError(t, err)
			assert.Equal(t, isActive, tc.result)
		})
	}
}

func TestObjectResolver_IsActiveReplicationController(t *testing.T) {
	busyboxDeploymentConfig := &ocpappsv1.DeploymentConfig{
		TypeMeta: metav1.TypeMeta{
			Kind:       "DeploymentConfig",
			APIVersion: "apps.openshift.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            "busybox",
			Namespace:       "test",
			UID:             "3767b9a7-c2ad-4a3e-a115-b72edda9084b",
			ResourceVersion: "212822",
			Generation:      3,
		},
		Spec: ocpappsv1.DeploymentConfigSpec{
			Strategy: ocpappsv1.DeploymentStrategy{
				Type: "Recreate",
			},
			MinReadySeconds: 0,
			Triggers:        nil,
			Replicas:        1,
			Test:            false,
			Paused:          false,
			Selector:        map[string]string{"deploymentconfig": "busybox"},
			Template: &corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"deploymentconfig": "busybox"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{corev1.Container{
						Name:    "busybox",
						Image:   "busybox",
						Command: []string{"/bin/sh", "-c", "while true ; do date; sleep 1; done;"},
					}},
				},
			},
		},
		Status: ocpappsv1.DeploymentConfigStatus{
			LatestVersion:       3,
			ObservedGeneration:  3,
			Replicas:            1,
			UpdatedReplicas:     1,
			AvailableReplicas:   1,
			UnavailableReplicas: 0,
			ReadyReplicas:       1,
		},
	}

	busyboxReplicaController := &corev1.ReplicationController{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ReplicationController",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            "busybox-3",
			Namespace:       "test",
			UID:             "69f2c92a-3032-4b7a-ba60-63be0bffdbe5",
			ResourceVersion: "212821",
			Generation:      2,
			Labels:          map[string]string{"openshift.io/deployment-config.name": "busybox"},
			Annotations: map[string]string{
				"openshift.io/deployer-pod.completed-at":        "2023-05-25 06:57:18 +0000 UTC",
				"openshift.io/deployer-pod.created-at":          "2023-05-25 06:56:39 +0000 UTC",
				"openshift.io/deployer-pod.name":                "busybox-3-deploy",
				"openshift.io/deployment-config.latest-version": "3",
				"openshift.io/deployment-config.name":           "busybox",
				"openshift.io/deployment.phase":                 "Complete",
				"openshift.io/deployment.replicas":              "1",
				"openshift.io/deployment.status-reason":         "config change",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion:         "apps.openshift.io/v1",
				Kind:               "DeploymentConfig",
				Name:               "busybox",
				UID:                "3767b9a7-c2ad-4a3e-a115-b72edda9084b",
				Controller:         pointer.Bool(true),
				BlockOwnerDeletion: pointer.Bool(true)},
			},
		},
		Spec: corev1.ReplicationControllerSpec{
			Replicas: pointer.Int32(1),
			Selector: map[string]string{
				"deployment":       "busybox-3",
				"deploymentconfig": "busybox",
			},
			Template: &corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"deploymentconfig": "busybox"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{corev1.Container{
						Name:    "busybox",
						Image:   "busybox",
						Command: []string{"/bin/sh", "-c", "while true ; do date; sleep 1; done;"},
					}},
				},
			},
		},
		Status: corev1.ReplicationControllerStatus{},
	}

	notActivebusyboxReplicaController := &corev1.ReplicationController{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ReplicationController",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            "busybox-2",
			Namespace:       "test",
			UID:             "69f2c92a-3032-4b7a-ba60-63be0bffdbe5",
			ResourceVersion: "212821",
			Generation:      1,
			Labels:          map[string]string{"openshift.io/deployment-config.name": "busybox"},
			Annotations: map[string]string{
				"openshift.io/deployer-pod.completed-at":        "2023-05-25 06:57:18 +0000 UTC",
				"openshift.io/deployer-pod.created-at":          "2023-05-25 06:56:39 +0000 UTC",
				"openshift.io/deployer-pod.name":                "busybox-3-deploy",
				"openshift.io/deployment-config.latest-version": "2",
				"openshift.io/deployment-config.name":           "busybox",
				"openshift.io/deployment.phase":                 "Complete",
				"openshift.io/deployment.replicas":              "1",
				"openshift.io/deployment.status-reason":         "config change",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion:         "apps.openshift.io/v1",
				Kind:               "DeploymentConfig",
				Name:               "busybox",
				UID:                "3767b9a7-c2ad-4a3e-a115-b72edda9084b",
				Controller:         pointer.Bool(true),
				BlockOwnerDeletion: pointer.Bool(true)},
			},
		},
		Spec: corev1.ReplicationControllerSpec{
			Replicas: pointer.Int32(1),
			Selector: map[string]string{
				"deployment":       "busybox-2",
				"deploymentconfig": "busybox",
			},
			Template: &corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"deploymentconfig": "busybox"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{corev1.Container{
						Name:    "busybox",
						Image:   "busybox",
						Command: []string{"/bin/sh", "-c", "while true ; do date; sleep 1; done;"},
					}},
				},
			},
		},
		Status: corev1.ReplicationControllerStatus{},
	}

	standalonebusyboxReplicaController := &corev1.ReplicationController{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ReplicationController",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:            "busybox-3",
			Namespace:       "test",
			UID:             "69f2c92a-3032-4b7a-ba60-63be0bffdbe5",
			ResourceVersion: "212821",
			Generation:      2,
			Labels:          map[string]string{"openshift.io/deployment-config.name": "busybox"},
		},
		Spec: corev1.ReplicationControllerSpec{
			Replicas: pointer.Int32(1),
			Selector: map[string]string{
				"deployment":       "busybox-3",
				"deploymentconfig": "busybox",
			},
			Template: &corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"deploymentconfig": "busybox"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{corev1.Container{
						Name:    "busybox",
						Image:   "busybox",
						Command: []string{"/bin/sh", "-c", "while true ; do date; sleep 1; done;"},
					}},
				},
			},
		},
		Status: corev1.ReplicationControllerStatus{},
	}
	testClient := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(
		busyboxDeploymentConfig,
		busyboxReplicaController,
		notActivebusyboxReplicaController,
	).Build()
	tests := []struct {
		name     string
		resource *corev1.ReplicationController
		result   bool
	}{
		{
			name:     "active Replication Controller",
			resource: busyboxReplicaController,
			result:   true,
		},
		{
			name:     "Non active replication controller",
			resource: notActivebusyboxReplicaController,
			result:   false,
		},
		{
			name:     "Standalone replication controller",
			resource: standalonebusyboxReplicaController,
			result:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			or := kube.NewObjectResolver(testClient, &kube.CompatibleObjectMapper{})
			controller := metav1.GetControllerOf(tc.resource)
			isActive, err := or.IsActiveReplicationController(context.TODO(), tc.resource, controller)
			require.NoError(t, err)
			assert.Equal(t, isActive, tc.result)
		})
	}
}

func TestIsRoleTypes(t *testing.T) {
	testCases := []struct {
		kind string
		want bool
	}{
		{
			kind: "Role",
			want: true,
		},
		{
			kind: "ClusterRole",
			want: true,
		},
		{
			kind: "Pod",
			want: false,
		},
	}
	for _, tt := range testCases {
		t.Run(fmt.Sprintf("Should return %t when  kind is %s", tt.want, tt.kind), func(t *testing.T) {
			assert.Equal(t, tt.want, kube.IsRoleTypes(kube.Kind(tt.kind)))
		})
	}
}

func TestIsValidK8sKinds(t *testing.T) {
	testCases := []struct {
		kind string
		want bool
	}{
		{
			kind: "Pod",
			want: true,
		},
		{
			kind: "ClusterRole",
			want: true,
		},
		{
			kind: "Deployment",
			want: true,
		},
		{
			kind: "ReplicationController",
			want: true,
		},
		{
			kind: "StatefulSet",
			want: true,
		},
		{
			kind: "Job",
			want: true,
		},
		{
			kind: "Deployment",
			want: true,
		},
		{
			kind: "CronJob",
			want: true,
		},
		{
			kind: "CustomResourceDefinition",
			want: true,
		},
		{
			kind: "Test",
			want: false,
		},
	}
	for _, tt := range testCases {
		t.Run(fmt.Sprintf("Should return %t when kind is %s", tt.want, tt.kind), func(t *testing.T) {
			assert.Equal(t, tt.want, kube.IsValidK8sKind(tt.kind))
		})
	}
}

func TestIsRoleRelatedNamespaceScope(t *testing.T) {
	testCases := []struct {
		kind string
		want bool
	}{
		{
			kind: "Role",
			want: true,
		},
		{
			kind: "ClusterRole",
			want: false,
		},
		{
			kind: "RoleBinding",
			want: true,
		},
	}
	for _, tt := range testCases {
		t.Run(fmt.Sprintf("Should return %t when  kind is %s", tt.want, tt.kind), func(t *testing.T) {
			assert.Equal(t, tt.want, kube.IsRoleRelatedNamespaceScope(kube.Kind(tt.kind)))
		})
	}
}
