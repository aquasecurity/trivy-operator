package kube_test

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetContainerImagesFromPodSpec(t *testing.T) {
	images := kube.GetContainerImagesFromPodSpec(corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:  "nginx",
				Image: "nginx:1.16",
			},
			{
				Name:  "sidecar",
				Image: "sidecar:1.32.7",
			},
		},
		InitContainers: []corev1.Container{
			{
				Name:  "init",
				Image: "init:1.0.0",
			},
			{
				Name:  "init2",
				Image: "init:1.0.0",
			},
		},
		EphemeralContainers: []corev1.EphemeralContainer{
			{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name:  "debug",
					Image: "debug:1.0.0",
				},
			},
		},
	}, false)
	assert.Equal(t, kube.ContainerImages{
		"nginx":   "nginx:1.16",
		"sidecar": "sidecar:1.32.7",
		"init":    "init:1.0.0",
		"init2":   "init:1.0.0",
		"debug":   "debug:1.0.0",
	}, images)
}

func TestGetContainerImagesFromContainersList(t *testing.T) {
	images := kube.GetContainerImagesFromContainersList(
		[]corev1.Container{
			{
				Name:  "nginx",
				Image: "nginx:1.16",
			},
			{
				Name:  "sidecar",
				Image: "sidecar:1.32.7",
			},
			{
				Name:  "init",
				Image: "init:1.0.0",
			},
			{
				Name:  "init2",
				Image: "init:1.0.0",
			},
			{
				Name:  "debug",
				Image: "debug:1.0.0",
			},
		},
	)
	assert.Equal(t, kube.ContainerImages{
		"nginx":   "nginx:1.16",
		"sidecar": "sidecar:1.32.7",
		"init":    "init:1.0.0",
		"init2":   "init:1.0.0",
		"debug":   "debug:1.0.0",
	}, images)
}

func TestGetContainerImagesFromJob(t *testing.T) {

	t.Run("Should return error when annotation is not set", func(t *testing.T) {
		_, err := kube.GetContainerImagesFromJob(&batchv1.Job{})
		require.EqualError(t, err, "required annotation not set: trivy-operator.container-images")
	})

	t.Run("Should return error when annotation is set but has invalid value", func(t *testing.T) {
		_, err := kube.GetContainerImagesFromJob(&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"trivy-operator.container-images": ``,
				},
			},
		})
		require.EqualError(t, err, "parsing annotation: trivy-operator.container-images: unexpected end of JSON input")
	})

	t.Run("Should return ContainerImages when annotation is set", func(t *testing.T) {
		images, err := kube.GetContainerImagesFromJob(&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"trivy-operator.container-images": `{"nginx":"nginx:1.16","sidecar":"sidecar:1.32.7"}`,
				},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, kube.ContainerImages{
			"nginx":   "nginx:1.16",
			"sidecar": "sidecar:1.32.7",
		}, images)
	})
}

func TestComputeHash(t *testing.T) {

	booleanValue1 := true
	booleanValue2 := true
	booleanValue3 := false
	booleanValue1Ptr := &booleanValue1
	booleanValue2Ptr := &booleanValue2
	booleanValue3Ptr := &booleanValue3

	t.Run("Should return the same hash when pointers change but values stay the same", func(t *testing.T) {
		spec1 := corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: booleanValue1Ptr,
			},
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:1.14.2",
				},
			},
		}

		spec2 := corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: booleanValue2Ptr,
			},
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:1.14.2",
				},
			},
		}

		assert.NotSame(t, booleanValue1Ptr, booleanValue2Ptr)
		assert.Equal(t, booleanValue1, booleanValue2)
		assert.Equal(t, kube.ComputeHash(spec1), kube.ComputeHash(spec2))
	})

	t.Run("Should return different hash when pointers point to different values", func(t *testing.T) {
		spec1 := corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: booleanValue1Ptr,
			},
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:1.14.2",
				},
			},
		}

		spec2 := corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: booleanValue2Ptr,
			},
			Containers: []corev1.Container{
				{
					Name:  "nginx",
					Image: "nginx:1.14.2",
				},
			},
		}

		assert.NotSame(t, booleanValue1Ptr, booleanValue3Ptr)
		assert.NotEqual(t, booleanValue1, booleanValue3)
		assert.Equal(t, kube.ComputeHash(spec1), kube.ComputeHash(spec2))
	})

	t.Run("Should return unique hashes", func(t *testing.T) {
		hashes := make(map[string]bool)
		for tag := 0; tag < 100; tag++ {
			hash := kube.ComputeHash(corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "nginx",
						Image: fmt.Sprintf("nginx:%d", tag),
					},
				},
			})
			hashes[hash] = true
		}
		assert.Equal(t, 100, len(hashes))
	})

}
