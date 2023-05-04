package kube

import (
	"fmt"
	"hash"
	"hash/fnv"

	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/davecgh/go-spew/spew"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/rand"
)

const KubeSystemNamespace = "kube-system"

// GetContainerImagesFromPodSpec returns a map of container names
// to container images from the specified v1.PodSpec.
func GetContainerImagesFromPodSpec(spec corev1.PodSpec) ContainerImages {
	images := ContainerImages{}

	containers := append(spec.Containers, spec.InitContainers...)
	for _, container := range containers {
		images[container.Name] = container.Image
	}

	// ephemeral container are not the same type as Containers/InitContainers,
	// then we add it in a different loop
	for _, c := range spec.EphemeralContainers {
		images[c.Name] = c.Image
	}

	return images
}

// GetContainerImagesFromContainersList returns a map of container names
// to container images from the specified corev1.Container array.
func GetContainerImagesFromContainersList(containers []corev1.Container) ContainerImages {
	images := ContainerImages{}

	for _, container := range containers {
		images[container.Name] = container.Image
	}

	return images
}

// GetContainerImagesFromJob returns a map of container names
// to container images from the specified v1.Job.
// The mapping is encoded as JSON value of the AnnotationContainerImages
// annotation.
func GetContainerImagesFromJob(job *batchv1.Job) (ContainerImages, error) {
	var containerImagesAsJSON string
	var ok bool

	if containerImagesAsJSON, ok = job.Annotations[trivyoperator.AnnotationContainerImages]; !ok {
		return nil, fmt.Errorf("required annotation not set: %s", trivyoperator.AnnotationContainerImages)
	}
	containerImages := ContainerImages{}
	err := containerImages.FromJSON(containerImagesAsJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing annotation: %s: %w", trivyoperator.AnnotationContainerImages, err)
	}
	return containerImages, nil
}

// ComputeHash returns a hash value calculated from a given object.
// The hash will be safe encoded to avoid bad words.
func ComputeHash(obj interface{}) string {
	podSpecHasher := fnv.New32a()
	DeepHashObject(podSpecHasher, obj)
	return rand.SafeEncodeString(fmt.Sprint(podSpecHasher.Sum32()))
}

// DeepHashObject writes specified object to hash using the spew library
// which follows pointers and prints actual values of the nested objects
// ensuring the hash does not change when a pointer changes.
func DeepHashObject(hasher hash.Hash, objectToWrite interface{}) {
	hasher.Reset()
	printer := spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
	printer.Fprintf(hasher, "%#v", objectToWrite)
}
