package kube_test

import (
	"testing"

	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	"github.com/aquasecurity/trivy-operator/pkg/docker"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewImagePullSecret(t *testing.T) {
	t.Run("should construct a new image secret with encoded data", func(t *testing.T) {
		g := NewGomegaWithT(t)

		secret, err := kube.NewImagePullSecret(metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "my-namespace",
		}, "http://index.docker.io/v1", "root", "s3cret")

		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(*secret).To(MatchFields(IgnoreExtras, Fields{
			"ObjectMeta": MatchFields(IgnoreExtras, Fields{
				"Name":      Equal("my-secret"),
				"Namespace": Equal("my-namespace"),
			}),
			"Type": Equal(corev1.SecretTypeDockerConfigJson),
			"Data": MatchAllKeys(Keys{
				".dockerconfigjson": MatchJSON(`{
  "auths": {
    "http://index.docker.io/v1": {
      "auth": "cm9vdDpzM2NyZXQ=",
      "username": "root",
      "password": "s3cret"
    }
  }
}`),
			}),
		}))
	})
}

func TestMapDockerRegistryServersToAuths(t *testing.T) {
	t.Run("should map Docker registry servers to Docker authentication credentials", func(t *testing.T) {
		g := NewGomegaWithT(t)

		auths, err := kube.MapDockerRegistryServersToAuths([]corev1.Secret{
			{
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					corev1.DockerConfigJsonKey: []byte(`{
  "auths": {
    "http://index.docker.io/v1": {
      "auth": "cm9vdDpzM2NyZXQ="
    }
  }
}`),
				},
			},
			{
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					corev1.DockerConfigJsonKey: []byte(`{
  "auths": {
    "quay.io": {
      "auth": "dXNlcjpBZG1pbjEyMzQ1"
    }
  }
}`),
				},
			},
		})
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(auths).To(MatchAllKeys(Keys{
			"index.docker.io": Equal(docker.Auth{
				Auth:     "cm9vdDpzM2NyZXQ=",
				Username: "root",
				Password: "s3cret",
			}),
			"quay.io": Equal(docker.Auth{
				Auth:     "dXNlcjpBZG1pbjEyMzQ1",
				Username: "user",
				Password: "Admin12345",
			}),
		}))
	})

	t.Run(`should skip secret of type "kubernetes.io/dockercfg"`, func(t *testing.T) {
		g := NewGomegaWithT(t)

		auths, err := kube.MapDockerRegistryServersToAuths([]corev1.Secret{
			{
				Type: corev1.SecretTypeDockercfg,
				Data: map[string][]byte{},
			},
			{
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					corev1.DockerConfigJsonKey: []byte(`{
  "auths": {
    "http://index.docker.io/v1": {
      "auth": "cm9vdDpzM2NyZXQ="
    }
  }
}`),
				},
			},
		})

		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(auths).To(MatchAllKeys(Keys{
			"index.docker.io": Equal(docker.Auth{
				Auth:     "cm9vdDpzM2NyZXQ=",
				Username: "root",
				Password: "s3cret",
			}),
		}))
	})
}

func TestMapContainerNamesToDockerAuths(t *testing.T) {
	t.Run("should map container images to Docker authentication credentials", func(t *testing.T) {
		g := NewGomegaWithT(t)

		auths, err := kube.MapContainerNamesToDockerAuths(kube.ContainerImages{
			"container-1": "docker.io/my-organization/my-app-backend:0.1.0",
			"container-2": "my-organization/my-app-frontend:0.3.2",
			"container-3": "quay.io/my-company/my-service:2.0",
		}, []corev1.Secret{
			{
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					corev1.DockerConfigJsonKey: []byte(`{
  "auths": {
    "http://index.docker.io/v1": {
      "auth": "cm9vdDpzM2NyZXQ="
    }
  }
}`),
				},
			},
			{
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					corev1.DockerConfigJsonKey: []byte(`{
  "auths": {
    "quay.io": {
      "auth": "dXNlcjpBZG1pbjEyMzQ1"
    }
  }
}`),
				},
			},
		})
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(auths).To(MatchAllKeys(Keys{
			"container-1": Equal(docker.Auth{
				Auth:     "cm9vdDpzM2NyZXQ=",
				Username: "root",
				Password: "s3cret",
			}),
			"container-2": Equal(docker.Auth{
				Auth:     "cm9vdDpzM2NyZXQ=",
				Username: "root",
				Password: "s3cret",
			}),
			"container-3": Equal(docker.Auth{
				Auth:     "dXNlcjpBZG1pbjEyMzQ1",
				Username: "user",
				Password: "Admin12345",
			}),
		}))
	})
}
