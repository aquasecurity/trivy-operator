package kube_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"

	"github.com/aquasecurity/trivy-operator/pkg/docker"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	corev1 "k8s.io/api/core/v1"
)

func TestMapDockerRegistryServersToAuths(t *testing.T) {
	t.Run("should map Docker registry servers to Docker authentication credentials", func(t *testing.T) {
		g := NewGomegaWithT(t)

		auths, wildcardServers, err := kube.MapDockerRegistryServersToAuths([]corev1.Secret{
			{
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					corev1.DockerConfigJsonKey: []byte(`{
  "auths": {
        "http://*.docker.io/v1": {
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
		assert.Equal(t, len(wildcardServers), 1)
		g.Expect(auths).To(MatchAllKeys(Keys{
			"*.docker.io": Equal(docker.Auth{
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

		auths, wildcardServers, err := kube.MapDockerRegistryServersToAuths([]corev1.Secret{
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
		assert.Equal(t, len(wildcardServers), 0)
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
	t.Run("should map container images to Docker authentication credentials where server has wildcard prefixed", func(t *testing.T) {
		g := NewGomegaWithT(t)

		auths, err := kube.MapContainerNamesToDockerAuths(kube.ContainerImages{
			"container-1": "tes.jfrog.com/my-organization/my-app-backend:0.1.0",
		}, []corev1.Secret{
			{
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					corev1.DockerConfigJsonKey: []byte(`{
  "auths": {
    "http://*.jfrog.com": {
      "auth": "cm9vdDpzM2NyZXQ="
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
		}))
	})
}

func TestListImagePullSecretsByPodSpec(t *testing.T) {
	t.Run("Test no error when service account not found", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).Build()
		spec := corev1.PodSpec{}
		sr := kube.NewSecretsReader(client)
		foundsecret, err := sr.ListImagePullSecretsByPodSpec(context.Background(), spec, "default")
		require.NoError(t, err)
		assert.True(t, len(foundsecret) == 0)
	})

	t.Run("Test with no service account but with one secrets should return one pull image secret from corev1.Secret", func(t *testing.T) {
		var secret corev1.Secret
		err := loadResource("./testdata/fixture/secret.json", &secret)
		require.NoError(t, err)
		var sa corev1.ServiceAccount
		err = loadResource("./testdata/fixture/sa_without_image_pull_secret.json", &sa)
		require.NoError(t, err)
		client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(&secret).WithObjects(&sa).Build()
		sr := kube.NewSecretsReader(client)
		spec := corev1.PodSpec{ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}, {Name: "notexist"}}, ServiceAccountName: "default"}
		foundsecret, err := sr.ListImagePullSecretsByPodSpec(context.Background(), spec, "default")
		require.NoError(t, err)
		assert.True(t, len(foundsecret) == 1)
	})

	t.Run("Test with service account and no secret should return one pull image secret from corev1.ServiceAccount", func(t *testing.T) {
		var secret corev1.Secret
		err := loadResource("./testdata/fixture/sa_secret.json", &secret)
		require.NoError(t, err)
		var sa corev1.ServiceAccount
		err = loadResource("./testdata/fixture/sa_with_image_pull_secret.json", &sa)
		require.NoError(t, err)
		client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(&secret).WithObjects(&sa).Build()
		sr := kube.NewSecretsReader(client)
		spec := corev1.PodSpec{ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}, {Name: "notexist"}}, ServiceAccountName: "default"}
		foundsecret, err := sr.ListImagePullSecretsByPodSpec(context.Background(), spec, "default")
		require.NoError(t, err)
		assert.True(t, len(foundsecret) == 1)
	})

	t.Run("Test with service account and secret should return one pull image secret from corev1.ServiceAccount and corev1.Secret ", func(t *testing.T) {
		var saSecret corev1.Secret
		err := loadResource("./testdata/fixture/sa_secret.json", &saSecret)
		require.NoError(t, err)
		var secret corev1.Secret
		err = loadResource("./testdata/fixture/secret.json", &secret)
		require.NoError(t, err)
		var sa corev1.ServiceAccount
		err = loadResource("./testdata/fixture/sa_with_image_pull_secret.json", &sa)
		require.NoError(t, err)
		client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(&saSecret).WithObjects(&secret).WithObjects(&sa).Build()
		sr := kube.NewSecretsReader(client)
		spec := corev1.PodSpec{ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}, {Name: "notexist"}}, ServiceAccountName: "default"}
		foundsecret, err := sr.ListImagePullSecretsByPodSpec(context.Background(), spec, "default")
		require.NoError(t, err)
		assert.True(t, len(foundsecret) == 2)
	})

	t.Run("Test with no service account and no secrets should return error no secret found", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).Build()
		sr := kube.NewSecretsReader(client)
		spec := corev1.PodSpec{ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}, {Name: "notexist"}}, ServiceAccountName: "default"}
		foundsecret, err := sr.ListImagePullSecretsByPodSpec(context.Background(), spec, "default")
		require.NoError(t, err)
		assert.True(t, len(foundsecret) == 0)
	})

	t.Run("Test with service account with bad image pull secret and no secrets should not return error when no secret found", func(t *testing.T) {
		var sa corev1.ServiceAccount
		err := loadResource("./testdata/fixture/sa_with_image_pull_secret.json", &sa)
		require.NoError(t, err)
		client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(&sa).Build()
		sr := kube.NewSecretsReader(client)
		spec := corev1.PodSpec{ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}, {Name: "notexist"}}, ServiceAccountName: "default"}
		foundsecret, err := sr.ListImagePullSecretsByPodSpec(context.Background(), spec, "default")
		require.NoError(t, err)
		assert.True(t, len(foundsecret) == 0)
	})
}

func loadResource(filePath string, resource interface{}) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(data, &resource)
	if err != nil {
		return nil
	}
	return err
}
