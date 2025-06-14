package kube_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/aquasecurity/trivy-operator/pkg/docker"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"

	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
)

func TestMapDockerRegistryServersToAuths(t *testing.T) {
	t.Run("should map Docker registry servers to Docker authentication credentials", func(t *testing.T) {
		g := NewGomegaWithT(t)

		auths, err := kube.MapDockerRegistryServersToAuths([]corev1.Secret{
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
		}, false)
		wildcardServers := kube.GetWildcardServers(auths)
		g.Expect(err).ToNot(HaveOccurred())
		assert.Len(t, wildcardServers, 1)
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

		auths, err := kube.MapDockerRegistryServersToAuths([]corev1.Secret{
			{
				Type: corev1.SecretTypeDockercfg,
				Data: map[string][]byte{
					corev1.DockerConfigKey: []byte(`{
  "quay.io": {
	"auth": "dXNlcjpBZG1pbjEyMzQ1"
  }
}`),
				},
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
		}, false)
		wildcardServers := kube.GetWildcardServers(auths)
		g.Expect(err).ToNot(HaveOccurred())
		assert.Empty(t, wildcardServers)
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

	t.Run("Test with service account and secret with same registry domain should map container images to Docker authentication credentials from Pod secret", func(t *testing.T) {
		g := NewGomegaWithT(t)

		var saSecret corev1.Secret
		err := loadResource("./testdata/fixture/sa_secret_same_domain.json", &saSecret)
		require.NoError(t, err)
		var secret corev1.Secret
		err = loadResource("./testdata/fixture/secret_same_domain.json", &secret)
		require.NoError(t, err)
		var sa corev1.ServiceAccount
		err = loadResource("./testdata/fixture/sa_with_image_pull_secret_same_domain.json", &sa)
		require.NoError(t, err)
		client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(&saSecret).WithObjects(&secret).WithObjects(&sa).Build()
		sr := kube.NewSecretsReader(client)
		spec := corev1.PodSpec{ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}, {Name: "notexist"}}, ServiceAccountName: "default"}
		foundsecret, err := sr.ListImagePullSecretsByPodSpec(t.Context(), spec, "default")
		require.NoError(t, err)
		assert.Len(t, foundsecret, 2)
		auths, err := kube.MapDockerRegistryServersToAuths(foundsecret, false)
		require.NoError(t, err)

		mapping, err := kube.MapContainerNamesToDockerAuths(kube.ContainerImages{
			"container-1": "quay.io/my-company/my-service:2.0",
		}, auths)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(mapping).To(MatchAllKeys(Keys{
			"container-1": Equal(docker.Auth{
				Auth:     "dXNlcjpBZG1pbjEyMzQ1",
				Username: "user",
				Password: "Admin12345",
			}),
		}))
	})
	t.Run("Test with service account and secret with same registry domain should map container images to Docker authentication credentials from Pod secret with multi secret support", func(t *testing.T) {
		g := NewGomegaWithT(t)

		var saSecret corev1.Secret
		err := loadResource("./testdata/fixture/sa_secret_same_domain.json", &saSecret)
		require.NoError(t, err)
		var secret corev1.Secret
		err = loadResource("./testdata/fixture/secret_same_domain.json", &secret)
		require.NoError(t, err)
		var sa corev1.ServiceAccount
		err = loadResource("./testdata/fixture/sa_with_image_pull_secret_same_domain.json", &sa)
		require.NoError(t, err)
		client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(&saSecret).WithObjects(&secret).WithObjects(&sa).Build()
		sr := kube.NewSecretsReader(client)
		spec := corev1.PodSpec{ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}, {Name: "notexist"}}, ServiceAccountName: "default"}
		foundsecret, err := sr.ListImagePullSecretsByPodSpec(t.Context(), spec, "default")
		require.NoError(t, err)
		assert.Len(t, foundsecret, 2)
		auths, err := kube.MapDockerRegistryServersToAuths(foundsecret, true)
		require.NoError(t, err)

		mapping, err := kube.MapContainerNamesToDockerAuths(kube.ContainerImages{
			"container-1": "quay.io/my-company/my-service:2.0",
		}, auths)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(mapping).To(MatchAllKeys(Keys{
			"container-1": Equal(docker.Auth{
				Auth:     "",
				Username: "root,user",
				Password: "s3cret,Admin12345",
			}),
		}))
	})
}

func TestMapContainerNamesToDockerAuths(t *testing.T) {
	t.Run("should map container images to Docker authentication credentials", func(t *testing.T) {
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
		}, false)
		require.NoError(t, err)

		mapping, err := kube.MapContainerNamesToDockerAuths(kube.ContainerImages{
			"container-1": "docker.io/my-organization/my-app-backend:0.1.0",
			"container-2": "my-organization/my-app-frontend:0.3.2",
			"container-3": "quay.io/my-company/my-service:2.0",
		}, auths)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(mapping).To(MatchAllKeys(Keys{
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

		auths, err := kube.MapDockerRegistryServersToAuths([]corev1.Secret{
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
		}, false)
		require.NoError(t, err)

		mapping, err := kube.MapContainerNamesToDockerAuths(kube.ContainerImages{
			"container-1": "tes.jfrog.com/my-organization/my-app-backend:0.1.0",
		}, auths)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(mapping).To(MatchAllKeys(Keys{
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
		foundsecret, err := sr.ListImagePullSecretsByPodSpec(t.Context(), spec, "default")
		require.NoError(t, err)
		assert.Empty(t, foundsecret)
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
		foundsecret, err := sr.ListImagePullSecretsByPodSpec(t.Context(), spec, "default")
		require.NoError(t, err)
		assert.Len(t, foundsecret, 1)
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
		foundsecret, err := sr.ListImagePullSecretsByPodSpec(t.Context(), spec, "default")
		require.NoError(t, err)
		assert.Len(t, foundsecret, 1)
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
		foundsecret, err := sr.ListImagePullSecretsByPodSpec(t.Context(), spec, "default")
		require.NoError(t, err)
		assert.Len(t, foundsecret, 2)
	})

	t.Run("Test with no service account and no secrets should return error no secret found", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).Build()
		sr := kube.NewSecretsReader(client)
		spec := corev1.PodSpec{ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}, {Name: "notexist"}}, ServiceAccountName: "default"}
		foundsecret, err := sr.ListImagePullSecretsByPodSpec(t.Context(), spec, "default")
		require.NoError(t, err)
		assert.Empty(t, foundsecret)
	})

	t.Run("Test with service account with bad image pull secret and no secrets should not return error when no secret found", func(t *testing.T) {
		var sa corev1.ServiceAccount
		err := loadResource("./testdata/fixture/sa_with_image_pull_secret.json", &sa)
		require.NoError(t, err)
		client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(&sa).Build()
		sr := kube.NewSecretsReader(client)
		spec := corev1.PodSpec{ImagePullSecrets: []corev1.LocalObjectReference{{Name: "regcred"}, {Name: "notexist"}}, ServiceAccountName: "default"}
		foundsecret, err := sr.ListImagePullSecretsByPodSpec(t.Context(), spec, "default")
		require.NoError(t, err)
		assert.Empty(t, foundsecret)
	})
}

func loadResource(filePath string, resource any) error {
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

func Test_secretsReader_CredentialsByServer(t *testing.T) {
	t.Run("Test with no secrets or serviceaccounts configured and globalAccess disabled should not map any credentials", func(t *testing.T) {

		client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).Build()
		sr := kube.NewSecretsReader(client)
		pod := corev1.Pod{
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Image: "quay.io/nginx:1.16",
					},
				},
			},
		}

		auths, err := sr.CredentialsByServer(t.Context(), &pod, make(map[string]string), false, false)
		require.NoError(t, err)
		assert.Empty(t, auths)
	})

	t.Run("Test with secrets configured but globalAccess disabled should map container images to Docker authentication credentials from serviceaccount secret", func(t *testing.T) {

		var secret corev1.Secret
		err := loadResource("./testdata/fixture/secret_same_domain.json", &secret)
		require.NoError(t, err)
		var imagePullSecret corev1.Secret
		err = loadResource("./testdata/fixture/secret_same_domain_imagePullSecret.json", &imagePullSecret)
		require.NoError(t, err)
		var sa corev1.ServiceAccount
		err = loadResource("./testdata/fixture/sa_with_image_pull_secret_same_domain.json", &sa)
		require.NoError(t, err)
		client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(&secret).WithObjects(&sa).WithObjects(&imagePullSecret).Build()
		sr := kube.NewSecretsReader(client)
		pod := corev1.Pod{
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Image: "quay.io/nginx:1.16",
					},
				},
				ImagePullSecrets: []corev1.LocalObjectReference{
					{
						Name: "private-regcred",
					},
				},
			},
		}

		auths, err := sr.CredentialsByServer(t.Context(), &pod, map[string]string{
			"default": "regcred",
		}, false, false)
		require.NoError(t, err)
		assert.Len(t, auths, 1)
		assert.Equal(t, map[string]docker.Auth{
			"quay.io": {Auth: "dXNlcjpBZG1pbjEyMzQ1", Username: "user", Password: "Admin12345"},
		}, auths)
	})

	t.Run("Test with secrets configured and globalAccess enabled should map container images to Docker authentication credentials from serviceaccount and imagePullSecret", func(t *testing.T) {

		var secret corev1.Secret
		err := loadResource("./testdata/fixture/secret_same_domain.json", &secret)
		require.NoError(t, err)
		var imagePullSecret corev1.Secret
		err = loadResource("./testdata/fixture/secret_same_domain_imagePullSecret.json", &imagePullSecret)
		require.NoError(t, err)
		var sa corev1.ServiceAccount
		err = loadResource("./testdata/fixture/sa_with_image_pull_secret_same_domain.json", &sa)
		require.NoError(t, err)
		client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(&secret).WithObjects(&sa).WithObjects(&imagePullSecret).Build()
		sr := kube.NewSecretsReader(client)
		pod := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Image: "quay.io/nginx:1.16",
					},
				},
				ImagePullSecrets: []corev1.LocalObjectReference{
					{
						Name: "private-regcred",
					},
				},
			},
		}

		auths, err := sr.CredentialsByServer(t.Context(), &pod, map[string]string{
			"default": "regcred",
		}, true, true)
		require.NoError(t, err)
		assert.Len(t, auths, 1)
		assert.Equal(t, map[string]docker.Auth{
			"quay.io": {Auth: "", Username: "admin,user", Password: "Password12345,Admin12345"},
		}, auths)
	})
}
