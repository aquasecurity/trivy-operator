package kube

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/docker"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NewImagePullSecret constructs a new image pull Secret with the specified
// registry server and basic authentication credentials.
func NewImagePullSecret(meta metav1.ObjectMeta, server, username, password string) (*corev1.Secret, error) {
	dockerConfig, err := docker.Config{
		Auths: map[string]docker.Auth{
			server: {
				Username: username,
				Password: password,
				Auth:     docker.NewBasicAuth(username, password),
			},
		},
	}.Write()
	if err != nil {
		return nil, err
	}
	return &corev1.Secret{
		ObjectMeta: meta,
		Type:       corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			corev1.DockerConfigJsonKey: dockerConfig,
		},
	}, nil
}

// MapContainerNamesToDockerAuths creates the mapping from a container name to the Docker authentication
// credentials for the specified kube.ContainerImages and image pull Secrets.
func MapContainerNamesToDockerAuths(images ContainerImages, secrets []corev1.Secret) (map[string]docker.Auth, error) {
	auths, wildcardServers, err := MapDockerRegistryServersToAuths(secrets)
	if err != nil {
		return nil, err
	}

	mapping := make(map[string]docker.Auth)

	for containerName, imageRef := range images {
		server, err := docker.GetServerFromImageRef(imageRef)
		if err != nil {
			return nil, err
		}
		if auth, ok := auths[server]; ok {
			mapping[containerName] = auth
		}
		if len(wildcardServers) > 0 {
			if wildcardDomain := matchSubDomain(wildcardServers, server); len(wildcardDomain) > 0 {
				if auth, ok := auths[wildcardDomain]; ok {
					mapping[containerName] = auth
				}
			}
		}
	}

	return mapping, nil
}

func matchSubDomain(wildcardServers []string, subDomain string) string {
	for _, domain := range wildcardServers {
		domainWithoutWildcard := strings.Replace(domain, "*", "", 1)
		if strings.HasSuffix(subDomain, domainWithoutWildcard) {
			return domain
		}
	}
	return ""
}

// MapDockerRegistryServersToAuths creates the mapping from a Docker registry server
// to the Docker authentication credentials for the specified slice of image pull Secrets.
func MapDockerRegistryServersToAuths(imagePullSecrets []corev1.Secret) (map[string]docker.Auth, []string, error) {
	auths := make(map[string]docker.Auth)
	wildcardServers := make([]string, 0)
	for _, secret := range imagePullSecrets {
		// Skip a deprecated secret of type "kubernetes.io/dockercfg" which contains a dockercfg file
		// that follows the same format rules as ~/.dockercfg
		// See https://docs.docker.com/engine/deprecated/#support-for-legacy-dockercfg-configuration-files
		if secret.Type != corev1.SecretTypeDockerConfigJson {
			continue
		}
		data, hasRequiredData := secret.Data[corev1.DockerConfigJsonKey]
		// Skip a secrets of type "kubernetes.io/dockerconfigjson" which does not contain
		// the required ".dockerconfigjson" key.
		if !hasRequiredData {
			continue
		}
		dockerConfig := &docker.Config{}
		err := dockerConfig.Read(data)
		if err != nil {
			return nil, nil, fmt.Errorf("reading %s field of %q secret: %w", corev1.DockerConfigJsonKey, secret.Namespace+"/"+secret.Name, err)
		}
		for authKey, auth := range dockerConfig.Auths {
			server, err := docker.GetServerFromDockerAuthKey(authKey)
			if err != nil {
				return nil, nil, err
			}
			auths[server] = auth
			if strings.HasPrefix(server, "*.") {
				wildcardServers = append(wildcardServers, server)
			}
		}
	}
	return auths, wildcardServers, nil
}

func AggregateImagePullSecretsData(images ContainerImages, credentials map[string]docker.Auth) map[string][]byte {
	secretData := make(map[string][]byte)

	for containerName := range images {
		if dockerAuth, ok := credentials[containerName]; ok {
			secretData[fmt.Sprintf("%s.username", containerName)] = []byte(dockerAuth.Username)
			secretData[fmt.Sprintf("%s.password", containerName)] = []byte(dockerAuth.Password)
		}
	}

	return secretData
}

const (
	serviceAccountDefault = "default"
)

// SecretsReader defines methods for reading Secrets.
type SecretsReader interface {
	ListByLocalObjectReferences(ctx context.Context, refs []corev1.LocalObjectReference, ns string) ([]corev1.Secret, error)
	ListByServiceAccount(ctx context.Context, name string, ns string) ([]corev1.Secret, error)
	ListImagePullSecretsByPodSpec(ctx context.Context, spec corev1.PodSpec, ns string) ([]corev1.Secret, error)
	CredentialsByWorkload(ctx context.Context, workload client.Object) (map[string]docker.Auth, error)
}

// NewSecretsReader constructs a new SecretsReader which is using the client
// package provided by the controller-runtime libraries for interacting with
// the Kubernetes API server.
func NewSecretsReader(client client.Client) SecretsReader {
	return &secretsReader{client: client}
}

type secretsReader struct {
	client client.Client
}

func (r *secretsReader) ListByLocalObjectReferences(ctx context.Context, refs []corev1.LocalObjectReference, ns string) ([]corev1.Secret, error) {
	secrets := make([]corev1.Secret, 0)

	for _, secretRef := range refs {
		var secret corev1.Secret
		err := r.client.Get(ctx, client.ObjectKey{Name: secretRef.Name, Namespace: ns}, &secret)
		if err != nil {
			return nil, fmt.Errorf("getting secret by name: %s/%s: %w", ns, secretRef.Name, err)
		}
		secrets = append(secrets, secret)
	}

	return secrets, nil
}

func (r *secretsReader) ListByServiceAccount(ctx context.Context, name string, ns string) ([]corev1.Secret, error) {
	var sa corev1.ServiceAccount

	err := r.client.Get(ctx, client.ObjectKey{Name: name, Namespace: ns}, &sa)
	if err != nil {
		return nil, fmt.Errorf("getting service account by name: %s/%s: %w", ns, name, err)
	}

	return r.ListByLocalObjectReferences(ctx, sa.ImagePullSecrets, ns)
}

func (r *secretsReader) ListImagePullSecretsByPodSpec(ctx context.Context, spec corev1.PodSpec, ns string) ([]corev1.Secret, error) {
	secrets, err := r.ListByLocalObjectReferences(ctx, spec.ImagePullSecrets, ns)
	if err != nil {
		return nil, err
	}

	serviceAccountName := spec.ServiceAccountName
	if serviceAccountName == "" {
		serviceAccountName = serviceAccountDefault
	}

	serviceAccountSecrets, err := r.ListByServiceAccount(ctx, serviceAccountName, ns)
	if err != nil {
		return nil, err
	}

	return append(secrets, serviceAccountSecrets...), nil
}

func (r *secretsReader) CredentialsByWorkload(ctx context.Context, workload client.Object) (map[string]docker.Auth, error) {
	spec, err := GetPodSpec(workload)
	if err != nil {
		return nil, fmt.Errorf("getting Pod template: %w", err)
	}
	imagePullSecrets, err := r.ListImagePullSecretsByPodSpec(ctx, spec, workload.GetNamespace())
	if err != nil {
		return nil, err
	}
	return MapContainerNamesToDockerAuths(GetContainerImagesFromPodSpec(spec), imagePullSecrets)
}
