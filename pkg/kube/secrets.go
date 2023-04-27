package kube

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/docker"
	corev1 "k8s.io/api/core/v1"
	k8sapierror "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// MapContainerNamesToDockerAuths creates the mapping from a container name to the Docker authentication
// credentials for the specified kube.ContainerImages and image pull Secrets.
func MapContainerNamesToDockerAuths(images ContainerImages, auths map[string]docker.Auth) (map[string]docker.Auth, error) {
	wildcardServers := GetWildcardServers(auths)

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
func MapDockerRegistryServersToAuths(imagePullSecrets []corev1.Secret, multiSecretSupport bool) (map[string]docker.Auth, error) {
	auths := make(map[string]docker.Auth)
	for _, secret := range imagePullSecrets {
		var data []byte
		var hasRequiredData, isLegacy bool

		switch secret.Type {
		case corev1.SecretTypeDockerConfigJson:
			data, hasRequiredData = secret.Data[corev1.DockerConfigJsonKey]
		case corev1.SecretTypeDockercfg:
			data, hasRequiredData = secret.Data[corev1.DockerConfigKey]
			isLegacy = true
		default:
			continue
		}

		// Skip a secrets of type "kubernetes.io/dockerconfigjson" or "kubernetes.io/dockercfg" which does not contain
		// the required ".dockerconfigjson" or ".dockercfg" key.
		if !hasRequiredData {
			continue
		}
		dockerConfig := &docker.Config{}
		err := dockerConfig.Read(data, isLegacy)
		if err != nil {
			return nil, fmt.Errorf("reading %s or %s field of %q secret: %w", corev1.DockerConfigJsonKey, corev1.DockerConfigKey, secret.Namespace+"/"+secret.Name, err)
		}
		for authKey, auth := range dockerConfig.Auths {
			server, err := docker.GetServerFromDockerAuthKey(authKey)
			if err != nil {
				return nil, err
			}
			if a, ok := auths[server]; multiSecretSupport && ok {
				user := fmt.Sprintf("%s,%s", a.Username, auth.Username)
				pass := fmt.Sprintf("%s,%s", a.Password, auth.Password)
				auths[server] = docker.Auth{Username: user, Password: pass}
			} else {
				auths[server] = auth
			}
		}
	}
	return auths, nil
}

func GetWildcardServers(auths map[string]docker.Auth) []string {
	wildcardServers := make([]string, 0)
	for server := range auths {
		if strings.HasPrefix(server, "*.") {
			wildcardServers = append(wildcardServers, server)
		}
	}
	return wildcardServers
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
	ListImagePullSecretsByPodSpec(ctx context.Context, spec corev1.PodSpec, ns string) ([]corev1.Secret, error)
	CredentialsByServer(ctx context.Context, workload client.Object, secretsInfo map[string]string, multiSecretSupport bool) (map[string]docker.Auth, error)
}

// NewSecretsReader constructs a new SecretsReader which is using the client
// package provided by the controller-runtime libraries for interacting with
// the Kubernetes API server.
func NewSecretsReader(c client.Client) SecretsReader {
	return &secretsReader{client: c}
}

// kubebuilder:rbac:groups="",resources=secrets,verbs=get
// kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get

type secretsReader struct {
	client client.Client
}

func (r *secretsReader) ListByLocalObjectReferences(ctx context.Context, refs []corev1.LocalObjectReference, ns string) ([]corev1.Secret, error) {
	secrets := make([]corev1.Secret, 0)

	for _, secretRef := range refs {
		var secret corev1.Secret
		err := r.client.Get(ctx, client.ObjectKey{Name: secretRef.Name, Namespace: ns}, &secret)
		if err != nil {
			if k8sapierror.IsNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("getting secret by name: %s/%s: %w", ns, secretRef.Name, err)
		}
		secrets = append(secrets, secret)
	}
	return secrets, nil
}

func (r *secretsReader) getServiceAccountByPodSpec(ctx context.Context, spec corev1.PodSpec, ns string) (corev1.ServiceAccount, error) {
	serviceAccountName := spec.ServiceAccountName
	if serviceAccountName == "" {
		serviceAccountName = serviceAccountDefault
	}

	sa := corev1.ServiceAccount{}
	err := r.client.Get(ctx, client.ObjectKey{Name: serviceAccountName, Namespace: ns}, &sa)
	if err != nil {
		return sa, fmt.Errorf("getting service account by name: %s/%s: %w", ns, serviceAccountName, err)
	}
	return sa, nil
}

func (r *secretsReader) ListImagePullSecretsByPodSpec(ctx context.Context, spec corev1.PodSpec, ns string) ([]corev1.Secret, error) {
	imagePullSecrets := spec.ImagePullSecrets

	sa, err := r.getServiceAccountByPodSpec(ctx, spec, ns)
	if err != nil && !k8sapierror.IsNotFound(err) {
		return nil, err
	}
	imagePullSecrets = append(sa.ImagePullSecrets, imagePullSecrets...)

	secrets, err := r.ListByLocalObjectReferences(ctx, imagePullSecrets, ns)
	if err != nil {
		return nil, err
	}
	return secrets, nil
}

func (r *secretsReader) GetSecretsFromEnv(ctx context.Context, secretsInfo map[string]string) ([]corev1.Secret, error) {
	secretsFromEnv := make([]corev1.Secret, 0)

	for ns, secretNames := range secretsInfo {
		secretNamesValues := strings.Split(secretNames, ",")
		for _, secretName := range secretNamesValues {
			var secretFromEnv corev1.Secret
			err := r.client.Get(ctx, client.ObjectKey{Name: strings.TrimSpace(secretName), Namespace: strings.TrimSpace(ns)}, &secretFromEnv)
			if err != nil {
				if k8sapierror.IsNotFound(err) {
					continue
				}
				return nil, fmt.Errorf("getting secret by name: %s/%s: %w", ns, secretName, err)
			}
			secretsFromEnv = append(secretsFromEnv, secretFromEnv)
		}
	}
	return secretsFromEnv, nil
}

func (r *secretsReader) CredentialsByServer(ctx context.Context, workload client.Object, secretsInfo map[string]string, multiSecretSupport bool) (map[string]docker.Auth, error) {
	spec, err := GetPodSpec(workload)
	if err != nil {
		return nil, fmt.Errorf("getting Pod template: %w", err)
	}
	imagePullSecrets, err := r.ListImagePullSecretsByPodSpec(ctx, spec, workload.GetNamespace())
	if err != nil {
		return nil, err
	}
	secretsFromEnv, err := r.GetSecretsFromEnv(ctx, secretsInfo)
	if err != nil {
		return nil, err
	}
	imagePullSecrets = append(imagePullSecrets, secretsFromEnv...)

	return MapDockerRegistryServersToAuths(imagePullSecrets, multiSecretSupport)
}
