package helper

import (
	"context"
	"fmt"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/docker"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/caarlos0/env/v6"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

type PrivateRegistryConfig struct {
	Server   string `env:"TRIVY_OPERATOR_TEST_REGISTRY_SERVER"`
	Username string `env:"TRIVY_OPERATOR_TEST_REGISTRY_USERNAME"`
	Password string `env:"TRIVY_OPERATOR_TEST_REGISTRY_PASSWORD"`
	ImageRef string `env:"TRIVY_OPERATOR_TEST_REGISTRY_PRIVATE_IMAGE_REF"`
}

func (c *PrivateRegistryConfig) Parse() error {
	return env.Parse(c)
}

type PodBuilder struct {
	name               string
	namespace          string
	containers         []corev1.Container
	serviceAccountName string
	imagePullSecrets   []corev1.LocalObjectReference
}

func NewPod() *PodBuilder {
	return &PodBuilder{}
}

func (b *PodBuilder) WithName(name string) *PodBuilder {
	b.name = name
	return b
}

func (b *PodBuilder) WithRandomName(prefix string) *PodBuilder {
	return b.WithName(prefix + "-" + rand.String(5))
}

func (b *PodBuilder) WithNamespace(namespace string) *PodBuilder {
	b.namespace = namespace
	return b
}

func (b *PodBuilder) WithContainer(name, image string) *PodBuilder {
	b.containers = append(b.containers, corev1.Container{
		Name:  name,
		Image: image,
	})
	return b
}

func (b *PodBuilder) WithServiceAccountName(name string) *PodBuilder {
	b.serviceAccountName = name
	return b
}

func (b *PodBuilder) WithImagePullSecret(name string) *PodBuilder {
	b.imagePullSecrets = append(b.imagePullSecrets, corev1.LocalObjectReference{
		Name: name,
	})
	return b
}

func (b *PodBuilder) Build() *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.name,
			Namespace: b.namespace,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: b.serviceAccountName,
			Containers:         b.containers,
			ImagePullSecrets:   b.imagePullSecrets,
		},
	}
}

type ServiceAccountBuilder struct {
	target *corev1.ServiceAccount
}

func (b *ServiceAccountBuilder) WithRandomName(prefix string) *ServiceAccountBuilder {
	b.target.Name = prefix + "-" + rand.String(5)
	return b
}

func (b *ServiceAccountBuilder) WithNamespace(namespace string) *ServiceAccountBuilder {
	b.target.Namespace = namespace
	return b
}

func (b *ServiceAccountBuilder) WithImagePullSecret(name string) *ServiceAccountBuilder {
	b.target.ImagePullSecrets = append(b.target.ImagePullSecrets, corev1.LocalObjectReference{Name: name})
	return b
}

func (b *ServiceAccountBuilder) Build() *corev1.ServiceAccount {
	return b.target
}

type SecretBuilder struct {
	target *corev1.Secret

	registryServer   string
	registryUsername string
	registryPassword string
}

func (b *SecretBuilder) WithRandomName(name string) *SecretBuilder {
	b.target.Name = name + "-" + rand.String(5)
	return b
}

func (b *SecretBuilder) WithNamespace(namespace string) *SecretBuilder {
	b.target.Namespace = namespace
	return b
}

func (b *SecretBuilder) WithServer(server string) *SecretBuilder {
	b.registryServer = server
	return b
}

func (b *SecretBuilder) WithUsername(username string) *SecretBuilder {
	b.registryUsername = username
	return b
}

func (b *SecretBuilder) WithPassword(password string) *SecretBuilder {
	b.registryPassword = password
	return b
}

func (b *SecretBuilder) Build() (*corev1.Secret, error) {
	dockerConfig, err := docker.Config{
		Auths: map[string]docker.Auth{
			b.registryServer: {
				Username: b.registryUsername,
				Password: b.registryPassword,
				Auth:     docker.NewBasicAuth(b.registryUsername, b.registryPassword),
			},
		},
	}.Write()
	if err != nil {
		return nil, err
	}

	b.target.Type = corev1.SecretTypeDockerConfigJson
	b.target.Data = map[string][]byte{
		corev1.DockerConfigJsonKey: dockerConfig,
	}

	return b.target, nil
}

type DeploymentBuilder struct {
	name       string
	namespace  string
	containers []corev1.Container
}

func NewDeployment() *DeploymentBuilder {
	return &DeploymentBuilder{}
}

func (b *DeploymentBuilder) WithName(name string) *DeploymentBuilder {
	b.name = name
	return b
}

func (b *DeploymentBuilder) WithRandomName(prefix string) *DeploymentBuilder {
	return b.WithName(prefix + "-" + rand.String(5))
}

func (b *DeploymentBuilder) WithNamespace(namespace string) *DeploymentBuilder {
	b.namespace = namespace
	return b
}

func (b *DeploymentBuilder) WithContainer(name, image string) *DeploymentBuilder {
	b.containers = append(b.containers, corev1.Container{
		Name:  name,
		Image: image,
	})
	return b
}

func (b *DeploymentBuilder) Build() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.name,
			Namespace: b.namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": b.name,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels.Set{
						"app": b.name,
					},
				},
				Spec: corev1.PodSpec{
					Containers: b.containers,
				},
			},
		},
	}
}

var (
	trivyScanner = v1alpha1.Scanner{
		Name:    v1alpha1.ScannerNameTrivy,
		Vendor:  "Aqua Security",
		Version: "0.18.0-rc",
	}
)

type VulnerabilityReportBuilder struct {
	name      string
	namespace string
	ownerKind kube.Kind
	ownerName string
}

func (b *VulnerabilityReportBuilder) WithName(name string) *VulnerabilityReportBuilder {
	b.name = name
	return b
}

func (b *VulnerabilityReportBuilder) WithNamespace(namespace string) *VulnerabilityReportBuilder {
	b.namespace = namespace
	return b
}

func (b *VulnerabilityReportBuilder) WithOwnerKind(kind kube.Kind) *VulnerabilityReportBuilder {
	b.ownerKind = kind
	return b
}

func (b *VulnerabilityReportBuilder) WithOwnerName(name string) *VulnerabilityReportBuilder {
	b.ownerName = name
	return b
}

func (b *VulnerabilityReportBuilder) Build() *v1alpha1.VulnerabilityReport {
	return &v1alpha1.VulnerabilityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.name,
			Namespace: b.namespace,
			Labels: map[string]string{
				trivyoperator.LabelContainerName:     "nginx", // TODO Make it configurable
				trivyoperator.LabelResourceKind:      string(b.ownerKind),
				trivyoperator.LabelResourceName:      b.ownerName,
				trivyoperator.LabelResourceNamespace: b.namespace,
			},
		},
		Report: v1alpha1.VulnerabilityReportData{
			UpdateTimestamp: metav1.NewTime(time.Now()),
			Scanner:         trivyScanner,
			Registry: v1alpha1.Registry{
				Server: "index.docker.io",
			},
			Artifact: v1alpha1.Artifact{
				Repository: "library/nginx",
				Tag:        "1.16",
			},
			OS: v1alpha1.OS{
				Family: "debian",
				Name:   "10.3",
			},
			Summary: v1alpha1.VulnerabilitySummary{
				MediumCount: 1,
			},
			Vulnerabilities: []v1alpha1.Vulnerability{
				{
					VulnerabilityID:  "CVE-2020-3810",
					Resource:         "apt",
					InstalledVersion: "1.8.2",
					FixedVersion:     "1.8.2.1",
					Severity:         v1alpha1.SeverityMedium,
					Title:            "",
					Description:      "Missing input validation in the ar/tar implementations of APT before version 2.1.2 could result in denial of service when processing specially crafted deb files.",
					Links: []string{
						"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-3810",
					},
				},
			},
		},
	}
}

// Helper is a mix of asserts and helpers, but we can fix that later.
type Helper struct {
	scheme     *runtime.Scheme
	kubeClient client.Client
}

func NewHelper(c client.Client) *Helper {
	return &Helper{
		scheme:     c.Scheme(),
		kubeClient: c,
	}
}

func (h *Helper) HasActiveReplicaSet(namespace, name string) func() (bool, error) {
	return func() (bool, error) {
		rs, err := h.GetActiveReplicaSetForDeployment(namespace, name)
		if err != nil {
			return false, err
		}
		return rs != nil, nil
	}
}

func (h *Helper) HasVulnerabilityReportOwnedBy(obj client.Object) func() (bool, error) {
	return func() (bool, error) {
		gvk, err := apiutil.GVKForObject(obj, h.scheme)
		if err != nil {
			return false, err
		}
		var reportList v1alpha1.VulnerabilityReportList
		err = h.kubeClient.List(context.Background(), &reportList, client.MatchingLabels{
			trivyoperator.LabelResourceKind:      gvk.Kind,
			trivyoperator.LabelResourceName:      obj.GetName(),
			trivyoperator.LabelResourceNamespace: obj.GetNamespace(),
		})
		if err != nil {
			return false, err
		}
		return len(reportList.Items) == 1, nil
	}
}

func (h *Helper) HasConfigAuditReportOwnedBy(obj client.Object) func() (bool, error) {
	return func() (bool, error) {
		gvk, err := apiutil.GVKForObject(obj, h.scheme)
		if err != nil {
			return false, err
		}
		var reportsList v1alpha1.ConfigAuditReportList
		err = h.kubeClient.List(context.Background(), &reportsList, client.MatchingLabels{
			trivyoperator.LabelResourceKind:      gvk.Kind,
			trivyoperator.LabelResourceName:      obj.GetName(),
			trivyoperator.LabelResourceNamespace: obj.GetNamespace(),
		})
		if err != nil {
			return false, err
		}

		return len(reportsList.Items) == 1 && reportsList.Items[0].DeletionTimestamp == nil, nil
	}
}

func (h *Helper) DeleteConfigAuditReportOwnedBy(obj client.Object) error {
	gvk, err := apiutil.GVKForObject(obj, h.scheme)
	if err != nil {
		return err
	}
	var reportsList v1alpha1.ConfigAuditReportList
	err = h.kubeClient.List(context.Background(), &reportsList, client.MatchingLabels{
		trivyoperator.LabelResourceKind:      gvk.Kind,
		trivyoperator.LabelResourceName:      obj.GetName(),
		trivyoperator.LabelResourceNamespace: obj.GetNamespace(),
	})
	if err != nil {
		return err
	}

	return h.kubeClient.Delete(context.Background(), &reportsList.Items[0])
}

func (h *Helper) GetActiveReplicaSetForDeployment(namespace, name string) (*appsv1.ReplicaSet, error) {
	var deployment appsv1.Deployment
	var replicaSetList appsv1.ReplicaSetList

	err := h.kubeClient.Get(context.TODO(), types.NamespacedName{
		Name: name, Namespace: namespace,
	}, &deployment)
	if err != nil {
		return nil, err
	}

	deploymentSelector, err := metav1.LabelSelectorAsMap(deployment.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("mapping label selector: %w", err)
	}
	selector := labels.Set(deploymentSelector)

	err = h.kubeClient.List(context.TODO(), &replicaSetList, client.MatchingLabels(selector))

	if err != nil {
		return nil, err
	}

	for _, replicaSet := range replicaSetList.Items {
		if deployment.Annotations["deployment.kubernetes.io/revision"] !=
			replicaSet.Annotations["deployment.kubernetes.io/revision"] {
			continue
		}
		return replicaSet.DeepCopy(), nil
	}
	return nil, nil
}

// nolint:staticcheck
func (h *Helper) UpdateDeploymentImage(namespace, name string) error {
	// TODO Check kubectl set image implementation
	return wait.PollImmediate(5*time.Second, 2*time.Minute, func() (bool, error) {
		var deployment appsv1.Deployment
		err := h.kubeClient.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, &deployment)
		if err != nil {
			return false, err
		}

		dcDeploy := deployment.DeepCopy()
		dcDeploy.Spec.Template.Spec.Containers[0].Image = "wordpress:5"
		err = h.kubeClient.Update(context.TODO(), dcDeploy)
		if err != nil && errors.IsConflict(err) {
			return false, nil
		}

		return err == nil, err
	})
}

func (h *Helper) DeploymentIsReady(deploy client.ObjectKey) func() (bool, error) {
	return func() (bool, error) {
		var d appsv1.Deployment
		err := h.kubeClient.Get(context.TODO(), client.ObjectKey{Namespace: deploy.Namespace, Name: deploy.Name}, &d)
		if err != nil {
			return false, err
		}
		return d.Status.ReadyReplicas == *d.Spec.Replicas, nil
	}
}
