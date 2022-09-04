package pluginconfig

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/config"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TODO: this is a dup for now
const labelK8SAppManagedBy = "app.kubernetes.io/managed-by"

// PluginConfig holds plugin configuration settings.
type PluginConfig struct {
	Data       map[string]string
	SecretData map[string][]byte
}

func (c PluginConfig) GetRequiredData(key string) (string, error) {
	var ok bool
	var value string
	if value, ok = c.Data[key]; !ok {
		return "", fmt.Errorf("property %s not set", key)
	}
	return value, nil
}

// PluginContext is plugin's execution context within the Trivy-operator toolkit.
// The context is used to grant access to other methods so that this plugin
// can interact with the toolkit.
type PluginContext interface {
	// GetName returns the name of the plugin.
	GetName() string
	// GetConfig returns the PluginConfig object that holds configuration settings of the plugin.
	GetConfig() (PluginConfig, error)
	// EnsureConfig ensures the PluginConfig, typically when a plugin is initialized.
	EnsureConfig(cfg PluginConfig) error
	// GetNamespace return the name of the K8s Namespace where Trivy-operator creates Jobs
	// and other helper objects.
	GetNamespace() string
	// GetServiceAccountName return the name of the K8s Service Account used to run workloads
	// created by Trivy-operator.
	GetServiceAccountName() string
	// GetTrivyOperatorConfig returns trivyoperator configuration.
	GetTrivyOperatorConfig() config.Config
}

// GetPluginConfigMapName returns the name of a ConfigMap used to configure a plugin
// with the given name.
// TODO Rename to GetPluginConfigObjectName as this method is used to determine the name of ConfigMaps and Secrets.
func GetPluginConfigMapName(pluginName string) string {
	return "trivy-operator-" + strings.ToLower(pluginName) + "-config"
}

type pluginContext struct {
	name                string
	client              client.Client
	namespace           string
	serviceAccountName  string
	trivyOperatorConfig config.Config
}

func (p *pluginContext) GetName() string {
	return p.name
}

func (p *pluginContext) EnsureConfig(cfg PluginConfig) error {
	err := p.client.Create(context.Background(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: p.namespace,
			Name:      GetPluginConfigMapName(p.name),
			Labels: labels.Set{
				labelK8SAppManagedBy: "trivyoperator",
			},
		},
		Data: cfg.Data,
	})
	if err != nil && !errors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func (p *pluginContext) GetConfig() (PluginConfig, error) {
	cm := &corev1.ConfigMap{}
	secret := &corev1.Secret{}

	err := p.client.Get(context.Background(), types.NamespacedName{
		Namespace: p.namespace,
		Name:      GetPluginConfigMapName(strings.ToLower(p.GetName())),
	}, cm)
	if err != nil {
		return PluginConfig{}, err
	}

	err = p.client.Get(context.Background(), types.NamespacedName{
		Namespace: p.namespace,
		Name:      GetPluginConfigMapName(strings.ToLower(p.GetName())),
	}, secret)

	var secretData map[string][]byte
	if err == nil {
		secretData = secret.DeepCopy().Data
	}

	if err != nil && !errors.IsNotFound(err) {
		return PluginConfig{}, err
	}

	return PluginConfig{
		Data:       cm.DeepCopy().Data,
		SecretData: secretData,
	}, nil
}

func (p *pluginContext) GetNamespace() string {
	return p.namespace
}

func (p *pluginContext) GetServiceAccountName() string {
	return p.serviceAccountName
}

func (p *pluginContext) GetTrivyOperatorConfig() config.Config {
	return p.trivyOperatorConfig
}

type PluginContextBuilder struct {
	ctx *pluginContext
}

func NewPluginContext() *PluginContextBuilder {
	return &PluginContextBuilder{
		ctx: &pluginContext{},
	}
}

func (b *PluginContextBuilder) WithName(name string) *PluginContextBuilder {
	b.ctx.name = name
	return b
}

func (b *PluginContextBuilder) WithClient(c client.Client) *PluginContextBuilder {
	b.ctx.client = c
	return b
}

func (b *PluginContextBuilder) WithNamespace(namespace string) *PluginContextBuilder {
	b.ctx.namespace = namespace
	return b
}

func (b *PluginContextBuilder) WithServiceAccountName(name string) *PluginContextBuilder {
	b.ctx.serviceAccountName = name
	return b
}

func (b *PluginContextBuilder) WithTrivyOperatorConfig(cfg config.Config) *PluginContextBuilder {
	b.ctx.trivyOperatorConfig = cfg
	return b
}

func (b *PluginContextBuilder) Get() PluginContext {
	return b.ctx
}
