package plugins

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/plugins/trivy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
)

type Resolver struct {
	buildInfo          trivyoperator.BuildInfo
	config             trivyoperator.ConfigData
	namespace          string
	serviceAccountName string
	client             client.Client
	objectResolver     *kube.ObjectResolver
}

func NewResolver() *Resolver {
	return &Resolver{}
}

func (r *Resolver) WithBuildInfo(buildInfo trivyoperator.BuildInfo) *Resolver {
	r.buildInfo = buildInfo
	return r
}

func (r *Resolver) WithConfig(config trivyoperator.ConfigData) *Resolver {
	r.config = config
	return r
}

func (r *Resolver) WithNamespace(namespace string) *Resolver {
	r.namespace = namespace
	return r
}

func (r *Resolver) WithServiceAccountName(name string) *Resolver {
	r.serviceAccountName = name
	return r
}

func (r *Resolver) WithClient(c client.Client) *Resolver {
	r.client = c
	return r
}
func (r *Resolver) WithObjectResolver(objectResolver *kube.ObjectResolver) *Resolver {
	r.objectResolver = objectResolver
	return r
}

// GetVulnerabilityPlugin is a factory method that instantiates the vulnerabilityreport.Plugin.
//
// Trivy-Operator currently supports Trivy scanner in Standalone and ClientServer
// mode.
//
// You could add your own scanner by implementing the vulnerabilityreport.Plugin interface.
func (r *Resolver) GetVulnerabilityPlugin() (vulnerabilityreport.Plugin, trivyoperator.PluginContext, error) {
	scanner, err := r.config.GetVulnerabilityReportsScanner()
	if err != nil {
		return nil, nil, err
	}

	pluginContext := trivyoperator.NewPluginContext().
		WithName(string(scanner)).
		WithClient(r.client).
		WithNamespace(r.namespace).
		WithServiceAccountName(r.serviceAccountName).
		WithTrivyOperatorConfig(r.config).
		Get()

	return trivy.NewPlugin(ext.NewSystemClock(), ext.NewGoogleUUIDGenerator(), r.objectResolver), pluginContext, nil
}

// GetConfigAuditPlugin is a factory method that instantiates the configauditreport.Plugin.
func (r *Resolver) GetConfigAuditPlugin() (configauditreport.PluginInMemory, trivyoperator.PluginContext) {
	scanner := r.config.GetConfigAuditReportsScanner()
	pluginContext := trivyoperator.NewPluginContext().
		WithName(string(scanner)).
		WithClient(r.client).
		WithNamespace(r.namespace).
		WithServiceAccountName(r.serviceAccountName).
		WithTrivyOperatorConfig(r.config).
		Get()

	return trivy.NewTrivyConfigAuditPlugin(ext.NewSystemClock(), ext.NewGoogleUUIDGenerator(), r.objectResolver), pluginContext
}
