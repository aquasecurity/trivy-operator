package plugin

import (
	"fmt"

	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/plugin/aqua"
	"github.com/aquasecurity/trivy-operator/pkg/plugin/conftest"
	"github.com/aquasecurity/trivy-operator/pkg/plugin/polaris"
	"github.com/aquasecurity/trivy-operator/pkg/plugin/trivy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	Trivy    trivyoperator.Scanner = "Trivy"
	Aqua     trivyoperator.Scanner = "Aqua"
	Polaris  trivyoperator.Scanner = "Polaris"
	Conftest trivyoperator.Scanner = "Conftest"
)

type Resolver struct {
	buildInfo          trivyoperator.BuildInfo
	config             trivyoperator.ConfigData
	namespace          string
	serviceAccountName string
	client             client.Client
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

func (r *Resolver) WithClient(client client.Client) *Resolver {
	r.client = client
	return r
}

// GetVulnerabilityPlugin is a factory method that instantiates the vulnerabilityreport.Plugin.
//
// Trivy-Operator currently supports Trivy scanner in Standalone and ClientServer
// mode, and Aqua Enterprise scanner.
//
// You could add your own scanner by implementing the vulnerabilityreport.Plugin interface.
func (r *Resolver) GetVulnerabilityPlugin() (vulnerabilityreport.Plugin, trivyoperator.PluginContext, error) {
	scanner, err := r.config.GetVulnerabilityReportsScanner()
	if err != nil {
		return nil, nil, err
	}

	pluginContext := trivyoperator.NewPluginContext().
		WithName(string(scanner)).
		WithNamespace(r.namespace).
		WithServiceAccountName(r.serviceAccountName).
		WithClient(r.client).
		WithTrivyOperatorConfig(r.config).
		Get()

	switch scanner {
	case Trivy:
		return trivy.NewPlugin(ext.NewSystemClock(), ext.NewGoogleUUIDGenerator(), r.client), pluginContext, nil
	case Aqua:
		return aqua.NewPlugin(ext.NewGoogleUUIDGenerator(), r.buildInfo), pluginContext, nil
	}
	return nil, nil, fmt.Errorf("unsupported vulnerability scanner plugin: %s", scanner)
}

// GetConfigAuditPlugin is a factory method that instantiates the configauditreport.Plugin.
//
// Trivy-Operator supports Polaris and Conftest as configuration auditing tools.
//
// You could add your own scanner by implementing the configauditreport.Plugin interface.
func (r *Resolver) GetConfigAuditPlugin() (configauditreport.Plugin, trivyoperator.PluginContext, error) {
	scanner, err := r.config.GetConfigAuditReportsScanner()
	if err != nil {
		return nil, nil, err
	}

	pluginContext := trivyoperator.NewPluginContext().
		WithName(string(scanner)).
		WithNamespace(r.namespace).
		WithServiceAccountName(r.serviceAccountName).
		WithClient(r.client).
		Get()

	switch scanner {
	case Polaris:
		return polaris.NewPlugin(ext.NewSystemClock()), pluginContext, nil
	case Conftest:
		return conftest.NewPlugin(ext.NewGoogleUUIDGenerator(), ext.NewSystemClock()), pluginContext, nil
	}
	return nil, nil, fmt.Errorf("unsupported configuration audit scanner plugin: %s", scanner)
}
