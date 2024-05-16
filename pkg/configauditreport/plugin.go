package configauditreport

import (
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

// PluginInMemory defines the interface between trivy-operator and trivy configuration
type PluginInMemory interface {

	// Init is a callback to initialize this plugin, e.g. ensure the default
	// configuration.
	Init(ctx trivyoperator.PluginContext) error

	NewConfigForConfigAudit(ctx trivyoperator.PluginContext) (ConfigAuditConfig, error)
}

// ConfigAuditConfig defines the interface between trivy-operator and trivy configuration which related to configauditreport
type ConfigAuditConfig interface {

	// GetUseBuiltinRegoPolicies return trivy config which associated to configauditreport plugin
	GetUseBuiltinRegoPolicies() bool
	// GetUseEmbeddedRegoPolicies return trivy embedded rego policies (mainly for air-gapped environment)
	GetUseEmbeddedRegoPolicies() bool
	// GetSupportedConfigAuditKinds list of supported kinds to be scanned by the config audit scanner
	GetSupportedConfigAuditKinds() []string

	// GetSeverity get security level
	GetSeverity() string
}
