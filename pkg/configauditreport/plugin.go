package configauditreport

import (
	"github.com/aquasecurity/trivy-operator/pkg/pluginconfig"
)

// PluginInMemory defines the interface between trivy-operator and trivy configuration
type PluginInMemory interface {

	// Init is a callback to initialize this plugin, e.g. ensure the default
	// configuration.
	Init(ctx pluginconfig.PluginContext) error

	NewConfigForConfigAudit(ctx pluginconfig.PluginContext) (ConfigAuditConfig, error)
}

// ConfigAuditConfig defines the interface between trivy-operator and trivy configuration which related to configauditreport
type ConfigAuditConfig interface {

	// GetUseBuiltinRegoPolicies return trivy config which associated to configauditreport plugin
	GetUseBuiltinRegoPolicies() bool
	// GetSupportedConfigAuditKinds list of supported kinds to be scanned by the config audit scanner
	GetSupportedConfigAuditKinds() []string
}
