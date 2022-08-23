package etc

import (
	"fmt"
	"strings"
	"time"

	"github.com/caarlos0/env/v6"
)

// Config defines parameters for running the operator.
type Config struct {
	Namespace                                    string         `env:"OPERATOR_NAMESPACE"`
	TargetNamespaces                             string         `env:"OPERATOR_TARGET_NAMESPACES"`
	ExcludeNamespaces                            string         `env:"OPERATOR_EXCLUDE_NAMESPACES"`
	ServiceAccount                               string         `env:"OPERATOR_SERVICE_ACCOUNT" envDefault:"trivy-operator"`
	LogDevMode                                   bool           `env:"OPERATOR_LOG_DEV_MODE" envDefault:"false"`
	ScanJobTimeout                               time.Duration  `env:"OPERATOR_SCAN_JOB_TIMEOUT" envDefault:"5m"`
	ConcurrentScanJobsLimit                      int            `env:"OPERATOR_CONCURRENT_SCAN_JOBS_LIMIT" envDefault:"10"`
	ScanJobRetryAfter                            time.Duration  `env:"OPERATOR_SCAN_JOB_RETRY_AFTER" envDefault:"30s"`
	BatchDeleteLimit                             int            `env:"OPERATOR_BATCH_DELETE_LIMIT" envDefault:"10"`
	BatchDeleteDelay                             time.Duration  `env:"OPERATOR_BATCH_DELETE_DELAY" envDefault:"10s"`
	MetricsBindAddress                           string         `env:"OPERATOR_METRICS_BIND_ADDRESS" envDefault:":8080"`
	MetricsFindingsEnabled                       bool           `env:"OPERATOR_METRICS_FINDINGS_ENABLED" envDefault:"true"`
	HealthProbeBindAddress                       string         `env:"OPERATOR_HEALTH_PROBE_BIND_ADDRESS" envDefault:":9090"`
	CISKubernetesBenchmarkEnabled                bool           `env:"OPERATOR_CIS_KUBERNETES_BENCHMARK_ENABLED" envDefault:"false"`
	VulnerabilityScannerEnabled                  bool           `env:"OPERATOR_VULNERABILITY_SCANNER_ENABLED" envDefault:"true"`
	VulnerabilityScannerScanOnlyCurrentRevisions bool           `env:"OPERATOR_VULNERABILITY_SCANNER_SCAN_ONLY_CURRENT_REVISIONS" envDefault:"true"`
	VulnerabilityScannerReportTTL                *time.Duration `env:"OPERATOR_VULNERABILITY_SCANNER_REPORT_TTL" envDefault:"24h"`
	ClusterComplianceEnabled                     bool           `env:"OPERATOR_CLUSTER_COMPLIANCE_ENABLED" envDefault:"false"`
	ConfigAuditScannerEnabled                    bool           `env:"OPERATOR_CONFIG_AUDIT_SCANNER_ENABLED" envDefault:"true"`
	RbacAssessmentScannerEnabled                 bool           `env:"OPERATOR_RBAC_ASSESSMENT_SCANNER_ENABLED" envDefault:"true"`
	ConfigAuditScannerScanOnlyCurrentRevisions   bool           `env:"OPERATOR_CONFIG_AUDIT_SCANNER_SCAN_ONLY_CURRENT_REVISIONS" envDefault:"true"`
	LeaderElectionEnabled                        bool           `env:"OPERATOR_LEADER_ELECTION_ENABLED" envDefault:"false"`
	LeaderElectionID                             string         `env:"OPERATOR_LEADER_ELECTION_ID" envDefault:"trivyoperator-lock"`
	ExposedSecretScannerEnabled                  bool           `env:"OPERATOR_EXPOSED_SECRET_SCANNER_ENABLED" envDefault:"true"`
}

// GetOperatorConfig loads Config from environment variables.
func GetOperatorConfig() (Config, error) {
	var config Config

	err := env.Parse(&config)
	if err != nil {
		return Config{}, err
	}

	return config, nil
}

// GetOperatorNamespace returns the namespace the operator should be running in.
func (c Config) GetOperatorNamespace() (string, error) {
	namespace := c.Namespace
	if namespace != "" {
		return namespace, nil
	}
	return "", fmt.Errorf("%s must be set", "OPERATOR_NAMESPACE")
}

// GetTargetNamespaces returns namespaces the operator should be watching for changes.
func (c Config) GetTargetNamespaces() []string {
	namespaces := c.TargetNamespaces
	if namespaces != "" {
		return strings.Split(namespaces, ",")
	}
	return []string{}
}

// InstallMode represents multitenancy support defined by the Operator Lifecycle Manager spec.
type InstallMode string

const (
	OwnNamespace    InstallMode = "OwnNamespace"
	SingleNamespace InstallMode = "SingleNamespace"
	MultiNamespace  InstallMode = "MultiNamespace"
	AllNamespaces   InstallMode = "AllNamespaces"
)

// ResolveInstallMode resolves InstallMode based on configured Config.Namespace and Config.TargetNamespaces.
func (c Config) ResolveInstallMode() (InstallMode, string, []string, error) {
	operatorNamespace, err := c.GetOperatorNamespace()
	if err != nil {
		return "", "", nil, err
	}
	targetNamespaces := c.GetTargetNamespaces()

	if len(targetNamespaces) == 1 && operatorNamespace == targetNamespaces[0] {
		return OwnNamespace, operatorNamespace, targetNamespaces, nil
	}
	if len(targetNamespaces) == 1 && operatorNamespace != targetNamespaces[0] {
		return SingleNamespace, operatorNamespace, targetNamespaces, nil
	}
	if len(targetNamespaces) > 1 {
		return MultiNamespace, operatorNamespace, targetNamespaces, nil
	}
	return AllNamespaces, operatorNamespace, targetNamespaces, nil
}
