package etc

import (
	"encoding/json"
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
	ScanJobTTL                                   *time.Duration `env:"OPERATOR_SCAN_JOB_TTL"`
	ConcurrentScanJobsLimit                      int            `env:"OPERATOR_CONCURRENT_SCAN_JOBS_LIMIT" envDefault:"10"`
	ConcurrentNodeCollectorLimit                 int            `env:"OPERATOR_CONCURRENT_NODE_COLLECTOR_LIMIT" envDefault:"1"`
	ScanJobRetryAfter                            time.Duration  `env:"OPERATOR_SCAN_JOB_RETRY_AFTER" envDefault:"30s"`
	BatchDeleteLimit                             int            `env:"OPERATOR_BATCH_DELETE_LIMIT" envDefault:"10"`
	BatchDeleteDelay                             time.Duration  `env:"OPERATOR_BATCH_DELETE_DELAY" envDefault:"10s"`
	MetricsBindAddress                           string         `env:"OPERATOR_METRICS_BIND_ADDRESS" envDefault:":8080"`
	MetricsFindingsEnabled                       bool           `env:"OPERATOR_METRICS_FINDINGS_ENABLED" envDefault:"true"`
	MetricsVulnerabilityId                       bool           `env:"OPERATOR_METRICS_VULN_ID_ENABLED" envDefault:"false"`
	MetricsExposedSecretInfo                     bool           `env:"OPERATOR_METRICS_EXPOSED_SECRET_INFO_ENABLED" envDefault:"false"`
	MetricsConfigAuditInfo                       bool           `env:"OPERATOR_METRICS_CONFIG_AUDIT_INFO_ENABLED" envDefault:"false"`
	MetricsRbacAssessmentInfo                    bool           `env:"OPERATOR_METRICS_RBAC_ASSESSMENT_INFO_ENABLED" envDefault:"false"`
	MetricsInfraAssessmentInfo                   bool           `env:"OPERATOR_METRICS_INFRA_ASSESSMENT_INFO_ENABLED" envDefault:"false"`
	MetricsImageInfo                             bool           `env:"OPERATOR_METRICS_IMAGE_INFO_ENABLED" envDefault:"false"`
	MetricsClusterComplianceInfo                 bool           `env:"OPERATOR_METRICS_CLUSTER_COMPLIANCE_INFO_ENABLED" envDefault:"false"`
	HealthProbeBindAddress                       string         `env:"OPERATOR_HEALTH_PROBE_BIND_ADDRESS" envDefault:":9090"`
	VulnerabilityScannerEnabled                  bool           `env:"OPERATOR_VULNERABILITY_SCANNER_ENABLED" envDefault:"true"`
	SbomGenerationEnable                         bool           `env:"OPERATOR_SBOM_GENERATION_ENABLED" envDefault:"true"`
	VulnerabilityScannerScanOnlyCurrentRevisions bool           `env:"OPERATOR_VULNERABILITY_SCANNER_SCAN_ONLY_CURRENT_REVISIONS" envDefault:"true"`
	ScannerReportTTL                             *time.Duration `env:"OPERATOR_SCANNER_REPORT_TTL" envDefault:"24h"`
	CacheReportTTL                               *time.Duration `env:"OPERATOR_CACHE_REPORT_TTL" envDefault:"120h"`
	ClusterComplianceEnabled                     bool           `env:"OPERATOR_CLUSTER_COMPLIANCE_ENABLED" envDefault:"true"`
	InvokeClusterComplianceOnce                  bool           `env:"OPERATOR_INVOKE_CLUSTER_COMPLIANCE_ONCE" envDefault:"false"` // for testing purposes only
	ConfigAuditScannerEnabled                    bool           `env:"OPERATOR_CONFIG_AUDIT_SCANNER_ENABLED" envDefault:"true"`
	RbacAssessmentScannerEnabled                 bool           `env:"OPERATOR_RBAC_ASSESSMENT_SCANNER_ENABLED" envDefault:"true"`
	InfraAssessmentScannerEnabled                bool           `env:"OPERATOR_INFRA_ASSESSMENT_SCANNER_ENABLED" envDefault:"true"`
	ConfigAuditScannerScanOnlyCurrentRevisions   bool           `env:"OPERATOR_CONFIG_AUDIT_SCANNER_SCAN_ONLY_CURRENT_REVISIONS" envDefault:"true"`
	LeaderElectionEnabled                        bool           `env:"OPERATOR_LEADER_ELECTION_ENABLED" envDefault:"false"`
	LeaderElectionID                             string         `env:"OPERATOR_LEADER_ELECTION_ID" envDefault:"trivyoperator-lock"`
	ExposedSecretScannerEnabled                  bool           `env:"OPERATOR_EXPOSED_SECRET_SCANNER_ENABLED" envDefault:"true"`
	WebhookBroadcastURL                          string         `env:"OPERATOR_WEBHOOK_BROADCAST_URL"`
	WebhookBroadcastTimeout                      *time.Duration `env:"OPERATOR_WEBHOOK_BROADCAST_TIMEOUT" envDefault:"30s"`
	WebhookSendDeletedReports                    bool           `env:"OPERATOR_SEND_DELETED_REPORTS" envDefault:"false"`
	TargetWorkloads                              string         `env:"OPERATOR_TARGET_WORKLOADS" envDefault:"Pod,ReplicaSet,ReplicationController,StatefulSet,DaemonSet,CronJob,Job"`
	AccessGlobalSecretsAndServiceAccount         bool           `env:"OPERATOR_ACCESS_GLOBAL_SECRETS_SERVICE_ACCOUNTS" envDefault:"true"`
	PrivateRegistryScanSecretsNames              string         `env:"OPERATOR_PRIVATE_REGISTRY_SCAN_SECRETS_NAMES"`
	BuiltInTrivyServer                           bool           `env:"OPERATOR_BUILT_IN_TRIVY_SERVER" envDefault:"false"`
	TrivyServerHealthCheckCacheExpiration        *time.Duration `env:"TRIVY_SERVER_HEALTH_CHECK_CACHE_EXPIRATION" envDefault:"10h"`
	MergeRbacFindingWithConfigAudit              bool           `env:"OPERATOR_MERGE_RBAC_FINDING_WITH_CONFIG_AUDIT" envDefault:"false"`
	ControllerCacheSyncTimeout                   *time.Duration `env:"CONTROLLER_CACHE_SYNC_TIMEOUT" envDefault:"5m"`
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

func (c Config) GetPrivateRegistryScanSecretsNames() (map[string]string, error) {
	privateRegistryScanSecretsNames := c.PrivateRegistryScanSecretsNames
	secretsInfoMap := map[string]string{}
	if privateRegistryScanSecretsNames != "" {
		err := json.Unmarshal([]byte(privateRegistryScanSecretsNames), &secretsInfoMap)
		if err != nil {
			return nil, fmt.Errorf("failed parsing incorrectly formatted information about namespaces and secrets: %s", privateRegistryScanSecretsNames)
		}
	}
	return secretsInfoMap, nil
}

func (c Config) GetTargetWorkloads() []string {
	workloads := c.TargetWorkloads
	if workloads != "" {
		return strings.Split(strings.ToLower(workloads), ",")
	}

	return []string{"pod", "replicaset", "replicationcontroller", "statefulset", "daemonset", "cronjob", "job"}
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
