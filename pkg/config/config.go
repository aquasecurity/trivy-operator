package config

import (
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type Config struct {
	config     etc.Config
	configData trivyoperator.ConfigData
}

func GetConfig(config etc.Config, configData trivyoperator.ConfigData) Config {
	return Config{
		config:     config,
		configData: configData,
	}
}

func (cfg Config) ResolveInstallMode() (etc.InstallMode, string, []string, error) {
	return cfg.config.ResolveInstallMode()
}

func (cfg Config) ExcludeNamespaces() string {
	return cfg.config.ExcludeNamespaces
}

func (cfg Config) MetricsBindAddress() string {
	return cfg.config.MetricsBindAddress
}

func (cfg Config) HealthProbeBindAddress() string {
	return cfg.config.HealthProbeBindAddress
}

func (cfg Config) LeaderElectionEnabled() bool {
	return cfg.config.LeaderElectionEnabled
}

func (cfg Config) LeaderElectionID() string {
	return cfg.config.LeaderElectionID
}

func (cfg Config) VulnerabilityScannerEnabled() bool {
	return cfg.configData.VulnerabilityScannerEnabled()
}

func (cfg Config) ExposedSecretsScannerEnabled() bool {
	return cfg.configData.ExposedSecretsScannerEnabled()
}

func (cfg Config) VulnerabilityScannerReportTTL() *time.Duration {
	return cfg.config.VulnerabilityScannerReportTTL
}

func (cfg Config) ConfigAuditScannerEnabled() bool {
	return cfg.config.ConfigAuditScannerEnabled
}

func (cfg Config) ServiceAccount() string {
	return cfg.config.ServiceAccount
}

func (cfg Config) ClusterComplianceEnabled() bool {
	return cfg.config.ClusterComplianceEnabled
}

func (cfg Config) MetricsFindingsEnabled() bool {
	return cfg.config.MetricsFindingsEnabled
}

func (cfg Config) GetVulnerabilityReportsScanner() (trivyoperator.Scanner, error) {
	return cfg.configData.GetVulnerabilityReportsScanner()
}

func (cfg Config) VulnerabilityScanJobsInSameNamespace() bool {
	return cfg.configData.VulnerabilityScanJobsInSameNamespace()
}

func (cfg Config) GetConfigAuditReportsScanner() (trivyoperator.Scanner, error) {
	return cfg.configData.GetConfigAuditReportsScanner()
}

func (cfg Config) VulnerabilityScannerScanOnlyCurrentRevisions() bool {
	return cfg.config.VulnerabilityScannerScanOnlyCurrentRevisions
}

func (cfg Config) Namespace() string {
	return cfg.config.Namespace
}

func (cfg Config) ConcurrentScanJobsLimit() int {
	return cfg.config.ConcurrentScanJobsLimit
}

func (cfg Config) ScanJobRetryAfter() time.Duration {
	return cfg.config.ScanJobRetryAfter
}

func (cfg Config) GetScanJobTolerations() ([]corev1.Toleration, error) {
	return cfg.configData.GetScanJobTolerations()
}

func (cfg Config) GetScanJobAnnotations() (map[string]string, error) {
	return cfg.configData.GetScanJobAnnotations()
}

func (cfg Config) GetScanJobNodeSelector() (map[string]string, error) {
	return cfg.configData.GetScanJobNodeSelector()
}

func (cfg Config) GetScanJobPodSecurityContext() (*corev1.PodSecurityContext, error) {
	return cfg.configData.GetScanJobPodSecurityContext()
}

func (cfg Config) GetScanJobPodTemplateLabels() (labels.Set, error) {
	return cfg.configData.GetScanJobPodTemplateLabels()
}

func (cfg Config) ScanJobTimeout() time.Duration {
	return cfg.config.ScanJobTimeout
}

func (cfg Config) ConfigAuditScannerScanOnlyCurrentRevisions() bool {
	return cfg.config.ConfigAuditScannerScanOnlyCurrentRevisions
}

func (cfg Config) RbacAssessmentScannerEnabled() bool {
	return cfg.config.RbacAssessmentScannerEnabled
}

func (cfg Config) BatchDeleteDelay() time.Duration {
	return cfg.config.BatchDeleteDelay
}

func (cfg Config) BatchDeleteLimit() int {
	return cfg.config.BatchDeleteLimit
}

func (cfg Config) ComplianceFailEntriesLimit() int {
	return cfg.configData.ComplianceFailEntriesLimit()
}

func (cfg Config) GetTargetNamespaces() []string {
	return cfg.config.GetTargetNamespaces()
}

func (cfg Config) GetScanJobContainerSecurityContext() (*corev1.SecurityContext, error) {
	return cfg.configData.GetScanJobContainerSecurityContext()
}
