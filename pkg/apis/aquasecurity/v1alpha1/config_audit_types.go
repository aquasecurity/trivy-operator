package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConfigAuditSummary counts failed checks by severity.
type ConfigAuditSummary struct {

	// CriticalCount is the number of failed checks with critical severity.
	CriticalCount int `json:"criticalCount"`

	// HighCount is the number of failed checks with high severity.
	HighCount int `json:"highCount"`

	// MediumCount is the number of failed checks with medium severity.
	MediumCount int `json:"mediumCount"`

	// LowCount is the number of failed check with low severity.
	LowCount int `json:"lowCount"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName={configaudit,configaudits}
// +kubebuilder:printcolumn:name="Scanner",type=string,JSONPath=`.report.scanner.name`,description="The name of the config audit scanner"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`,description="The age of the report"
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.report.summary.criticalCount`,priority=1,description="The number of failed checks with critical severity"
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.report.summary.highCount`,priority=1,description="The number of failed checks with high severity"
// +kubebuilder:printcolumn:name="Medium",type=integer,JSONPath=`.report.summary.mediumCount`,priority=1,description="The number of failed checks with medium severity"
// +kubebuilder:printcolumn:name="Low",type=integer,JSONPath=`.report.summary.lowCount`,priority=1,description="The number of failed checks with low severity"

// ConfigAuditReport is a specification for the ConfigAuditReport resource.
type ConfigAuditReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Report ConfigAuditReportData `json:"report"`
}

// +kubebuilder:object:root=true

// ConfigAuditReportList is a list of AuditConfig resources.
type ConfigAuditReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ConfigAuditReport `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName={clusterconfigaudit}
// +kubebuilder:printcolumn:name="Scanner",type=string,JSONPath=`.report.scanner.name`,description="The name of the config audit scanner"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`,description="The age of the report"
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.report.summary.criticalCount`,priority=1,description="The number of failed checks with critical severity"
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.report.summary.highCount`,priority=1,description="The number of failed checks with high severity"
// +kubebuilder:printcolumn:name="Medium",type=integer,JSONPath=`.report.summary.mediumCount`,priority=1,description="The number of failed checks with medium severity"
// +kubebuilder:printcolumn:name="Low",type=integer,JSONPath=`.report.summary.lowCount`,priority=1,description="The number of failed checks with low severity"

// ClusterConfigAuditReport is a specification for the ClusterConfigAuditReport resource.
type ClusterConfigAuditReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Report ConfigAuditReportData `json:"report"`
}

// +kubebuilder:object:root=true

// ClusterConfigAuditReportList is a list of ClusterConfigAuditReport resources.
type ClusterConfigAuditReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ClusterConfigAuditReport `json:"items"`
}

type ConfigAuditReportData struct {
	// +optional
	UpdateTimestamp metav1.Time `json:"updateTimestamp"`
	// +optional
	Scanner Scanner `json:"scanner"`
	// +optional
	Summary ConfigAuditSummary `json:"summary"`

	// Checks provides results of conducting audit steps.
	Checks []Check `json:"checks"`
}

// CheckScope has Type and Value fields to further identify a given Check.
// For example, we can use `Container` as Type and `nginx` as Value to indicate
// that a particular check is relevant to the nginx container. Alternatively,
// Type may be `JSONPath` and the Value would be JSONPath expression, e.g.
// `.spec.container[0].securityContext.allowPrivilegeEscalation`.
//
// Another use case for CheckScope is to inspect a ConfigMap with many keys and
// indicate a troublesome key. In this case the Type would be `ConfigMapKey`
// and the Value will hold the name of a key, e.g. `myawsprivatekey`.
type CheckScope struct {

	// Type indicates type of this scope, e.g. Container, ConfigMapKey or JSONPath.
	Type string `json:"type"`

	// Value indicates value of this scope that depends on Type, e.g. container name, ConfigMap key or JSONPath expression
	Value string `json:"value"`
}

// Check provides the result of conducting a single audit step.
type Check struct {
	ID          string   `json:"checkID"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category,omitempty"`

	Messages []string `json:"messages,omitempty"`

	// Remediation provides description or links to external resources to remediate failing check.
	// +optional
	Remediation string `json:"remediation,omitempty"`

	Success bool `json:"success"`

	// Scope indicates the section of config that was audited.
	// +optional
	Scope *CheckScope `json:"scope,omitempty"`
}

func ConfigAuditSummaryFromChecks(checks []Check) ConfigAuditSummary {
	summary := ConfigAuditSummary{}

	for _, check := range checks {
		if check.Success {
			continue
		}
		switch check.Severity {
		case SeverityCritical:
			summary.CriticalCount++
		case SeverityHigh:
			summary.HighCount++
		case SeverityMedium:
			summary.MediumCount++
		case SeverityLow:
			summary.LowCount++
		}
	}

	return summary
}
