package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// InfraAssessmentSummary counts failed checks by severity.
type InfraAssessmentSummary struct {

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
// +kubebuilder:resource:scope=Cluster,shortName={clusterinfraassessment}
// +kubebuilder:printcolumn:name="Scanner",type=string,JSONPath=`.report.scanner.name`,description="The name of the infra assessement scanner"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`,description="The age of the report"
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.report.summary.criticalCount`,priority=1,description="The number of failed checks with critical severity"
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.report.summary.highCount`,priority=1,description="The number of failed checks with high severity"
// +kubebuilder:printcolumn:name="Medium",type=integer,JSONPath=`.report.summary.mediumCount`,priority=1,description="The number of failed checks with medium severity"
// +kubebuilder:printcolumn:name="Low",type=integer,JSONPath=`.report.summary.lowCount`,priority=1,description="The number of failed checks with low severity"

// ClusterInfraAssessmentReport is a specification for the ClusterInfraAssessmentReport resource.
type ClusterInfraAssessmentReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Report InfraAssessmentReportData `json:"report"`
}

// +kubebuilder:object:root=true

// ClusterInfraAssessmentReportList is a list of ClusterInfraAssessmentRepor resources.
type ClusterInfraAssessmentReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ClusterInfraAssessmentReport `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName={infraassessment,infraassessments}
// +kubebuilder:printcolumn:name="Scanner",type=string,JSONPath=`.report.scanner.name`,description="The name of the infra assessment scanner"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`,description="The age of the report"
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.report.summary.criticalCount`,priority=1,description="The number of failed checks with critical severity"
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.report.summary.highCount`,priority=1,description="The number of failed checks with high severity"
// +kubebuilder:printcolumn:name="Medium",type=integer,JSONPath=`.report.summary.mediumCount`,priority=1,description="The number of failed checks with medium severity"
// +kubebuilder:printcolumn:name="Low",type=integer,JSONPath=`.report.summary.lowCount`,priority=1,description="The number of failed checks with low severity"

// InfraAssessmentReport is a specification for the InfraAssessmentReport resource.
type InfraAssessmentReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Report InfraAssessmentReportData `json:"report"`
}

// +kubebuilder:object:root=true

// InfraAssessmentReportList is a list of Infra assessment resources.
type InfraAssessmentReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []InfraAssessmentReport `json:"items"`
}

type InfraAssessmentReportData struct {
	Scanner Scanner                `json:"scanner"`
	Summary InfraAssessmentSummary `json:"summary"`

	// Checks provides results of conducting audit steps.
	Checks []Check `json:"checks"`
}

func InfraAssessmentSummaryFromChecks(checks []Check) InfraAssessmentSummary {
	summary := InfraAssessmentSummary{}

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
