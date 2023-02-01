package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RbacAssessmentSummary counts failed checks by severity.
type RbacAssessmentSummary struct {

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
// +kubebuilder:resource:shortName={rbacassessment,rbacassessments}
// +kubebuilder:printcolumn:name="Scanner",type=string,JSONPath=`.report.scanner.name`,description="The name of the rbac assessment scanner"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`,description="The age of the report"
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.report.summary.criticalCount`,priority=1,description="The number of failed checks with critical severity"
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.report.summary.highCount`,priority=1,description="The number of failed checks with high severity"
// +kubebuilder:printcolumn:name="Medium",type=integer,JSONPath=`.report.summary.mediumCount`,priority=1,description="The number of failed checks with medium severity"
// +kubebuilder:printcolumn:name="Low",type=integer,JSONPath=`.report.summary.lowCount`,priority=1,description="The number of failed checks with low severity"

// RbacAssessmentReport is a specification for the RbacAssessmentReport resource.
type RbacAssessmentReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Report RbacAssessmentReportData `json:"report"`
}

// +kubebuilder:object:root=true

// RbacAssessmentReportList is a list of Rbac assessment resources.
type RbacAssessmentReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []RbacAssessmentReport `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName={clusterrbacassessmentreport}
// +kubebuilder:printcolumn:name="Scanner",type=string,JSONPath=`.report.scanner.name`,description="The name of the rbac assessment scanner"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`,description="The age of the report"
// +kubebuilder:printcolumn:name="Critical",type=integer,JSONPath=`.report.summary.criticalCount`,priority=1,description="The number of failed checks with critical severity"
// +kubebuilder:printcolumn:name="High",type=integer,JSONPath=`.report.summary.highCount`,priority=1,description="The number of failed checks with high severity"
// +kubebuilder:printcolumn:name="Medium",type=integer,JSONPath=`.report.summary.mediumCount`,priority=1,description="The number of failed checks with medium severity"
// +kubebuilder:printcolumn:name="Low",type=integer,JSONPath=`.report.summary.lowCount`,priority=1,description="The number of failed checks with low severity"

// ClusterRbacAssessmentReport is a specification for the ClusterRbacAssessmentReport resource.
type ClusterRbacAssessmentReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Report RbacAssessmentReportData `json:"report"`
}

// +kubebuilder:object:root=true

// ClusterRbacAssessmentReportList is a list of ClusterRbacAssessmentReport resources.
type ClusterRbacAssessmentReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ClusterRbacAssessmentReport `json:"items"`
}

type RbacAssessmentReportData struct {
	Scanner Scanner               `json:"scanner"`
	Summary RbacAssessmentSummary `json:"summary"`

	// Checks provides results of conducting audit steps.
	Checks []Check `json:"checks"`
}

func RbacAssessmentSummaryFromChecks(checks []Check) RbacAssessmentSummary {
	summary := RbacAssessmentSummary{}

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
