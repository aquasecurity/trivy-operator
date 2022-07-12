package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//+kubebuilder:object:root=true
//+kubebuilder:resource:scope=Cluster,shortName={compliancedetail}
//+kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`,description="The age of the report"
//+kubebuilder:printcolumn:name="Fail",type=integer,JSONPath=`.report.summary.failCount`,priority=1,description="The number of checks that failed with Danger status"
//+kubebuilder:printcolumn:name="Pass",type=integer,JSONPath=`.report.summary.passCount`,priority=1,description="The number of checks that passed"

// ClusterComplianceDetailReport is a specification for the ClusterComplianceDetailReport resource.
type ClusterComplianceDetailReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Report            ClusterComplianceDetailReportData `json:"report"`
}

//+kubebuilder:object:root=true

// ClusterComplianceDetailReportList is a list of compliance kinds.
type ClusterComplianceDetailReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ClusterComplianceReport `json:"items"`
}

type ClusterComplianceDetailReportData struct {
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Format=date-time
	UpdateTimestamp metav1.Time              `json:"updateTimestamp"`
	Type            Compliance               `json:"type"`
	Summary         ClusterComplianceSummary `json:"summary"`
	ControlChecks   []ControlCheckDetails    `json:"controlCheck"`
}

// ControlCheckDetails provides the result of conducting a single audit step.
type ControlCheckDetails struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	//+kubebuilder:validation:Enum={CRITICAL,HIGH,MEDIUM,LOW}
	Severity           Severity             `json:"severity"`
	ScannerCheckResult []ScannerCheckResult `json:"checkResults"`
}

type ResultDetails struct {
	Name      string        `json:"name,omitempty"`
	Namespace string        `json:"namespace,omitempty"`
	Msg       string        `json:"msg"`
	Status    ControlStatus `json:"status"`
}

type ScannerCheckResult struct {
	ObjectType  string          `json:"objectType"`
	ID          string          `json:"id,omitempty"`
	Remediation string          `json:"remediation,omitempty"`
	Details     []ResultDetails `json:"details"`
}

// Compliance is the specs for a security assessment report.
type Compliance struct {
	// Name the name of the compliance report.
	Name string `json:"name"`
	// Description of the compliance report.
	Description string `json:"description"`

	// Version the compliance report.
	Version string `json:"version"`
}
