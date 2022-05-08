package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ClusterComplianceReportCRName = "clustercompliancereports.aquasecurity.github.io"
)

type ClusterComplianceSummary struct {
	PassCount int `json:"passCount"`
	FailCount int `json:"failCount"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterComplianceReport is a specification for the ClusterComplianceReport resource.
type ClusterComplianceReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ReportSpec   `json:"spec,omitempty"`
	Status            ReportStatus `json:"status,omitempty"`
}

//ReportSpec represent the compliance specification
type ReportSpec struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Cron        string    `json:"cron"`
	Version     string    `json:"version"`
	Controls    []Control `json:"controls"`
}

//Control represent the cps controls data and mapping checks
type Control struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Description   string        `json:"description,omitempty"`
	Kinds         []string      `json:"kinds"`
	Mapping       Mapping       `json:"mapping"`
	Severity      Severity      `json:"severity"`
	DefaultStatus ControlStatus `json:"defaultStatus,omitempty"`
}

//SpecCheck represent the scanner who perform the control check
type SpecCheck struct {
	ID string `json:"id"`
}

//Mapping represent the scanner who perform the control check
type Mapping struct {
	Scanner string      `json:"scanner"`
	Checks  []SpecCheck `json:"checks"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterComplianceReportList is a list of compliance kinds.
type ClusterComplianceReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ClusterComplianceReport `json:"items"`
}

type ReportStatus struct {
	UpdateTimestamp metav1.Time              `json:"updateTimestamp"`
	Summary         ClusterComplianceSummary `json:"summary"`
	ControlChecks   []ControlCheck           `json:"controlCheck"`
}

// ControlCheck provides the result of conducting a single audit step.
type ControlCheck struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	PassTotal   int      `json:"passTotal"`
	FailTotal   int      `json:"failTotal"`
	Severity    Severity `json:"severity"`
}

type ControlStatus string

const (
	FailStatus ControlStatus = "FAIL"
	PassStatus ControlStatus = "PASS"
	WarnStatus ControlStatus = "WARN"
)
