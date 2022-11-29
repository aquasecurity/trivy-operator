package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ClusterComplianceSummary struct {
	PassCount int `json:"passCount"`
	FailCount int `json:"failCount"`
}

//+kubebuilder:object:root=true
//+kubebuilder:resource:scope=Cluster,shortName={compliance}
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`,description="The age of the report"
//+kubebuilder:printcolumn:name="Fail",type=integer,JSONPath=`.status.summary.failCount`,priority=1,description="The number of checks that failed with Danger status"
//+kubebuilder:printcolumn:name="Pass",type=integer,JSONPath=`.status.summary.passCount`,priority=1,description="The number of checks that passed"

// ClusterComplianceReport is a specification for the ClusterComplianceReport resource.
type ClusterComplianceReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ReportSpec   `json:"spec,omitempty"`
	Status            ReportStatus `json:"status,omitempty"`
}

// ReportSpec represent the compliance specification
type ReportSpec struct {
	// cron define the intervals for report generation
	//+kubebuilder:validation:Pattern=`^(((([\*]{1}){1})|((\*\/){0,1}(([0-9]{1}){1}|(([1-5]{1}){1}([0-9]{1}){1}){1}))) ((([\*]{1}){1})|((\*\/){0,1}(([0-9]{1}){1}|(([1]{1}){1}([0-9]{1}){1}){1}|([2]{1}){1}([0-3]{1}){1}))) ((([\*]{1}){1})|((\*\/){0,1}(([1-9]{1}){1}|(([1-2]{1}){1}([0-9]{1}){1}){1}|([3]{1}){1}([0-1]{1}){1}))) ((([\*]{1}){1})|((\*\/){0,1}(([1-9]{1}){1}|(([1-2]{1}){1}([0-9]{1}){1}){1}|([3]{1}){1}([0-1]{1}){1}))|(jan|feb|mar|apr|may|jun|jul|aug|sep|okt|nov|dec)) ((([\*]{1}){1})|((\*\/){0,1}(([0-7]{1}){1}))|(sun|mon|tue|wed|thu|fri|sat)))$`
	Cron         string     `json:"cron"`
	ReportFormat string     `json:"reportFormat"`
	Complaince   Complaince `json:"complaince"`
}

type Complaince struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	Version          string   `json:"version"`
	RelatedResources []string `json:"relatedResources"`
	// Control represent the cps controls data and mapping checks
	Controls []Control `json:"controls"`
}

// Control represent the cps controls data and mapping checks
type Control struct {
	// id define the control check id
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// kinds define the list of kinds control check apply on, example: Node,Workload
	Kinds   []string `json:"kinds"`
	Mapping Mapping  `json:"mapping"`
	// define the severity of the control
	//+kubebuilder:validation:Enum={CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN}
	Severity Severity `json:"severity"`
	// define the default value for check status in case resource not found
	//+kubebuilder:validation:Enum={PASS,WARN,FAIL}
	DefaultStatus ControlStatus `json:"defaultStatus,omitempty"`
}

// SpecCheck represent the scanner who perform the control check
type SpecCheck struct {
	// id define the check id as produced by scanner
	ID string `json:"id"`
}

// Mapping represent the scanner who perform the control check
type Mapping struct {
	// scanner define the name of the scanner which produce data, currently only config-audit is supported
	//+kubebuilder:validation:Pattern=`^config-audit$`
	Scanner string      `json:"scanner"`
	Checks  []SpecCheck `json:"checks"`
}

//+kubebuilder:object:root=true

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
