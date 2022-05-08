package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	CISKubeBenchReportCRName    = "ciskubebenchreports.aquasecurity.github.io"
	CISKubeBenchReportCRVersion = "v1alpha1"
	CISKubeBenchReportKind      = "CISKubeBenchReport"
	CISKubeBenchReportListKind  = "CISKubeBenchReportList"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CISKubeBenchReport is a specification for the CISKubeBenchReport resource.
type CISKubeBenchReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Report CISKubeBenchReportData `json:"report"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CISKubeBenchReportList is a list of CISKubeBenchReport resources.
type CISKubeBenchReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []CISKubeBenchReport `json:"items"`
}

type CISKubeBenchReportData struct {
	UpdateTimestamp metav1.Time           `json:"updateTimestamp"`
	Scanner         Scanner               `json:"scanner"`
	Summary         CISKubeBenchSummary   `json:"summary"`
	Sections        []CISKubeBenchSection `json:"sections"`
}

type CISKubeBenchSummary struct {
	PassCount int `json:"passCount"`
	InfoCount int `json:"infoCount"`
	WarnCount int `json:"warnCount"`
	FailCount int `json:"failCount"`
}

type CISKubeBenchSection struct {
	ID        string `json:"id"`
	Version   string `json:"version"`
	Text      string `json:"text"`
	NodeType  string `json:"node_type"`
	TotalPass int    `json:"total_pass"`
	TotalFail int    `json:"total_fail"`
	TotalWarn int    `json:"total_warn"`
	TotalInfo int    `json:"total_info"`

	Tests []CISKubeBenchTests `json:"tests"`
}

type CISKubeBenchTests struct {
	Section string `json:"section"`
	Pass    int    `json:"pass"`
	Fail    int    `json:"fail"`
	Warn    int    `json:"warn"`
	Info    int    `json:"info"`
	Desc    string `json:"desc"`

	Results []CISKubeBenchResult `json:"results"`
}

type CISKubeBenchResult struct {
	TestNumber  string `json:"test_number"`
	TestDesc    string `json:"test_desc"`
	Remediation string `json:"remediation"`
	Status      string `json:"status"`
	Scored      bool   `json:"scored"`
}
