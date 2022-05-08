package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	KubeHunterReportCRName    = "kubehunterreports.aquasecurity.github.io"
	KubeHunterReportCRVersion = "v1alpha1"
	KubeHunterReportKind      = "KubeHunterReport"
	KubeHunterReportListKind  = "KubeHunterReportList"
)

const (
	KubeHunterSeverityHigh    Severity = "high"
	KubeHunterSeverityMedium  Severity = "medium"
	KubeHunterSeverityLow     Severity = "low"
	KubeHunterSeverityUnknown Severity = "unknown"
)

type KubeHunterSummary struct {
	HighCount    int `json:"highCount"`
	MediumCount  int `json:"mediumCount"`
	LowCount     int `json:"lowCount"`
	UnknownCount int `json:"unknownCount"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// KubeHunterReport is a specification for the KubeHunterReport resource.
type KubeHunterReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Report KubeHunterReportData `json:"report"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// KubeHunterReportList is a list of KubeHunterReport resources.
type KubeHunterReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []KubeHunterReport `json:"items"`
}

type KubeHunterReportData struct {
	UpdateTimestamp metav1.Time               `json:"updateTimestamp"`
	Scanner         Scanner                   `json:"scanner"`
	Summary         KubeHunterSummary         `json:"summary"`
	Vulnerabilities []KubeHunterVulnerability `json:"vulnerabilities"`
}

type KubeHunterVulnerability struct {
	Location      string   `json:"location"`      // e.g. "Local to Pod(kube-hunter-sj7zj)"
	ID            string   `json:"vid"`           // e.g. "KHV050"
	Category      string   `json:"category"`      // e.g. "Access Risk"
	Severity      Severity `json:"severity"`      // e.g. "low"
	Vulnerability string   `json:"vulnerability"` // e.g. "Read access to pod's service account token"
	Description   string   `json:"description"`   // e.g. "Accessing the pod service account token gives an attacker the option to use the server API"
	Evidence      string   `json:"evidence"`      // e.g. "eyJhbGciOiJSUzI1NiIMXA1..."
	Hunter        string   `json:"hunter"`        // e.g. "Access Secrets"
	AvdReference  string   `json:"avd_reference"` // e.g. "Aqua vulnerability database reference"
}
