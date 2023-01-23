package trivy

import (
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

type ScanResult struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
	Secrets         []Secret        `json:"Secrets"`
}

type ScanReport struct {
	Results []ScanResult `json:"Results"`
}

type Vulnerability struct {
	VulnerabilityID  string            `json:"VulnerabilityID"`
	PkgName          string            `json:"PkgName"`
	InstalledVersion string            `json:"InstalledVersion"`
	FixedVersion     string            `json:"FixedVersion"`
	Title            string            `json:"Title"`
	Description      string            `json:"Description"`
	Severity         v1alpha1.Severity `json:"Severity"`
	Layer            Layer             `json:"Layer"`
	PrimaryURL       string            `json:"PrimaryURL"`
	References       []string          `json:"References"`
	CVSS             types.VendorCVSS  `json:"CVSS"`
	Target           string            `json:"Target"`
	Class            string            `json:"Class"`
}

type CVSS struct {
	V3Score  *float64 `json:"V3Score,omitempty"`
	V3Vector *string  `json:"V3Vector,omitempty"`
}

type Layer struct {
	Digest string `json:"Digest"`
	DiffID string `json:"DiffID"`
}

type Secret struct {
	Target   string            `json:"Target"`
	RuleID   string            `json:"RuleID"`
	Category string            `json:"Category"`
	Severity v1alpha1.Severity `json:"Severity"`
	Title    string            `json:"Title"`
	Match    string            `json:"Match"`
}
