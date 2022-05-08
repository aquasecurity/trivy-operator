package trivy

import (
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

type ScanResult struct {
	Target          string          `json:"Target"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
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
	Cvss             map[string]*CVSS  `json:"CVSS"`
}

type CVSS struct {
	V3Score *float64 `json:"V3Score,omitempty"`
}

type Layer struct {
	Digest string `json:"Digest"`
	DiffID string `json:"DiffID"`
}
