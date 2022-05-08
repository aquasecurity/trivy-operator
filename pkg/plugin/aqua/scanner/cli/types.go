package cli

import "github.com/aquasecurity/trivy-operator/pkg/plugin/aqua/client"

type ResourceType int

const (
	_ ResourceType = iota
	Library
	Package
)

// Command to scan image or filesystem.
type Command string

const (
	Filesystem Command = "filesystem"
	Image      Command = "image"
)

type Options struct {
	Version      string
	BaseURL      string
	Credentials  client.UsernameAndPassword
	RegistryName string
	Command      string
}

type ScanReport struct {
	Image          string               `json:"image"`
	Registry       string               `json:"registry"`
	Digest         string               `json:"digest"`
	OS             string               `json:"os"`
	Version        string               `json:"version"`
	PullName       string               `json:"pull_name"`
	InitiatingUser string               `json:"initiating_user"`
	Resources      []ResourceScan       `json:"resources"`
	Summary        VulnerabilitySummary `json:"vulnerability_summary"`
	Warnings       []Warning            `json:"warnings"`
	ScanOptions    ScanOptions          `json:"scan_options"`
}

type ResourceScan struct {
	Resource        Resource        `json:"resource"`
	Scanned         bool            `json:"scanned"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Resource struct {
	Type    ResourceType `json:"type"`
	Path    string       `json:"path"`
	Name    string       `json:"name"`
	Version string       `json:"version"`
}

type Vulnerability struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	FixVersion  string `json:"fix_version"`

	VendorURL        string `json:"vendor_url"`
	VendorSeverity   string `json:"vendor_severity"`
	VendorSeverityV3 string `json:"vendor_severity_v3"`

	NVDURL        string  `json:"nvd_url"`
	NVDSeverity   string  `json:"nvd_severity"`
	NVDScore      float32 `json:"nvd_score"`
	NVDSeverityV3 string  `json:"nvd_severity_v3"`
	NVDScoreV3    float32 `json:"nvd_score_v3"`

	AquaSeverity      string  `json:"aqua_severity"`
	AquaScore         float32 `json:"aqua_score"`
	AquaScoringSystem string  `json:"aqua_scoring_system"`
}

type VulnerabilitySummary struct {
	Total      int `json:"total"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Negligible int `json:"negligible"`
	Sensitive  int `json:"sensitive"`
	Malware    int `json:"malware"`
	Critical   int `json:"critical"`
}

type ScanOptions struct {
	ScanMalware              bool `json:"scan_malware"`
	ScanFiles                bool `json:"scan_files"`
	ManualPullFallback       bool `json:"manual_pull_fallback"`
	SaveAdHockScans          bool `json:"save_adhoc_scans"`
	Dockerless               bool `json:"dockerless"`
	EnableFastScanning       bool `json:"enable_fast_scanning"`
	SuggestOSUpgrade         bool `json:"suggest_os_upgrade"`
	IncludeSiblingAdvisories bool `json:"include_sibling_advisories"`
	UseCVSS3                 bool `json:"use_cvss3"`
}

type Warning struct {
}
