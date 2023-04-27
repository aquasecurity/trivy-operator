package v1alpha1

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy/pkg/compliance/report"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName={compliance}
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`,description="The age of the report"
// +kubebuilder:printcolumn:name="Fail",type=integer,JSONPath=`.status.summary.failCount`,priority=1,description="The number of checks that failed"
// +kubebuilder:printcolumn:name="Pass",type=integer,JSONPath=`.status.summary.passCount`,priority=1,description="The number of checks that passed"

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
	// +kubebuilder:validation:Pattern=`^(((([\*]{1}){1})|((\*\/){0,1}(([0-9]{1}){1}|(([1-5]{1}){1}([0-9]{1}){1}){1}))) ((([\*]{1}){1})|((\*\/){0,1}(([0-9]{1}){1}|(([1]{1}){1}([0-9]{1}){1}){1}|([2]{1}){1}([0-3]{1}){1}))) ((([\*]{1}){1})|((\*\/){0,1}(([1-9]{1}){1}|(([1-2]{1}){1}([0-9]{1}){1}){1}|([3]{1}){1}([0-1]{1}){1}))) ((([\*]{1}){1})|((\*\/){0,1}(([1-9]{1}){1}|(([1-2]{1}){1}([0-9]{1}){1}){1}|([3]{1}){1}([0-1]{1}){1}))|(jan|feb|mar|apr|may|jun|jul|aug|sep|okt|nov|dec)) ((([\*]{1}){1})|((\*\/){0,1}(([0-7]{1}){1}))|(sun|mon|tue|wed|thu|fri|sat)))$`
	Cron string `json:"cron"`
	// +kubebuilder:validation:Enum={summary,all}
	ReportFormat ReportType `json:"reportType"`
	Complaince   Complaince `json:"compliance"`
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
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Checks      []SpecCheck `json:"checks,omitempty"`
	// define the severity of the control
	// +kubebuilder:validation:Enum={CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN}
	Severity Severity `json:"severity"`
	// define the default value for check status in case resource not found
	// +kubebuilder:validation:Enum={PASS,WARN,FAIL}
	DefaultStatus ControlStatus `json:"defaultStatus,omitempty"`
}

// SpecCheck represent the scanner who perform the control check
type SpecCheck struct {
	// id define the check id as produced by scanner
	ID string `json:"id"`
}

// +kubebuilder:object:root=true

// ClusterComplianceReportList is a list of compliance kinds.
type ClusterComplianceReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []ClusterComplianceReport `json:"items"`
}

type ReportStatus struct {
	Summary ComplianceSummary `json:"summary,omitempty"`

	UpdateTimestamp metav1.Time `json:"updateTimestamp"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:XPreserveUnknownFields
	DetailReport *ComplianceReport `json:"detailReport,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:XPreserveUnknownFields
	SummaryReport *SummaryReport `json:"summaryReport,omitempty"`
}

type ComplianceSummary struct {
	FailCount int `json:"failCount,omitempty"`
	PassCount int `json:"passCount,omitempty"`
}

// SummaryReport represents a kubernetes scan report with consolidated findings
type SummaryReport struct {
	ID              string                `json:"id,omitempty"`
	Title           string                `json:"title,omitempty"`
	SummaryControls []ControlCheckSummary `json:"controlCheck,omitempty"`
}

type ControlCheckSummary struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Severity  string `json:"severity,omitempty"`
	TotalFail *int   `json:"totalFail,omitempty"`
}

type ControlStatus string

const (
	FailStatus ControlStatus = "FAIL"
	PassStatus ControlStatus = "PASS"
	WarnStatus ControlStatus = "WARN"
)

type ReportType string

const (
	ReportSummary ReportType = "summary"
	ReportDetail  ReportType = "all"
)

// ComplianceReport represents a kubernetes scan report
type ComplianceReport struct {
	ID               string                `json:"id,omitempty"`
	Title            string                `json:"title,omitempty"`
	Description      string                `json:"description,omitempty"`
	Version          string                `json:"version,omitempty"`
	RelatedResources []string              `json:"relatedVersion,omitempty"`
	Results          []*ControlCheckResult `json:"results,omitempty"`
}

type ControlCheckResult struct {
	ID            string                    `json:"id,omitempty"`
	Name          string                    `json:"name,omitempty"`
	Description   string                    `json:"description,omitempty"`
	DefaultStatus defsecTypes.ControlStatus `json:"status,omitempty"`
	Severity      string                    `json:"severity,omitempty"`
	Checks        []ComplianceCheck         `json:"checks"`
}

// ComplianceCheck provides the result of conducting a single compliance step.
type ComplianceCheck struct {
	ID          string   `json:"checkID"`
	Target      string   `json:"target,omitempty"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category,omitempty"`

	Messages []string `json:"messages,omitempty"`

	// Remediation provides description or links to external resources to remediate failing check.
	// +optional
	Remediation string `json:"remediation,omitempty"`

	Success bool `json:"success"`
}

// ToComplainceSpec map data from crd compliance spec to trivy compliance spec
func ToComplainceSpec(cSpec Complaince) spec.ComplianceSpec {
	specControls := make([]defsecTypes.Control, 0)
	for _, control := range cSpec.Controls {
		sChecks := make([]defsecTypes.SpecCheck, 0)
		for _, scheck := range control.Checks {
			sChecks = append(sChecks, defsecTypes.SpecCheck{ID: scheck.ID})
		}
		specControls = append(specControls, defsecTypes.Control{
			ID:            control.ID,
			Name:          control.Name,
			Description:   control.Description,
			Checks:        sChecks,
			Severity:      defsecTypes.Severity(control.Severity),
			DefaultStatus: defsecTypes.ControlStatus(control.DefaultStatus),
		})
	}
	compSpec := defsecTypes.Spec{
		ID:               cSpec.ID,
		Title:            cSpec.Title,
		Description:      cSpec.Description,
		Version:          cSpec.Version,
		RelatedResources: cSpec.RelatedResources,
		Controls:         specControls,
	}
	return spec.ComplianceSpec{Spec: compSpec}
}

// FromSummaryReport map data from trivy summary report to crd summary report
func FromSummaryReport(sr *report.SummaryReport) *SummaryReport {
	summaryControls := make([]ControlCheckSummary, 0)
	for _, sr := range sr.SummaryControls {
		summaryControls = append(summaryControls, ControlCheckSummary{
			ID:        sr.ID,
			Name:      sr.Name,
			Severity:  sr.Severity,
			TotalFail: sr.TotalFail,
		})
	}
	return &SummaryReport{
		ID:              sr.ID,
		Title:           sr.Title,
		SummaryControls: summaryControls,
	}
}

// FromDetailReport map data from trivy summary report to crd summary report
func FromDetailReport(sr *report.ComplianceReport) *ComplianceReport {
	controlResults := make([]*ControlCheckResult, 0)
	for _, sr := range sr.Results {
		checks := make([]ComplianceCheck, 0)
		for _, r := range sr.Results {
			for _, ms := range r.Misconfigurations {
				checks = append(checks, ComplianceCheck{
					ID:          ms.AVDID,
					Target:      r.Target,
					Title:       ms.Title,
					Description: ms.Description,
					Severity:    Severity(ms.Severity),
					Category:    "Kubernetes Security Check",
					Messages:    []string{ms.Message},
					Success:     false,
				})
			}
		}
		// mark check as pass of no misconfig issue found
		if len(checks) == 0 {
			checks = append(checks, ComplianceCheck{
				Success: true,
			})
		}
		controlResults = append(controlResults, &ControlCheckResult{
			ID:            sr.ID,
			Name:          sr.Name,
			Severity:      sr.Severity,
			Description:   sr.Description,
			DefaultStatus: sr.DefaultStatus,
			Checks:        checks,
		})
	}
	return &ComplianceReport{
		ID:               sr.ID,
		Title:            sr.Title,
		Version:          sr.Version,
		Description:      sr.Description,
		RelatedResources: sr.RelatedResources,
		Results:          controlResults,
	}
}

func TotalsCheckCount(sr *report.ComplianceReport) ComplianceSummary {
	var passCount int
	var failCount int
	for _, sr := range sr.Results {
		if len(sr.Results) == 0 {
			passCount++
			continue
		}
		failCount++
	}
	return ComplianceSummary{
		PassCount: passCount,
		FailCount: failCount,
	}
}
