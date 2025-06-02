package metrics

import (
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

type SeverityLabel struct {
	Severity v1alpha1.Severity
	Label    string
}

func SeverityCritical() SeverityLabel {
	return SeverityLabel{
		Severity: v1alpha1.SeverityCritical,
		Label:    "Critical",
	}
}
func SeverityHigh() SeverityLabel {
	return SeverityLabel{
		Severity: v1alpha1.SeverityHigh,
		Label:    "High",
	}
}
func SeverityMedium() SeverityLabel {
	return SeverityLabel{
		Severity: v1alpha1.SeverityMedium,
		Label:    "Medium",
	}
}
func SeverityLow() SeverityLabel {
	return SeverityLabel{
		Severity: v1alpha1.SeverityLow,
		Label:    "Low",
	}
}
func SeverityUnknown() SeverityLabel {
	return SeverityLabel{
		Severity: v1alpha1.SeverityUnknown,
		Label:    "Unknown",
	}
}

func NewSeverityLabel(severity v1alpha1.Severity) SeverityLabel {
	m := map[v1alpha1.Severity]SeverityLabel{
		v1alpha1.SeverityCritical: SeverityCritical(),
		v1alpha1.SeverityHigh:     SeverityHigh(),
		v1alpha1.SeverityMedium:   SeverityMedium(),
		v1alpha1.SeverityLow:      SeverityLow(),
		v1alpha1.SeverityUnknown:  SeverityUnknown(),
	}
	if sevLbl, ok := m[severity]; ok {
		return sevLbl
	}
	return SeverityLabel{
		Severity: severity,
		Label:    cases.Title(language.Und).String(string(severity)),
	}
}

type StatusLabel struct {
	Status Status
	Label  string
}

type Status v1alpha1.ControlStatus

const (
	FailStatus Status = "FAIL"
	PassStatus Status = "PASS"
)

func StatusFail() StatusLabel {
	return StatusLabel{
		Status: FailStatus,
		Label:  "Fail",
	}
}
func StatusPass() StatusLabel {
	return StatusLabel{
		Status: PassStatus,
		Label:  "Pass",
	}
}

func NewStatusLabel(status Status) StatusLabel {
	m := map[Status]StatusLabel{
		FailStatus: StatusFail(),
		PassStatus: StatusPass(),
	}
	if sevLbl, ok := m[status]; ok {
		return sevLbl
	}
	return StatusLabel{
		Status: status,
		Label:  cases.Title(language.Und).String(string(status)),
	}
}
