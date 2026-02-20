package metrics

import (
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/shared"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

type SeverityLabel struct {
	Severity shared.Severity
	Label    string
}

func SeverityCritical() SeverityLabel {
	return SeverityLabel{
		Severity: shared.SeverityCritical,
		Label:    "Critical",
	}
}
func SeverityHigh() SeverityLabel {
	return SeverityLabel{
		Severity: shared.SeverityHigh,
		Label:    "High",
	}
}
func SeverityMedium() SeverityLabel {
	return SeverityLabel{
		Severity: shared.SeverityMedium,
		Label:    "Medium",
	}
}
func SeverityLow() SeverityLabel {
	return SeverityLabel{
		Severity: shared.SeverityLow,
		Label:    "Low",
	}
}
func SeverityUnknown() SeverityLabel {
	return SeverityLabel{
		Severity: shared.SeverityUnknown,
		Label:    "Unknown",
	}
}

func NewSeverityLabel(severity shared.Severity) SeverityLabel {
	m := map[shared.Severity]SeverityLabel{
		shared.SeverityCritical: SeverityCritical(),
		shared.SeverityHigh:     SeverityHigh(),
		shared.SeverityMedium:   SeverityMedium(),
		shared.SeverityLow:      SeverityLow(),
		shared.SeverityUnknown:  SeverityUnknown(),
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
