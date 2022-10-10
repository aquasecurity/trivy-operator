package metrics

import (
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
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
