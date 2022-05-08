package kubehunter

import (
	"encoding/json"
	"io"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func toSummary(vulnerabilities []v1alpha1.KubeHunterVulnerability) (summary v1alpha1.KubeHunterSummary) {
	for _, v := range vulnerabilities {
		switch v.Severity {
		case v1alpha1.KubeHunterSeverityHigh:
			summary.HighCount++
		case v1alpha1.KubeHunterSeverityMedium:
			summary.MediumCount++
		case v1alpha1.KubeHunterSeverityLow:
			summary.LowCount++
		default:
			summary.UnknownCount++
		}
	}
	return
}

func OutputFrom(config Config, reader io.Reader) (v1alpha1.KubeHunterReportData, error) {
	imageRef, err := config.GetKubeHunterImageRef()
	if err != nil {
		return v1alpha1.KubeHunterReportData{}, err
	}
	version, err := trivyoperator.GetVersionFromImageRef(imageRef)
	if err != nil {
		return v1alpha1.KubeHunterReportData{}, err
	}

	report := v1alpha1.KubeHunterReportData{
		Scanner: v1alpha1.Scanner{
			Name:    "kube-hunter",
			Vendor:  "Aqua Security",
			Version: version,
		},
	}
	report.UpdateTimestamp = metav1.NewTime(time.Now())
	err = json.NewDecoder(reader).Decode(&report)
	if err != nil {
		return v1alpha1.KubeHunterReportData{}, err
	}

	report.Summary = toSummary(report.Vulnerabilities)
	return report, nil
}
