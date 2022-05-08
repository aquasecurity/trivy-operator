package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/google/go-containerregistry/pkg/name"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Scanner struct {
	scanOptions Options
}

func NewScanner(options Options) *Scanner {
	return &Scanner{
		options,
	}
}

func (s *Scanner) Scan(imageRef string) (report v1alpha1.VulnerabilityReportData, err error) {
	var command *exec.Cmd
	if Command(s.scanOptions.Command) == Filesystem {
		command = s.getFSScanCommand(imageRef)
	} else {
		command = s.getImageScanCommand(imageRef)
	}

	var stderr bytes.Buffer
	command.Stderr = &stderr
	out, err := command.Output()
	if err != nil {
		_, _ = fmt.Fprint(os.Stderr, stderr.String())
		err = fmt.Errorf("running scannercli: %w", err)
		return
	}
	var aquaReport ScanReport
	err = json.Unmarshal(out, &aquaReport)
	if err != nil {
		return
	}
	return s.convert(imageRef, aquaReport)
}

func (s *Scanner) getImageScanCommand(imageRef string) *exec.Cmd {
	args := []string{
		"scan",
		"--checkonly",
		"--dockerless",
		fmt.Sprintf("--host=%s", s.scanOptions.BaseURL),
		fmt.Sprintf("--user=%s", s.scanOptions.Credentials.Username),
		fmt.Sprintf("--password=%s", s.scanOptions.Credentials.Password),
		"--local",
		imageRef,
	}
	command := exec.Command("scannercli", args...)
	return command
}

func (s *Scanner) getFSScanCommand(imageRef string) *exec.Cmd {
	args := []string{
		"scan",
		"--checkonly",
		fmt.Sprintf("--host=%s", s.scanOptions.BaseURL),
		fmt.Sprintf("--user=%s", s.scanOptions.Credentials.Username),
		fmt.Sprintf("--password=%s", s.scanOptions.Credentials.Password),
		fmt.Sprintf("--registry=%s", s.scanOptions.RegistryName),
		fmt.Sprintf("--image-name=%s", imageRef),
		"--register",
		"--fs-scan",
		"/",
	}
	command := exec.Command("/var/aqua/scannercli", args...)
	return command
}

func (s *Scanner) convert(imageRef string, aquaReport ScanReport) (report v1alpha1.VulnerabilityReportData, err error) {
	items := make([]v1alpha1.Vulnerability, 0)

	for _, resourceScan := range aquaReport.Resources {
		for _, vln := range resourceScan.Vulnerabilities {
			var pkg string
			switch resourceScan.Resource.Type {
			case Library:
				pkg = resourceScan.Resource.Path
			case Package:
				pkg = resourceScan.Resource.Name
			default:
				pkg = resourceScan.Resource.Name
			}
			items = append(items, v1alpha1.Vulnerability{
				VulnerabilityID:  vln.Name,
				Resource:         pkg,
				InstalledVersion: resourceScan.Resource.Version,
				FixedVersion:     vln.FixVersion,
				Severity:         s.toSeverity(vln),
				Description:      vln.Description,
				Links:            s.toLinks(vln),
			})
		}
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return
	}

	artifact := v1alpha1.Artifact{
		Repository: ref.Context().RepositoryStr(),
	}
	switch t := ref.(type) {
	case name.Tag:
		artifact.Tag = t.TagStr()
	case name.Digest:
		artifact.Digest = t.DigestStr()
	}

	report = v1alpha1.VulnerabilityReportData{
		UpdateTimestamp: metav1.NewTime(time.Now()),
		Scanner: v1alpha1.Scanner{
			Name:    "Aqua CSP",
			Vendor:  "Aqua Security",
			Version: s.scanOptions.Version,
		},
		Registry: v1alpha1.Registry{
			Server: ref.Context().RegistryStr(),
		},
		Artifact:        artifact,
		Summary:         s.toSummary(aquaReport.Summary),
		Vulnerabilities: items,
	}
	return
}

func (s *Scanner) toSeverity(v Vulnerability) v1alpha1.Severity {
	switch severity := v.AquaSeverity; severity {
	case "critical":
		return v1alpha1.SeverityCritical
	case "high":
		return v1alpha1.SeverityHigh
	case "medium":
		return v1alpha1.SeverityMedium
	case "low":
		return v1alpha1.SeverityLow
	case "negligible":
		// TODO We should have severity None defined in k8s-security-crds
		return v1alpha1.SeverityUnknown
	default:
		return v1alpha1.SeverityUnknown
	}
}

func (s *Scanner) toLinks(v Vulnerability) []string {
	var links []string
	if v.NVDURL != "" {
		links = append(links, v.NVDURL)
	}
	if v.VendorURL != "" {
		links = append(links, v.VendorURL)
	}
	return links
}

func (s *Scanner) toSummary(aquaSummary VulnerabilitySummary) v1alpha1.VulnerabilitySummary {
	return v1alpha1.VulnerabilitySummary{
		CriticalCount: aquaSummary.Critical,
		HighCount:     aquaSummary.High,
		MediumCount:   aquaSummary.Medium,
		LowCount:      aquaSummary.Low,
	}
}
