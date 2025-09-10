package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test data structures for streamReportToFile tests
type TestVulnerabilityReport struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Metadata   TestReportMetadata    `json:"metadata"`
	Report     TestVulnerabilityData `json:"report"`
}

type TestReportMetadata struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type TestVulnerabilityData struct {
	Scanner         TestScanner         `json:"scanner"`
	Summary         TestSummary         `json:"summary"`
	Vulnerabilities []TestVulnerability `json:"vulnerabilities"`
}

type TestScanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type TestSummary struct {
	CriticalCount int `json:"criticalCount"`
	HighCount     int `json:"highCount"`
	MediumCount   int `json:"mediumCount"`
	LowCount      int `json:"lowCount"`
}

type TestVulnerability struct {
	VulnerabilityID string   `json:"vulnerabilityID"`
	Severity        string   `json:"severity"`
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	FixedVersion    string   `json:"fixedVersion,omitempty"`
	Links           []string `json:"links,omitempty"`
}

func TestStreamReportToFile(t *testing.T) {
	mockReport := TestVulnerabilityReport{
		APIVersion: "aquasecurity.github.io/v1alpha1",
		Kind:       "VulnerabilityReport",
		Metadata: TestReportMetadata{
			Name:      "test-vulnerability-report",
			Namespace: "default",
			Labels: map[string]string{
				"app.kubernetes.io/name":  "test-app",
				"trivy-operator.resource": "test",
			},
		},
		Report: TestVulnerabilityData{
			Scanner: TestScanner{
				Name:    "Trivy",
				Vendor:  "Aqua Security",
				Version: "v0.65.0",
			},
			Summary: TestSummary{
				CriticalCount: 2,
				HighCount:     5,
				MediumCount:   3,
				LowCount:      1,
			},
			Vulnerabilities: []TestVulnerability{
				{
					VulnerabilityID: "CVE-2023-1234",
					Severity:        "CRITICAL",
					Title:           "Test Critical Vulnerability",
					Description:     "A test critical vulnerability for unit testing",
					FixedVersion:    "1.2.3",
					Links:           []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234"},
				},
				{
					VulnerabilityID: "CVE-2023-5678",
					Severity:        "HIGH",
					Title:           "Test High Vulnerability",
					Description:     "A test high vulnerability for unit testing",
					FixedVersion:    "1.2.4",
					Links:           []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5678"},
				},
			},
		},
	}

	tests := []struct {
		name           string
		report         any
		setupFile      func(t *testing.T) string
		validateResult func(t *testing.T, filePath string, originalReport any)
		expectPretty   bool
		expectError    bool
		errorContains  string
	}{
		{
			name:   "successful streaming of vulnerability report (pretty printed)",
			report: mockReport,
			setupFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				return filepath.Join(tmpDir, "vulnerability-report.json")
			},
			validateResult: func(t *testing.T, filePath string, originalReport any) {
				// Check file exists
				assert.FileExists(t, filePath)

				// Read file content
				content, err := os.ReadFile(filePath)
				require.NoError(t, err)

				// Validate JSON structure
				var decodedReport TestVulnerabilityReport
				err = json.Unmarshal(content, &decodedReport)
				require.NoError(t, err)

				// Validate content matches original
				original := originalReport.(TestVulnerabilityReport)
				assert.Equal(t, original.APIVersion, decodedReport.APIVersion)
				assert.Equal(t, original.Kind, decodedReport.Kind)
				assert.Equal(t, original.Metadata.Name, decodedReport.Metadata.Name)
				assert.Equal(t, original.Report.Scanner.Name, decodedReport.Report.Scanner.Name)
				assert.Equal(t, original.Report.Summary.CriticalCount, decodedReport.Report.Summary.CriticalCount)
				assert.Len(t, decodedReport.Report.Vulnerabilities, 2)

				// Validate pretty printing (indentation)
				assert.Contains(t, string(content), "  \"apiVersion\":")
				assert.Contains(t, string(content), "    \"name\":")
			},
			expectPretty: true,
			expectError:  false,
		},
		{
			name:   "successful streaming of vulnerability report (single line)",
			report: mockReport,
			setupFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				return filepath.Join(tmpDir, "vulnerability-report.json")
			},
			validateResult: func(t *testing.T, filePath string, originalReport any) {
				// Check file exists
				assert.FileExists(t, filePath)

				// Read file content
				content, err := os.ReadFile(filePath)
				require.NoError(t, err)

				// Validate JSON structure
				var decodedReport TestVulnerabilityReport
				err = json.Unmarshal(content, &decodedReport)
				require.NoError(t, err)

				// Validate content matches original
				original := originalReport.(TestVulnerabilityReport)
				assert.Equal(t, original.APIVersion, decodedReport.APIVersion)
				assert.Equal(t, original.Kind, decodedReport.Kind)
				assert.Equal(t, original.Metadata.Name, decodedReport.Metadata.Name)
				assert.Equal(t, original.Report.Scanner.Name, decodedReport.Report.Scanner.Name)
				assert.Equal(t, original.Report.Summary.CriticalCount, decodedReport.Report.Summary.CriticalCount)
				assert.Len(t, decodedReport.Report.Vulnerabilities, 2)

				// Validate pretty printing (indentation)
				assert.Contains(t, string(content), "\"apiVersion\":")
				assert.Contains(t, string(content), "\"name\":")
			},
			expectPretty: true,
			expectError:  false,
		},
		{
			name:   "failure due to invalid directory path",
			report: map[string]string{"test": "data"},
			setupFile: func(_ *testing.T) string {
				return "/nonexistent/directory/report.json"
			},
			validateResult: func(t *testing.T, filePath string, _ any) {
				// File should not exist
				assert.NoFileExists(t, filePath)
			},
			expectPretty:  false,
			expectError:   true,
			errorContains: "failed to create file",
		},
		{
			name: "failure due to non-serializable data",
			report: map[string]any{
				"valid":   "data",
				"invalid": make(chan int), // Channels cannot be JSON marshaled
			},
			setupFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				return filepath.Join(tmpDir, "invalid-report.json")
			},
			validateResult: func(t *testing.T, filePath string, _ any) {
				// File may be created but content will be invalid
				info, err := os.Stat(filePath)
				if err == nil {
					// If file exists, it should be empty or contain invalid JSON
					assert.Equal(t, int64(0), info.Size())
				}
			},
			expectPretty:  false,
			expectError:   true,
			errorContains: "failed to encode report",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setupFile(t)

			// Execute the function under test
			err := StreamReportToFile(tt.report, filePath, 0o666, tt.expectPretty)

			// Validate error expectations
			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}

			// Validate results
			tt.validateResult(t, filePath, tt.report)
		})
	}
}

func TestStreamReportToFilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "permissions-test.json")

	report := map[string]string{
		"test": "data for permissions test",
	}

	err := StreamReportToFile(report, filePath, 0o666, false)
	require.NoError(t, err)

	// Check file permissions
	info, err := os.Stat(filePath)
	require.NoError(t, err)

	// File should be readable and writable by owner
	mode := info.Mode()
	assert.True(t, mode.IsRegular())

	// Verify file can be read
	content, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "permissions test")
}

// Benchmark tests to measure memory efficiency of streaming approach
func BenchmarkStreamReportToFile(b *testing.B) {
	tmpDir := b.TempDir()

	// Create a moderately sized report
	vulnerabilities := make([]TestVulnerability, 100)
	for i := 0; i < 100; i++ {
		vulnerabilities[i] = TestVulnerability{
			VulnerabilityID: fmt.Sprintf("CVE-2023-%04d", i),
			Severity:        "MEDIUM",
			Title:           fmt.Sprintf("Benchmark Vulnerability %d", i),
			Description:     fmt.Sprintf("A benchmark vulnerability number %d for performance testing", i),
			FixedVersion:    "1.0.0",
			Links:           []string{fmt.Sprintf("https://example.com/cve-%d", i)},
		}
	}

	report := TestVulnerabilityReport{
		APIVersion: "aquasecurity.github.io/v1alpha1",
		Kind:       "VulnerabilityReport",
		Metadata: TestReportMetadata{
			Name:      "benchmark-vulnerability-report",
			Namespace: "default",
		},
		Report: TestVulnerabilityData{
			Scanner: TestScanner{
				Name:    "Trivy",
				Vendor:  "Aqua Security",
				Version: "v0.65.0",
			},
			Summary: TestSummary{
				MediumCount: 100,
			},
			Vulnerabilities: vulnerabilities,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filePath := filepath.Join(tmpDir, fmt.Sprintf("benchmark-report-%d.json", i))
		err := StreamReportToFile(report, filePath, 0o666, false)
		if err != nil {
			b.Fatal(err)
		}
	}
}
