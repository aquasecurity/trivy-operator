package sbomreport

import (
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// TestCycloneDXBOMConversionAndValidity ensures that a CycloneDX BOM can be
// converted into our report format and remains structurally valid
func TestCycloneDXBOMConversionAndValidity(t *testing.T) {
	// Build a minimal but representative CycloneDX BOM
	component := cdx.Component{
		BOMRef:     "pkg:deb/debian/bash@5.2.0?arch=amd64",
		Type:       cdx.ComponentTypeApplication,
		Name:       "bash",
		Group:      "debian",
		Version:    "5.2.0",
		PackageURL: "pkg:deb/debian/bash@5.2.0?arch=amd64",
		Hashes: &[]cdx.Hash{{
			Algorithm: cdx.HashAlgoSHA256,
			Value:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}},
		Licenses: &cdx.Licenses{{
			License: &cdx.License{ID: "GPL-3.0-or-later"},
		}},
		Properties: &[]cdx.Property{{
			Name:  "org.opencontainers.image.source",
			Value: "https://example.com/repo",
		}},
	}

	compList := &[]cdx.Component{component}
	deps := &[]cdx.Dependency{{
		Ref:          component.BOMRef,
		Dependencies: &[]string{},
	}}

	bom := cdx.BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  cdx.SpecVersion1_4,
		SerialNumber: "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
		Version:      1,
		Metadata: &cdx.Metadata{
			Timestamp: "2024-01-02T03:04:05Z",
			Component: &component,
		},
		Components:   compList,
		Dependencies: deps,
	}

	// Convert to the report BOM and basic sanity checks
	rbom := cycloneDxBomToReport(bom, "0.0.0-test")
	require.NotNil(t, rbom)
	require.Equal(t, "CycloneDX", rbom.BOMFormat)
	require.NotEmpty(t, rbom.SpecVersion)
	require.NotNil(t, rbom.Metadata)
	require.NotNil(t, rbom.Components)
	require.True(t, len(rbom.Components) > 0, "components should not be empty")
	require.NotNil(t, rbom.Dependencies)

	// Validate summary computation aligns with BOM content
	summary := BomSummary(*rbom)
	// BomSummary adds 1 for the root component in ComponentsCount
	require.Equal(t, 2, summary.ComponentsCount)
	require.Equal(t, 1, summary.DependenciesCount)

	// Round-trip: our BOM -> JSON -> CycloneDX BOM
	data, err := json.Marshal(rbom)
	require.NoError(t, err)

	var parsed cdx.BOM
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err, "internal BOM should be compatible with CycloneDX schema fields")

	// Check key CycloneDX invariants after round-trip
	require.Equal(t, "CycloneDX", parsed.BOMFormat)
	require.Equal(t, cdx.SpecVersion1_4, parsed.SpecVersion)
	require.NotNil(t, parsed.Components)
	require.Greater(t, len(*parsed.Components), 0)
	require.NotNil(t, parsed.Dependencies)

	// Build a full SbomReportData and ensure fields wire up
	report := v1alpha1.SbomReportData{
		Scanner: v1alpha1.Scanner{
			Name:    v1alpha1.ScannerNameTrivy,
			Vendor:  "Aqua Security",
			Version: "0.0.0-test",
		},
		Summary: summary,
		Bom:     *rbom,
	}

	// Final sanity: JSON marshal of full report should succeed
	_, err = json.Marshal(report)
	require.NoError(t, err)
}
