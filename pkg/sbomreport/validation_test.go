package sbomreport

import (
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// TestCycloneDXBOMConversionAndValidity covers multiple license representations
// using a table-driven style. It ensures conversion to our internal BOM and
// round-trip back to CycloneDX preserves structural validity.
func TestCycloneDXBOMConversionAndValidity(t *testing.T) {
	cases := []struct {
		name                  string
		licenses              *cdx.Licenses
		wantLicensePresent    bool
		wantLicenseID         string
		wantExpressionPresent bool
		wantExpression        string
	}{
		{
			name: "license with ID",
			licenses: &cdx.Licenses{{
				License: &cdx.License{ID: "GPL-3.0-or-later"},
			}},
			wantLicensePresent:    true,
			wantLicenseID:         "GPL-3.0-or-later",
			wantExpressionPresent: false,
		},
		{
			name: "license expression with empty license object",
			licenses: &cdx.Licenses{{
				License:    &cdx.License{},
				Expression: "Apache-2.0 AND BSD-3-Clause",
			}},
			wantLicensePresent:    true,
			wantLicenseID:         "",
			wantExpressionPresent: true,
			wantExpression:        "Apache-2.0 AND BSD-3-Clause",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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
				Licenses: tc.licenses,
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
			require.Positive(t, len(rbom.Components), "components should not be empty")
			require.NotNil(t, rbom.Dependencies)

			// Validate summary computation aligns with BOM content
			summary := BomSummary(*rbom)
			// BomSummary adds 1 for the root component in ComponentsCount
			require.Equal(t, 2, summary.ComponentsCount)
			require.Equal(t, 1, summary.DependenciesCount)

			// Verify license mapping specifics on first component
			gotComp := rbom.Components[0]
			if tc.wantLicensePresent {
				require.True(t, len(gotComp.Licenses) > 0)
				if tc.wantLicenseID != "" {
					require.NotNil(t, gotComp.Licenses[0].License)
					require.Equal(t, tc.wantLicenseID, gotComp.Licenses[0].License.ID)
				} else {
					// Expect a present but empty license object
					require.NotNil(t, gotComp.Licenses[0].License)
					require.Empty(t, gotComp.Licenses[0].License.ID)
					require.Empty(t, gotComp.Licenses[0].License.Name)
					require.Empty(t, gotComp.Licenses[0].License.URL)
				}
			}
			if tc.wantExpressionPresent {
				require.Equal(t, tc.wantExpression, gotComp.Licenses[0].Expression)
			}

			// Round-trip: our BOM -> JSON -> CycloneDX BOM
			data, err := json.Marshal(rbom)
			require.NoError(t, err)

			var parsed cdx.BOM
			err = json.Unmarshal(data, &parsed)
			require.NoError(t, err, "internal BOM should be compatible with CycloneDX schema fields")

			// Check key CycloneDX invariants after round-trip
			require.Equal(t, "CycloneDX", parsed.BOMFormat)
			require.Equal(t, cdx.SpecVersion1_4, parsed.SpecVersion)
			require.NotEmpty(t, parsed.Components)
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
		})
	}
}
