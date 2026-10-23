package v1alpha1_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// TestBOM_UnmarshalJSON_NumericSpecVersion_Issue1398 reproduces
// aquasecurity/trivy-operator#1398: "cannot unmarshal number into Go
// struct field BOM.items.report.components.specVersion of type string".
//
// v1alpha1.BOM.SpecVersion is declared as a plain Go `string`
// (sbom_types.go), so encoding/json's default reflection-based decoder
// rejects any stored SbomReport/ClusterSbomReport object whose
// `.report.components.specVersion` value is a bare JSON number instead
// of a JSON string. Because client-go's List/Watch unmarshals the whole
// response in one shot, a single such object breaks the informer cache
// for the entire resource type and the operator never becomes ready
// ("failed to wait for ... caches to sync"), per the issue reports (and
// confirmed still open as of the most recent comment on the issue).
func TestBOM_UnmarshalJSON_NumericSpecVersion_Issue1398(t *testing.T) {
	// Minimal excerpt of a stored SbomReportData.components (BOM) object
	// with specVersion serialized as a bare JSON number, as observed in
	// the wild (issue #1398).
	raw := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": 1.4,
		"version": 1
	}`)

	var bom v1alpha1.BOM
	err := json.Unmarshal(raw, &bom)
	require.NoError(t, err, "BOM must tolerate a numeric specVersion the way real stored SbomReport objects can contain it (issue #1398)")
	require.Equal(t, "1.4", bom.SpecVersion)
	require.Equal(t, "CycloneDX", bom.BOMFormat)
}

// TestBOM_UnmarshalJSON_StringSpecVersion_StillWorks is the control case:
// the well-formed, spec-compliant representation (specVersion as a JSON
// string) must keep working after any fix for Issue1398.
func TestBOM_UnmarshalJSON_StringSpecVersion_StillWorks(t *testing.T) {
	raw := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"version": 1
	}`)

	var bom v1alpha1.BOM
	err := json.Unmarshal(raw, &bom)
	require.NoError(t, err)
	require.Equal(t, "1.4", bom.SpecVersion)
	require.Equal(t, "CycloneDX", bom.BOMFormat)
}
