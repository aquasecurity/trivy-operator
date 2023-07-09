package trivy

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

func cycloneDxBomToReport(cbom cdx.BOM) *v1alpha1.BOM {
	components := make([]*v1alpha1.Component, 0)
	for _, c := range *cbom.Components {
		components = append(components, cycloneDxComponentToReportComponent(c))
	}
	return &v1alpha1.BOM{
		BOMFormat:    cbom.BOMFormat,
		SpecVersion:  int(cbom.SpecVersion),
		SerialNumber: cbom.SerialNumber,
		Version:      cbom.Version,
		Metadata:     cycloneDxMetadataToReportMetadata(cbom.Metadata),
		Components:   components,
		Dependencies: cycloneDxDependenciesToReportDependencies(cbom.Dependencies),
	}
}

func cycloneDxMetadataToReportMetadata(cmetadata *cdx.Metadata) *v1alpha1.Metadata {
	t := make([]v1alpha1.Tool, 0)
	for _, ct := range *cmetadata.Tools {
		t = append(t, v1alpha1.Tool{
			Vendor:  ct.Vendor,
			Name:    ct.Name,
			Version: ct.Version,
		})
	}
	return &v1alpha1.Metadata{
		Timestamp: cmetadata.Timestamp,
		Tools:     &t,
		Component: cycloneDxComponentToReportComponent(*cmetadata.Component),
	}
}

func cycloneDxComponentToReportComponent(cComp cdx.Component) *v1alpha1.Component {
	var oe v1alpha1.OrganizationalEntity
	if cComp.Supplier != nil {
		oe = v1alpha1.OrganizationalEntity{
			Name: cComp.Supplier.Name,
			URL:  cComp.Supplier.URL,
		}
	}
	return &v1alpha1.Component{
		BOMRef:     cComp.BOMRef,
		Type:       string(cComp.Type),
		Name:       cComp.Name,
		Group:      cComp.Group,
		Version:    cComp.Version,
		PackageURL: cComp.PackageURL,
		Hashes:     cycloneDxHashesToReportHashes(cComp.Hashes),
		Licenses:   cycloneDxLicensesToReportLicenses(cComp.Licenses),
		Properties: cycloneDxPropertiesToReportProperties(cComp.Properties),
		Supplier:   oe,
	}
}

func cycloneDxHashesToReportHashes(hashes *[]cdx.Hash) []v1alpha1.Hash {
	reportHashes := make([]v1alpha1.Hash, 0)
	if hashes != nil {
		for _, h := range *hashes {
			reportHashes = append(reportHashes, v1alpha1.Hash{
				Algorithm: string(h.Algorithm),
				Value:     h.Value,
			})
		}
	}
	return reportHashes
}

func cycloneDxLicensesToReportLicenses(licenses *cdx.Licenses) []v1alpha1.LicenseChoice {
	reportLicenses := make([]v1alpha1.LicenseChoice, 0)
	if licenses != nil {
		for _, l := range *licenses {
			var li v1alpha1.License
			if l.License != nil {
				li = v1alpha1.License{
					ID:   l.License.ID,
					Name: l.License.Name,
					URL:  l.License.URL,
				}
			}
			exp := l.Expression
			reportLicenses = append(reportLicenses, v1alpha1.LicenseChoice{
				License:    li,
				Expression: exp,
			})
		}
	}
	return reportLicenses
}

func cycloneDxPropertiesToReportProperties(properties *[]cdx.Property) []v1alpha1.Property {
	reportProperties := make([]v1alpha1.Property, 0)
	if properties != nil {
		for _, p := range *properties {
			reportProperties = append(reportProperties, v1alpha1.Property{
				Name:  p.Name,
				Value: p.Value,
			})
		}
	}
	return reportProperties
}

func cycloneDxDependenciesToReportDependencies(dependencies *[]cdx.Dependency) *[]v1alpha1.Dependency {
	reportDependencies := make([]v1alpha1.Dependency, 0)
	for _, d := range *dependencies {
		reportDependencies = append(reportDependencies, v1alpha1.Dependency{
			Ref:          d.Ref,
			Dependencies: d.Dependencies,
		})
	}
	return &reportDependencies
}
