package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SbomSummary is a summary of components and dependencies counts .
type SbomSummary struct {
	// DependenciesCount is the number of dependencies in bom.
	// +kubebuilder:validation:Minimum=0
	DependenciesCount int `json:"dependenciesCount"`

	// ComponentsCount is the number of components in bom.
	// +kubebuilder:validation:Minimum=0
	ComponentsCount int `json:"componentsCount"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName={sbom,sboms}
// +kubebuilder:printcolumn:name="Repository",type=string,JSONPath=`.report.artifact.repository`,description="The name of image repository"
// +kubebuilder:printcolumn:name="Tag",type=string,JSONPath=`.report.artifact.tag`,description="The name of image tag"
// +kubebuilder:printcolumn:name="Scanner",type=string,JSONPath=`.report.scanner.name`,description="The name of the sbom generation scanner"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`,description="The age of the report"
// +kubebuilder:printcolumn:name="Components",type=integer,JSONPath=`.report.summary.componentsCount`,priority=1,description="The number of dependencies in bom"
// +kubebuilder:printcolumn:name="Dependencies",type=integer,JSONPath=`.report.summary.dependenciesCount`,priority=1,description="The the number of components in bom"

// SbomReport summarizes components and dependencies found in container image
type SbomReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Report is the actual sbom report data.
	Report SbomReportData `json:"report"`
}

// SbomReportData is the spec for the generating sbom result.
type SbomReportData struct {
	// UpdateTimestamp is a timestamp representing the server time in UTC when this report was updated.
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Format=date-time
	UpdateTimestamp metav1.Time `json:"updateTimestamp"`

	// Scanner is the scanner that generated this report.
	Scanner Scanner `json:"scanner"`

	// Registry is the registry the Artifact was pulled from.
	// +optional
	Registry Registry `json:"registry"`

	// Artifact represents a standalone, executable package of software that includes everything needed to
	// run an application.
	Artifact Artifact `json:"artifact"`

	// Summary is a summary of sbom report.
	Summary SbomSummary `json:"summary"`

	// Bom isartifact bill of materials.
	Bom BOM `json:"components"`
}

type BOM struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`

	SerialNumber string        `json:"serialNumber,omitempty"`
	Version      int           `json:"version,omitempty"`
	Metadata     *Metadata     `json:"metadata,omitempty"`
	Components   []*Component  `json:"components,omitempty"`
	Dependencies *[]Dependency `json:"dependencies,omitempty"`
}

type Component struct {
	BOMRef     string               `json:"bom-ref,omitempty"`
	Type       string               `json:"type,omitempty"`
	Name       string               `json:"name,omitempty"`
	Group      string               `json:"group,omitempty"`
	Version    string               `json:"version,omitempty"`
	PackageURL string               `json:"purl,omitempty"`
	Supplier   OrganizationalEntity `json:"supplier,omitempty"`
	Hashes     []Hash               `json:"hashes,omitempty"`
	Licenses   []LicenseChoice      `json:"licenses,omitempty"`
	Properties []Property           `json:"properties,omitempty"`
}

type Tool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}
type Metadata struct {
	Timestamp string     `json:"timestamp,omitempty"`
	Tools     *[]Tool    `json:"tools,omitempty"`
	Component *Component `json:"component,omitempty"`
}

type Dependency struct {
	Ref          string    `json:"ref,omitempty"`
	Dependencies *[]string `json:"dependsOn,omitempty"`
}

type LicenseChoice struct {
	License    License `json:"license,omitempty"`
	Expression string  `json:"expression,omitempty"`
}

type License struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

type Hash struct {
	Algorithm string `json:"alg,omitempty"`
	Value     string `json:"content,omitempty"`
}

type OrganizationalEntity struct {
	Name    string                   `json:"name,omitempty"`
	URL     *[]string                `json:"url,omitempty"`
	Contact *[]OrganizationalContact `json:"contact,omitempty"`
}

type OrganizationalContact struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
}

type Property struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

// +kubebuilder:object:root=true

// SbomReportList is a list of SbomReport resources.
type SbomReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// SbomReport is the spec for a sbom record.
	Items []SbomReport `json:"items"`
}
