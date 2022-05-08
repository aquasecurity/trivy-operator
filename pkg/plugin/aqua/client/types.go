package client

type VulnerabilitiesResponse struct {
	Count   int                             `json:"count"`
	Results []VulnerabilitiesResponseResult `json:"result"`
}

type VulnerabilitiesResponseResult struct {
	Registry            string   `json:"registry"`
	ImageRepositoryName string   `json:"image_repository_name"`
	Resource            Resource `json:"resource"`
	Name                string   `json:"name"` // e.g. CVE-2020-3910
	Description         string   `json:"description"`
	AquaSeverity        string   `json:"aqua_severity"`
	AquaVectors         string   `json:"aqua_vectors"`
	AquaScoringSystem   string   `json:"aqua_scoring_system"`
	FixVersion          string   `json:"fix_version"`
}

type Resource struct {
	Type    string `json:"type"`   // e.g. package
	Format  string `json:"format"` // e.g. deb
	Path    string `json:"path"`
	Name    string `json:"name"`    // e.g. libxml2
	Version string `json:"version"` // e.g. 2.9.4+dfsg1-7+b3
}

type RegistryResponse struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // e.g. HUB, API
	Description string   `json:"description"`
	URL         string   `json:"url"`
	Prefixes    []string `json:"prefixes"`
}
