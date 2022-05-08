package polaris

type Report struct {
	PolarisOutputVersion string       `json:"PolarisOutputVersion"`
	SourceType           string       `json:"SourceType"`
	SourceName           string       `json:"SourceName"`
	DisplayName          string       `json:"DisplayName"`
	ClusterInfo          *ClusterInfo `json:"ClusterInfo"`
	Results              []Result     `json:"Results"`
}

type ClusterInfo struct {
	Version     string `json:"Version"`
	Nodes       int    `json:"Nodes"`
	Pods        int    `json:"Pods"`
	Namespaces  int    `json:"Namespaces"`
	Controllers int    `json:"Controllers"`
}

type Result struct {
	Name      string    `json:"Name"`
	Namespace string    `json:"Namespace"`
	Kind      string    `json:"Kind"`
	PodResult PodResult `json:"PodResult"`
}

type PodResult struct {
	Name             string            `json:"Name"`
	Results          map[string]Check  `json:"Results"`
	ContainerResults []ContainerResult `json:"ContainerResults"`
}

type ContainerResult struct {
	Name    string           `json:"Name"`
	Results map[string]Check `json:"Results"`
}

type Check struct {
	ID       string `json:"ID"`
	Message  string `json:"Message"`
	Success  bool   `json:"Success"`
	Severity string `json:"Severity"`
	Category string `json:"Category"`
}
