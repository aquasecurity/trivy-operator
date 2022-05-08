package conftest

// CheckResult describes the result of a conftest policy evaluation.
// Errors produced by rego should be considered separate
// from other classes of exceptions.
type CheckResult struct {
	FileName   string        `json:"filename"`
	Namespace  string        `json:"namespace"`
	Successes  int           `json:"successes"`
	Warnings   []Result      `json:"warnings,omitempty"`
	Failures   []Result      `json:"failures,omitempty"`
	Exceptions []Result      `json:"exceptions,omitempty"`
	Queries    []QueryResult `json:"queries,omitempty"`
}

// Result describes the result of a single rule evaluation.
type Result struct {
	Message  string                 `json:"msg"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// QueryResult describes the result of evaluting a query.
type QueryResult struct {

	// Query is the fully qualified query that was used
	// to determine the result. Ex: (data.main.deny)
	Query string `json:"query"`

	// Results are the individual results of the query.
	// When querying data.main.deny, multiple deny rules can
	// exist, producing multiple results.
	Results []Result `json:"results"`

	// Traces represents a single trace of how the query was
	// evaluated. Each trace value is a trace line.
	Traces []string `json:"traces"`
}
