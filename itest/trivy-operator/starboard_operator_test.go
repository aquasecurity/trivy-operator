package trivy_operator

import (
	. "github.com/aquasecurity/trivy-operator/itest/trivy-operator/behavior"
	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("Trivy Operator", func() {

	// TODO Refactor to run this container in a separate test suite
	Describe("Vulnerability Scanner", VulnerabilityScannerBehavior(&inputs))

	// TODO Refactor to run this container in a separate test suite
	Describe("Configuration Checker", ConfigurationCheckerBehavior(&inputs))

	// TODO Refactor to run this container in a separate test suite
	// Describe("CIS Kubernetes Benchmark", CISKubernetesBenchmarkBehavior(&inputs))

})
