package conftest

import (
	. "github.com/aquasecurity/trivy-operator/itest/trivy-operator/behavior"
	. "github.com/onsi/ginkgo"
)

var _ = Describe("Conftest", ConfigurationCheckerBehavior(&inputs))
