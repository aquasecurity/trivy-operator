package jobs

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestPredicate(t *testing.T) {
	RegisterFailHandler(Fail)
	suiteName := "Jobs Suite"
	RunSpecs(t, suiteName)
}
