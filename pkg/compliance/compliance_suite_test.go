package compliance

import (
	"testing"

	"github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestPredicate(t *testing.T) {
	RegisterFailHandler(ginkgo.Fail)
	suiteName := "Controller Suite"
	ginkgo.RunSpecs(t, suiteName)
}
