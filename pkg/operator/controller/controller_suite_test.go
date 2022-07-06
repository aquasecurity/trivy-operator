package controller

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestPredicate(t *testing.T) {
	RegisterFailHandler(Fail)
	suiteName := "Controller Suite"
	RunSpecs(t, suiteName)
}
