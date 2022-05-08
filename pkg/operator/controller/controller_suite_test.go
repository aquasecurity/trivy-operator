package controller

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestPredicate(t *testing.T) {
	RegisterFailHandler(Fail)
	suiteName := "Controller Suite"
	RunSpecs(t, suiteName)
}
