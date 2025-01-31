package metrics

import (
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	CRITICAL_LABEL = "Critical"
	HIGH_LABEL     = "High"
	MEDIUM_LABEL   = "Medium"
	LOW_LABEL      = "Low"
	UNKNOWN_LABEL  = "Unknown"
)

var _ = Describe("SeverityLabel", func() {

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(v1alpha1.AddToScheme(scheme)).To(Succeed())
	})

	Context("SeverityLabel", func() {

		It("Critical", func() {
			Expect(SeverityCritical()).
				To(Equal(SeverityLabel{Label: CRITICAL_LABEL, Severity: v1alpha1.SeverityCritical}))
		})
		It("CRITICAL", func() {
			Expect(NewSeverityLabel("CRITICAL")).
				To(Equal(SeverityLabel{Label: CRITICAL_LABEL, Severity: v1alpha1.SeverityCritical}))
		})
		It("High", func() {
			Expect(SeverityHigh()).
				To(Equal(SeverityLabel{Label: HIGH_LABEL, Severity: v1alpha1.SeverityHigh}))
		})
		It("HIGH", func() {
			Expect(NewSeverityLabel("HIGH")).
				To(Equal(SeverityLabel{Label: HIGH_LABEL, Severity: v1alpha1.SeverityHigh}))
		})
		It("Medium", func() {
			Expect(SeverityMedium()).
				To(Equal(SeverityLabel{Label: MEDIUM_LABEL, Severity: v1alpha1.SeverityMedium}))
		})
		It("MEDIUM", func() {
			Expect(NewSeverityLabel("MEDIUM")).
				To(Equal(SeverityLabel{Label: MEDIUM_LABEL, Severity: v1alpha1.SeverityMedium}))
		})
		It("Low", func() {
			Expect(SeverityLow()).
				To(Equal(SeverityLabel{Label: LOW_LABEL, Severity: v1alpha1.SeverityLow}))
		})
		It("LOW", func() {
			Expect(NewSeverityLabel("LOW")).
				To(Equal(SeverityLabel{Label: LOW_LABEL, Severity: v1alpha1.SeverityLow}))
		})
		It("Unknown", func() {
			Expect(SeverityUnknown()).
				To(Equal(SeverityLabel{Label: UNKNOWN_LABEL, Severity: v1alpha1.SeverityUnknown}))
		})
		It("UNKNOWN", func() {
			Expect(NewSeverityLabel("UNKNOWN")).
				To(Equal(SeverityLabel{Label: UNKNOWN_LABEL, Severity: v1alpha1.SeverityUnknown}))
		})

	})

})
