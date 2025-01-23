package jobs_test

import (
	"context"

	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/jobs"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("LimitChecker", func() {

	config := etc.Config{
		Namespace:                    "trivy-operator",
		ConcurrentScanJobsLimit:      2,
		ConcurrentNodeCollectorLimit: 1,
	}
	defaultTrivyOperatorConfig := trivyoperator.GetDefaultConfig()

	Context("When there are more jobs than limit", func() {

		It("Should return true", func() {

			client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "logs-exporter",
					Namespace: "trivy-operator",
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "scan-vulnerabilityreport-hash1",
					Namespace: "trivy-operator",
					Labels: map[string]string{
						trivyoperator.LabelK8SAppManagedBy:            trivyoperator.AppTrivyOperator,
						trivyoperator.LabelVulnerabilityReportScanner: "Trivy",
					},
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "scan-vulnerabilityreport-hash2",
					Namespace: "trivy-operator",
					Labels: map[string]string{
						trivyoperator.LabelK8SAppManagedBy:            trivyoperator.AppTrivyOperator,
						trivyoperator.LabelVulnerabilityReportScanner: "Trivy",
					},
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "scan-configauditreport-hash2",
					Namespace: "trivy-operator",
					Labels: map[string]string{
						trivyoperator.LabelK8SAppManagedBy:            trivyoperator.AppTrivyOperator,
						trivyoperator.LabelVulnerabilityReportScanner: "Trivy",
					},
				}},
			).Build()

			instance := jobs.NewLimitChecker(config, client, defaultTrivyOperatorConfig)
			limitExceeded, jobsCount, err := instance.Check(context.TODO())
			Expect(err).ToNot(HaveOccurred())
			Expect(limitExceeded).To(BeTrue())
			Expect(jobsCount).To(Equal(3))
		})

	})

	Context("When there are less jobs than limit", func() {

		It("Should return false", func() {
			client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "logs-exporter",
					Namespace: "trivy-operator",
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "scan-vulnerabilityreport-hash1",
					Namespace: "trivy-operator",
					Labels: map[string]string{
						trivyoperator.LabelK8SAppManagedBy:            trivyoperator.AppTrivyOperator,
						trivyoperator.LabelVulnerabilityReportScanner: "Trivy",
					},
				}},
			).Build()

			instance := jobs.NewLimitChecker(config, client, defaultTrivyOperatorConfig)
			limitExceeded, jobsCount, err := instance.Check(context.TODO())
			Expect(err).ToNot(HaveOccurred())
			Expect(limitExceeded).To(BeFalse())
			Expect(jobsCount).To(Equal(1))
		})

	})

	Context("When there are more jobs than limit running in different namespace", func() {

		It("Should return true", func() {
			client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "logs-exporter",
					Namespace: "trivy-operator",
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "scan-vulnerabilityreport-hash1",
					Namespace: "default",
					Labels: map[string]string{
						trivyoperator.LabelK8SAppManagedBy:            trivyoperator.AppTrivyOperator,
						trivyoperator.LabelVulnerabilityReportScanner: "Trivy",
					},
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "scan-vulnerabilityreport-hash2",
					Namespace: "prod",
					Labels: map[string]string{
						trivyoperator.LabelK8SAppManagedBy:            trivyoperator.AppTrivyOperator,
						trivyoperator.LabelVulnerabilityReportScanner: "Trivy",
					},
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "scan-configauditreport-hash3",
					Namespace: "stage",
					Labels: map[string]string{
						trivyoperator.LabelK8SAppManagedBy:            trivyoperator.AppTrivyOperator,
						trivyoperator.LabelVulnerabilityReportScanner: "Trivy",
					},
				}},
			).Build()
			trivyOperatorConfig := defaultTrivyOperatorConfig
			trivyOperatorConfig[trivyoperator.KeyVulnerabilityScansInSameNamespace] = "true"
			instance := jobs.NewLimitChecker(config, client, trivyOperatorConfig)
			limitExceeded, jobsCount, err := instance.Check(context.TODO())
			Expect(err).ToNot(HaveOccurred())
			Expect(limitExceeded).To(BeTrue())
			Expect(jobsCount).To(Equal(3))
		})

	})

	Context("When there are more node collector jobs than limit", func() {

		It("Should return true", func() {

			client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "logs-exporter",
					Namespace: "trivy-operator",
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "node-collector-hash1",
					Namespace: "trivy-operator",
					Labels: map[string]string{
						trivyoperator.LabelK8SAppManagedBy:   trivyoperator.AppTrivyOperator,
						trivyoperator.LabelNodeInfoCollector: "Trivy",
					},
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "node-collector-hash2",
					Namespace: "trivy-operator",
					Labels: map[string]string{
						trivyoperator.LabelK8SAppManagedBy:   trivyoperator.AppTrivyOperator,
						trivyoperator.LabelNodeInfoCollector: "Trivy",
					},
				}},
				&batchv1.Job{ObjectMeta: metav1.ObjectMeta{
					Name:      "node-collector-hash3",
					Namespace: "trivy-operator",
					Labels: map[string]string{
						trivyoperator.LabelK8SAppManagedBy:   trivyoperator.AppTrivyOperator,
						trivyoperator.LabelNodeInfoCollector: "Trivy",
					},
				}},
			).Build()

			instance := jobs.NewLimitChecker(config, client, defaultTrivyOperatorConfig)
			limitExceeded, jobsCount, err := instance.CheckNodes(context.TODO())
			Expect(err).ToNot(HaveOccurred())
			Expect(limitExceeded).To(BeTrue())
			Expect(jobsCount).To(Equal(3))
		})

	})

	Context("When there are less node collector jobs than limit", func() {

		It("Should return false", func() {
			client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects().Build()

			instance := jobs.NewLimitChecker(config, client, defaultTrivyOperatorConfig)
			limitExceeded, jobsCount, err := instance.CheckNodes(context.TODO())
			Expect(err).ToNot(HaveOccurred())
			Expect(limitExceeded).To(BeFalse())
			Expect(jobsCount).To(Equal(0))
		})

	})

})
