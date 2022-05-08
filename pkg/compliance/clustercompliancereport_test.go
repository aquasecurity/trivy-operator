package compliance

import (
	"context"
	"io/ioutil"
	"sort"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/google/go-cmp/cmp"
	"github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func loadResource(filePath string, resource interface{}) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(data, &resource)
	if err != nil {
		return nil
	}
	return err
}

var _ = ginkgo.Describe("cluster compliance report", func() {
	logger := log.Log.WithName("operator")
	config := getTrivyOperatorConfig()
	ginkgo.Context("reconcile compliance spec report with cis-bench anc audit-config data and validate compliance reports data and requeue", func() {
		var cisBenchList v1alpha1.CISKubeBenchReportList
		err := loadResource("./testdata/fixture/cisBenchmarkReportList.json", &cisBenchList)
		Expect(err).ToNot(HaveOccurred())

		var confAuditList v1alpha1.ConfigAuditReportList
		err = loadResource("./testdata/fixture/configAuditReportList.json", &confAuditList)
		Expect(err).ToNot(HaveOccurred())

		var clusterComplianceSpec v1alpha1.ClusterComplianceReport
		err = loadResource("./testdata/fixture/clusterComplianceSpec.json", &clusterComplianceSpec)
		Expect(err).ToNot(HaveOccurred())
		// generate client with cis-bench,audit-config and compliance spec
		client := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithLists(
			&cisBenchList,
			&confAuditList,
		).WithObjects(
			&clusterComplianceSpec,
		).Build()

		// create compliance controller
		instance := ClusterComplianceReportReconciler{Logger: logger, Client: client, Mgr: NewMgr(client, logger, config), Clock: ext.NewSystemClock()}

		// trigger compliance report generation
		_, err = instance.generateComplianceReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa"})
		Expect(err).ToNot(HaveOccurred())

		ginkgo.It("check cluster compliance report detail data match expected result", func() {
			// validate cluster compliance detail report data
			var clusterComplianceDetialReport v1alpha1.ClusterComplianceDetailReport
			err = loadResource("./testdata/fixture/clusterComplianceDetailReport.json", &clusterComplianceDetialReport)
			complianceDetailReport, err := getDetailReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa-details"}, client)
			Expect(err).ToNot(HaveOccurred())
			sort.Sort(controlDetailSort(complianceDetailReport.Report.ControlChecks))
			sort.Sort(controlDetailSort(clusterComplianceDetialReport.Report.ControlChecks))
			for i := 0; i < len(complianceDetailReport.Report.ControlChecks); i++ {
				sort.Sort(controlObjectTypeSort(complianceDetailReport.Report.ControlChecks[i].ScannerCheckResult))
				sort.Sort(controlObjectTypeSort(clusterComplianceDetialReport.Report.ControlChecks[i].ScannerCheckResult))
			}
			Expect(cmp.Equal(complianceDetailReport.Report, clusterComplianceDetialReport.Report, ignoreTimeStamp())).To(BeTrue())
		})

		ginkgo.It("check cluster compliance report status match expected result", func() {
			// validate cluster compliance report status
			var clusterComplianceReport v1alpha1.ClusterComplianceReport
			err = loadResource("./testdata/fixture/clusterComplianceReport.json", &clusterComplianceReport)
			complianceReport, err := getReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa"}, client)
			Expect(err).ToNot(HaveOccurred())
			sort.Sort(controlSort(complianceReport.Status.ControlChecks))
			sort.Sort(controlSort(clusterComplianceReport.Status.ControlChecks))
			Expect(cmp.Equal(complianceReport.Status, clusterComplianceReport.Status, ignoreTimeStamp())).To(BeTrue())
		})

		ginkgo.It("check requeue interval bigger then 0", func() {
			// validate resource requeue with interval
			res, err := instance.generateComplianceReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa"})
			Expect(err).ToNot(HaveOccurred())
			Expect(res.RequeueAfter > 0).To(BeTrue())
		})

		ginkgo.It("check compliance compliance report status is updated following to changes occur with cis-bench and config-audit report", func() {
			// update cis-benchmark report and config-audit with failed tests and compare update compliance report
			var updatedCisBench v1alpha1.CISKubeBenchReport
			err = loadResource("./testdata/fixture/cisBenchmarkReportUpdate.json", &updatedCisBench)
			Expect(err).ToNot(HaveOccurred())
			var caUpdated v1alpha1.ConfigAuditReport
			err = loadResource("./testdata/fixture/configAuditReportUpdate.json", &caUpdated)
			Expect(err).ToNot(HaveOccurred())
			err = client.Update(context.Background(), &updatedCisBench)
			Expect(err).ToNot(HaveOccurred())
			err = client.Update(context.Background(), &caUpdated)
			Expect(err).ToNot(HaveOccurred())
			// wait for next cron interval
			time.Sleep(4 * time.Second)
			// generate reconcile report
			_, err = instance.generateComplianceReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa"})
			Expect(err).ToNot(HaveOccurred())

			// get compliance report
			complianceReportUpdate, err := getReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa"}, client)
			Expect(err).ToNot(HaveOccurred())

			var clusterComplianceReportUpdate v1alpha1.ClusterComplianceReport
			err = loadResource("./testdata/fixture/clusterComplianceReportUpdate.json", &clusterComplianceReportUpdate)
			Expect(err).ToNot(HaveOccurred())
			sort.Sort(controlSort(complianceReportUpdate.Status.ControlChecks))
			sort.Sort(controlSort(clusterComplianceReportUpdate.Status.ControlChecks))
			// validate updated cluster compliance report status
			Expect(cmp.Equal(complianceReportUpdate.Status, clusterComplianceReportUpdate.Status, ignoreTimeStamp())).To(BeTrue())
		})
		ginkgo.It("check compliance compliance report detail is updated following to changes occur with cis-bench and config-audit report", func() {
			// update cis-benchmark report and config-audit with failed tests and compare update compliance report
			var clusterComplianceDetialReport v1alpha1.ClusterComplianceDetailReport
			err = loadResource("./testdata/fixture/clusterComplianceDetailReportUpdate.json", &clusterComplianceDetialReport)
			complianceDetailReport, err := getDetailReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa-details"}, client)
			Expect(err).ToNot(HaveOccurred())
			sort.Sort(controlDetailSort(complianceDetailReport.Report.ControlChecks))
			sort.Sort(controlDetailSort(clusterComplianceDetialReport.Report.ControlChecks))
			for i := 0; i < len(complianceDetailReport.Report.ControlChecks); i++ {
				sort.Sort(controlObjectTypeSort(complianceDetailReport.Report.ControlChecks[i].ScannerCheckResult))
				sort.Sort(controlObjectTypeSort(clusterComplianceDetialReport.Report.ControlChecks[i].ScannerCheckResult))
			}
			Expect(cmp.Equal(complianceDetailReport.Report, clusterComplianceDetialReport.Report, ignoreTimeStamp())).To(BeTrue())
		})
	})

	ginkgo.Context("reconcile compliance spec report without cis-bench and audit-config data and validate compliance reports data", func() {
		var clusterComplianceSpec v1alpha1.ClusterComplianceReport
		err := loadResource("./testdata/fixture/clusterComplianceSpec.json", &clusterComplianceSpec)
		// create new client
		clientWithComplianceSpecOnly := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(&clusterComplianceSpec).Build()
		// create compliance controller
		complianceControllerInstance := ClusterComplianceReportReconciler{Logger: logger, Client: clientWithComplianceSpecOnly, Mgr: NewMgr(clientWithComplianceSpecOnly, logger, config), Clock: ext.NewSystemClock()}
		reconcileReport, err := complianceControllerInstance.generateComplianceReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa"})
		Expect(err).ToNot(HaveOccurred())

		ginkgo.It("check compliance reconcile where cis-benchmark and config-audit reports are not present", func() {
			// validate compliance reports has no status / data
			complianceDetailReport, err := getDetailReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa-details"}, clientWithComplianceSpecOnly)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(complianceDetailReport.Report.ControlChecks) == 0).To(BeTrue())

			// validate cluster compliance report
			complianceReport, err := getReport(context.TODO(), types.NamespacedName{Namespace: "", Name: "nsa"}, clientWithComplianceSpecOnly)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(complianceReport.Status.ControlChecks) == 0).To(BeTrue())
			// validate reconcile requeue
			Expect(reconcileReport.RequeueAfter == 0).To(BeTrue())
		})
	})
})

func ignoreTimeStamp() cmp.Options {
	alwaysEqual := cmp.Comparer(func(_, _ interface{}) bool { return true })
	opts := cmp.Options{
		cmp.FilterValues(func(t1, t2 metav1.Time) bool {
			return true
		}, alwaysEqual),
	}
	return opts
}

type controlSort []v1alpha1.ControlCheck

func (a controlSort) Len() int           { return len(a) }
func (a controlSort) Less(i, j int) bool { return a[i].ID < a[j].ID }
func (a controlSort) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type controlDetailSort []v1alpha1.ControlCheckDetails

func (a controlDetailSort) Len() int           { return len(a) }
func (a controlDetailSort) Less(i, j int) bool { return a[i].ID < a[j].ID }
func (a controlDetailSort) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type controlObjectTypeSort []v1alpha1.ScannerCheckResult

func (a controlObjectTypeSort) Len() int           { return len(a) }
func (a controlObjectTypeSort) Less(i, j int) bool { return a[i].ObjectType < a[j].ObjectType }
func (a controlObjectTypeSort) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func getReport(ctx context.Context, namespaceName types.NamespacedName, client client.Client) (*v1alpha1.ClusterComplianceReport, error) {
	var report v1alpha1.ClusterComplianceReport
	err := client.Get(ctx, namespaceName, &report)
	if err != nil {
		return nil, err
	}
	return &report, nil
}

func getDetailReport(ctx context.Context, namespaceName types.NamespacedName, client client.Client) (*v1alpha1.ClusterComplianceDetailReport, error) {
	var report v1alpha1.ClusterComplianceDetailReport
	err := client.Get(ctx, namespaceName, &report)
	if err != nil {
		return nil, err
	}
	return &report, nil
}

func getTrivyOperatorConfig() trivyoperator.ConfigData {
	return trivyoperator.ConfigData{"compliance.failEntriesLimit": "1"}
}
