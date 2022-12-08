package operator_test

import (
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"path"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"time"
)

var _ = Describe("Workload controller", func() {

	const (
		WorkloadNamespace = "default"

		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	NormalizeUntestableScanJobFields := func(job *batchv1.Job) *batchv1.Job {
		job.APIVersion = "batch/v1"
		job.Kind = string(kube.KindJob)
		job.UID = ""
		job.ResourceVersion = ""
		job.CreationTimestamp = metav1.Time{}
		job.ManagedFields = nil
		job.Spec.Selector.MatchLabels["controller-uid"] = "<CONTROLLER-UID>"
		job.Spec.Template.Labels["controller-uid"] = "<CONTROLLER-UID>"
		for i := range job.Spec.Template.Spec.InitContainers {
			job.Spec.Template.Spec.InitContainers[i].Name = "<INIT-CONTAINER-NAME>"
		}
		return job
	}

	NormalizeUntestableConfigAuditReportFields := func(ca *v1alpha1.ConfigAuditReport) *v1alpha1.ConfigAuditReport {
		ca.APIVersion = "aquasecurity.github.io/v1alpha1"
		ca.Kind = "ConfigAuditReport"
		ca.UID = ""
		ca.ResourceVersion = ""
		ca.CreationTimestamp = metav1.Time{}
		ca.ManagedFields = nil
		ca.OwnerReferences[0].UID = ""
		ca.Report.UpdateTimestamp = metav1.Time{}
		sort.Sort(ByCheckID(ca.Report.Checks))
		return ca
	}
	NormalizeUntestableRbacAssessmentReportFields := func(ca *v1alpha1.RbacAssessmentReport) *v1alpha1.RbacAssessmentReport {
		ca.APIVersion = "aquasecurity.github.io/v1alpha1"
		ca.Kind = "RbacAssessmentReport"
		ca.UID = ""
		ca.SetLabels(map[string]string{
			"trivy-operator.resource.kind": "Role",
			"trivy-operator.resource.name": "proxy",
		})
		ca.ResourceVersion = ""
		ca.CreationTimestamp = metav1.Time{}
		ca.ManagedFields = nil
		ca.OwnerReferences[0].UID = ""
		sort.Sort(ByCheckID(ca.Report.Checks))
		return ca
	}
	var testdataResourceDir = path.Join("testdata", "fixture")

	DescribeTable("On deploying workloads",
		func(workload client.Object, workloadResourceFile string) {
			Expect(loadResource(workload, path.Join(testdataResourceDir, workloadResourceFile))).Should(Succeed())
			workload.SetNamespace(WorkloadNamespace)
			Expect(k8sClient.Create(ctx, workload)).Should(Succeed())
		},
		Entry("Should create a CronJob resource", &batchv1.CronJob{}, "cronjob.yaml"),
		Entry("Should create a DaemonSet resource", &appsv1.DaemonSet{}, "daemonset.yaml"),
		Entry("Should create a Job resource", &batchv1.Job{}, "job.yaml"),
		Entry("Should create a Pod resource", &corev1.Pod{}, "pod.yaml"),
		Entry("Should create a ReplicaSet resource", &appsv1.ReplicaSet{}, "replicaset.yaml"),
		Entry("Should create a ReplicationController resource", &corev1.ReplicationController{}, "replicationcontroller.yaml"),
		Entry("Should create a StatefulSet resource", &appsv1.StatefulSet{}, "statefulset.yaml"),
		Entry("Should create a Role resource", &rbacv1.Role{}, "role.yaml"),
	)

	DescribeTable("On Vulnerability reconcile loop",
		func(expectedScanJobResourceFile string) {
			expectedJob := &batchv1.Job{}
			Expect(loadResource(expectedJob, path.Join(testdataResourceDir, expectedScanJobResourceFile))).Should(Succeed())
			expectedJob.Namespace = WorkloadNamespace

			jobLookupKey := client.ObjectKeyFromObject(expectedJob)
			createdJob := &batchv1.Job{}

			// We'll need to retry getting this newly created Job, given that creation may not immediately happen.
			Eventually(func() error {
				return k8sClient.Get(ctx, jobLookupKey, createdJob)
			}, timeout, interval).Should(Succeed())

			Expect(createdJob).Should(WithTransform(NormalizeUntestableScanJobFields, Equal(expectedJob)))
		},
		Entry("Should create a scan Job for CronJob", "cronjob-expected-scan.yaml"),
		Entry("Should create a scan Job for DaemonSet", "daemonset-expected-scan.yaml"),
		Entry("Should create a scan Job for Job", "job-expected-scan.yaml"),
		Entry("Should create a scan Job for Pod", "pod-expected-scan.yaml"),
		Entry("Should create a scan Job for ReplicaSet", "replicaset-expected-scan.yaml"),
		Entry("Should create a scan Job for ReplicationController", "replicationcontroller-expected-scan.yaml"),
		Entry("Should create a scan Job for StatefulSet", "statefulset-expected-scan.yaml"),
	)

	DescribeTable("On ConfigAudit reconcile loop",
		func(expectedConfigAuditReportResourceFile string) {
			expectedConfigAuditReport := &v1alpha1.ConfigAuditReport{}
			Expect(loadResource(expectedConfigAuditReport, path.Join(testdataResourceDir, expectedConfigAuditReportResourceFile))).Should(Succeed())
			expectedConfigAuditReport.Namespace = WorkloadNamespace

			caLookupKey := client.ObjectKeyFromObject(expectedConfigAuditReport)
			createdConfigAuditReport := &v1alpha1.ConfigAuditReport{}

			// We'll need to retry getting this newly created Job, given that creation may not immediately happen.
			Eventually(func() error {
				return k8sClient.Get(ctx, caLookupKey, createdConfigAuditReport)
			}, timeout, interval).Should(Succeed())
			sort.Sort(ByCheckID(expectedConfigAuditReport.Report.Checks))
			Expect(createdConfigAuditReport).Should(WithTransform(NormalizeUntestableConfigAuditReportFields, Equal(expectedConfigAuditReport)))
		},
		Entry("Should create a config audit report CronJob", "cronjob-configauditreport-expected.yaml"),
		Entry("Should create a config audit report DaemonSet", "daemonset-configauditreport-expected.yaml"),
		Entry("Should create a config audit report Job", "job-configauditreport-expected.yaml"),
		Entry("Should create a config audit report Pod", "pod-configauditreport-expected.yaml"),
		Entry("Should create a config audit report ReplicaSet", "replicaset-configauditreport-expected.yaml"),
	)

	DescribeTable("On Rbac reconcile loop",
		func(expectedRbacAssessmentReportResourceFile string) {
			expectedRbacAssessmentReport := &v1alpha1.RbacAssessmentReport{}
			Expect(loadResource(expectedRbacAssessmentReport, path.Join(testdataResourceDir, expectedRbacAssessmentReportResourceFile))).Should(Succeed())
			expectedRbacAssessmentReport.Namespace = WorkloadNamespace

			caLookupKey := client.ObjectKeyFromObject(expectedRbacAssessmentReport)
			createdRbacAssessmentReport := &v1alpha1.RbacAssessmentReport{}

			// We'll need to retry getting this newly created Job, given that creation may not immediately happen.
			Eventually(func() error {
				return k8sClient.Get(ctx, caLookupKey, createdRbacAssessmentReport)
			}, timeout, interval).Should(Succeed())
			sort.Sort(ByCheckID(expectedRbacAssessmentReport.Report.Checks))
			Expect(createdRbacAssessmentReport).Should(WithTransform(NormalizeUntestableRbacAssessmentReportFields, Equal(expectedRbacAssessmentReport)))
		},
		Entry("Should create a rbac assessment report ", "role-rbacassessment-expected.yaml"),
	)
})

type ByCheckID []v1alpha1.Check

func (a ByCheckID) Len() int           { return len(a) }
func (a ByCheckID) Less(i, j int) bool { return a[i].ID < a[j].ID }
func (a ByCheckID) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
