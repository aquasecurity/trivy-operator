package behavior

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"context"
	"time"

	"github.com/aquasecurity/trivy-operator/itest/helper"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Inputs represents required inputs to shared behavior containers.
type Inputs struct {
	AssertTimeout         time.Duration
	PrimaryNamespace      string
	PrimaryWorkloadPrefix string

	// ConfigAuditReportsPlugin is the name of the configauditreport.Plugin.
	ConfigAuditReportsPlugin string

	client.Client
	*helper.Helper
}

// VulnerabilityScannerBehavior returns the container of specs that describe behavior
// of a vulnerability scanner with the given inputs.
func VulnerabilityScannerBehavior(inputs *Inputs) func() {
	return func() {

		Context("When unmanaged Pod is created", func() {

			var ctx context.Context
			var pod *corev1.Pod

			BeforeEach(func() {
				ctx = context.Background()
				pod = helper.NewPod().
					WithRandomName("unmanaged-nginx").
					WithNamespace(inputs.PrimaryNamespace).
					WithContainer("nginx", "nginx:1.16").
					Build()

				err := inputs.Create(ctx, pod)
				Expect(err).ToNot(HaveOccurred())
			})

			It("Should create VulnerabilityReport", func() {
				Eventually(inputs.HasVulnerabilityReportOwnedBy(pod), inputs.AssertTimeout).Should(BeTrue())
			})

			AfterEach(func() {
				err := inputs.Delete(ctx, pod)
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("When Deployment is created", func() {

			var ctx context.Context
			var deploy *appsv1.Deployment

			BeforeEach(func() {
				ctx = context.Background()
				deploy = helper.NewDeployment().
					WithRandomName(inputs.PrimaryWorkloadPrefix).
					WithNamespace(inputs.PrimaryNamespace).
					WithContainer("wordpress", "wordpress:4.9").
					Build()

				err := inputs.Create(ctx, deploy)
				Expect(err).ToNot(HaveOccurred())
				Eventually(inputs.HasActiveReplicaSet(inputs.PrimaryNamespace, deploy.Name), inputs.AssertTimeout).Should(BeTrue())
			})

			It("Should create VulnerabilityReport", func() {
				rs, err := inputs.GetActiveReplicaSetForDeployment(inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())
				Expect(rs).ToNot(BeNil())

				Eventually(inputs.HasVulnerabilityReportOwnedBy(rs), inputs.AssertTimeout).Should(BeTrue())
			})

			AfterEach(func() {
				err := inputs.Delete(ctx, deploy)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("When Deployment is rolling updated", func() {

			var ctx context.Context
			var deploy *appsv1.Deployment

			BeforeEach(func() {
				By("Creating Deployment wordpress")
				ctx = context.Background()
				deploy = helper.NewDeployment().
					WithRandomName(inputs.PrimaryWorkloadPrefix).
					WithNamespace(inputs.PrimaryNamespace).
					WithContainer("wordpress", "wordpress:4.9").
					Build()

				err := inputs.Create(ctx, deploy)
				Expect(err).ToNot(HaveOccurred())
				Eventually(inputs.HasActiveReplicaSet(inputs.PrimaryNamespace, deploy.Name), inputs.AssertTimeout).Should(BeTrue())
			})

			It("Should create VulnerabilityReport for new ReplicaSet", func() {
				By("Getting current active ReplicaSet")
				rs, err := inputs.GetActiveReplicaSetForDeployment(inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())
				Expect(rs).ToNot(BeNil())

				By("Waiting for VulnerabilityReport")
				Eventually(inputs.HasVulnerabilityReportOwnedBy(rs), inputs.AssertTimeout).Should(BeTrue())

				By("Updating deployment image to wordpress:5")
				err = inputs.UpdateDeploymentImage(inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())

				Eventually(inputs.HasActiveReplicaSet(inputs.PrimaryNamespace, deploy.Name), inputs.AssertTimeout).Should(BeTrue())

				By("Getting new active replicaset")
				rs, err = inputs.GetActiveReplicaSetForDeployment(inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())
				Expect(rs).ToNot(BeNil())

				By("Waiting for new VulnerabilityReport")
				Eventually(inputs.HasVulnerabilityReportOwnedBy(rs), inputs.AssertTimeout).Should(BeTrue())
			})

			AfterEach(func() {
				err := inputs.Delete(ctx, deploy)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("When CronJob is created", func() {

			var ctx context.Context
			var cronJob *batchv1.CronJob

			BeforeEach(func() {
				ctx = context.Background()
				cronJob = &batchv1.CronJob{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: inputs.PrimaryNamespace,
						Name:      "hello-" + rand.String(5),
					},
					Spec: batchv1.CronJobSpec{
						Schedule: "*/1 * * * *",
						JobTemplate: batchv1.JobTemplateSpec{
							Spec: batchv1.JobSpec{
								Template: corev1.PodTemplateSpec{
									Spec: corev1.PodSpec{
										RestartPolicy: corev1.RestartPolicyOnFailure,
										Containers: []corev1.Container{
											{
												Name:  "hello",
												Image: "busybox",
												Command: []string{
													"/bin/sh",
													"-c",
													"date; echo Hello from the Kubernetes cluster",
												},
											},
										},
									},
								},
							},
						},
					},
				}
				err := inputs.Create(ctx, cronJob)
				Expect(err).ToNot(HaveOccurred())
			})

			It("Should create VulnerabilityReport", func() {
				Eventually(inputs.HasVulnerabilityReportOwnedBy(cronJob), inputs.AssertTimeout).Should(BeTrue())
			})

			AfterEach(func() {
				err := inputs.Delete(ctx, cronJob)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		// TODO Add scenario to test that VulnerabilityReport is recreated

		// TODO Add scenario for workload with multiple containers

		// TODO Add scenario for ReplicaSet

		// TODO Add scenario for StatefulSet

		// TODO Add scenario for DaemonSet
	}
}

// ConfigurationCheckerBehavior returns the container of specs that describe behavior
// of a configuration checker with the given inputs.
func ConfigurationCheckerBehavior(inputs *Inputs) func() {
	return func() {

		Context("When unmanaged Pod is created", func() {

			var ctx context.Context
			var pod *corev1.Pod

			BeforeEach(func() {
				ctx = context.Background()
				pod = helper.NewPod().
					WithRandomName("unmanaged-nginx").
					WithNamespace(inputs.PrimaryNamespace).
					WithContainer("nginx", "nginx:1.16").
					Build()

				err := inputs.Create(ctx, pod)
				Expect(err).ToNot(HaveOccurred())
			})

			It("Should create ConfigAuditReport", func() {
				Eventually(inputs.HasConfigAuditReportOwnedBy(pod), inputs.AssertTimeout).Should(BeTrue())
			})

			AfterEach(func() {
				err := inputs.Delete(ctx, pod)
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("When Deployment is created", func() {

			var ctx context.Context
			var deploy *appsv1.Deployment

			BeforeEach(func() {
				ctx = context.Background()
				deploy = helper.NewDeployment().
					WithRandomName(inputs.PrimaryWorkloadPrefix).
					WithNamespace(inputs.PrimaryNamespace).
					WithContainer("wordpress", "wordpress:4.9").
					Build()

				err := inputs.Create(ctx, deploy)
				Expect(err).ToNot(HaveOccurred())
				Eventually(inputs.HasActiveReplicaSet(inputs.PrimaryNamespace, deploy.Name), inputs.AssertTimeout).Should(BeTrue())
			})

			It("Should create ConfigAuditReport", func() {
				rs, err := inputs.GetActiveReplicaSetForDeployment(inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())
				Expect(rs).ToNot(BeNil())

				Eventually(inputs.HasConfigAuditReportOwnedBy(rs), inputs.AssertTimeout).Should(BeTrue())
			})

			AfterEach(func() {
				err := inputs.Delete(ctx, deploy)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("When Deployment is rolling updated", func() {

			var ctx context.Context
			var deploy *appsv1.Deployment

			BeforeEach(func() {
				By("Creating Deployment wordpress")
				ctx = context.Background()
				deploy = helper.NewDeployment().
					WithRandomName(inputs.PrimaryWorkloadPrefix).
					WithNamespace(inputs.PrimaryNamespace).
					WithContainer("wordpress", "wordpress:4.9").
					Build()

				err := inputs.Create(ctx, deploy)
				Expect(err).ToNot(HaveOccurred())
				Eventually(inputs.HasActiveReplicaSet(inputs.PrimaryNamespace, deploy.Name), inputs.AssertTimeout).Should(BeTrue())
			})

			It("Should create ConfigAuditReport for new ReplicaSet", func() {
				By("Getting current active ReplicaSet")
				rs, err := inputs.GetActiveReplicaSetForDeployment(inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())
				Expect(rs).ToNot(BeNil())

				By("Waiting for ConfigAuditReport")
				Eventually(inputs.HasConfigAuditReportOwnedBy(rs), inputs.AssertTimeout).Should(BeTrue())

				By("Updating deployment image to wordpress:5")
				err = inputs.UpdateDeploymentImage(inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())

				Eventually(inputs.HasActiveReplicaSet(inputs.PrimaryNamespace, deploy.Name), inputs.AssertTimeout).Should(BeTrue())

				By("Getting new active replicaset")
				rs, err = inputs.GetActiveReplicaSetForDeployment(inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())
				Expect(rs).ToNot(BeNil())

				By("Waiting for new Config Audit Report")
				Eventually(inputs.HasConfigAuditReportOwnedBy(rs), inputs.AssertTimeout).Should(BeTrue())
			})

			AfterEach(func() {
				err := inputs.Delete(ctx, deploy)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("When CronJob is created", func() {

			var ctx context.Context
			var cronJob *batchv1beta1.CronJob

			BeforeEach(func() {
				ctx = context.Background()
				cronJob = &batchv1beta1.CronJob{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: inputs.PrimaryNamespace,
						Name:      "hello-" + rand.String(5),
					},
					Spec: batchv1beta1.CronJobSpec{
						Schedule: "*/1 * * * *",
						JobTemplate: batchv1beta1.JobTemplateSpec{
							Spec: batchv1.JobSpec{
								Template: corev1.PodTemplateSpec{
									Spec: corev1.PodSpec{
										RestartPolicy: corev1.RestartPolicyOnFailure,
										Containers: []corev1.Container{
											{
												Name:  "hello",
												Image: "busybox",
												Command: []string{
													"/bin/sh",
													"-c",
													"date; echo Hello from the Kubernetes cluster",
												},
											},
										},
									},
								},
							},
						},
					},
				}
				err := inputs.Create(ctx, cronJob)
				Expect(err).ToNot(HaveOccurred())
			})

			It("Should create ConfigAuditReport", func() {
				Eventually(inputs.HasConfigAuditReportOwnedBy(cronJob), inputs.AssertTimeout).Should(BeTrue())
			})

			AfterEach(func() {
				err := inputs.Delete(ctx, cronJob)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("When ConfigAuditReport is deleted", func() {

			var ctx context.Context
			var deploy *appsv1.Deployment

			BeforeEach(func() {
				By("Creating Deployment")
				ctx = context.Background()
				deploy = helper.NewDeployment().
					WithRandomName(inputs.PrimaryWorkloadPrefix).
					WithNamespace(inputs.PrimaryNamespace).
					WithContainer("wordpress", "wordpress:4.9").
					Build()

				err := inputs.Create(ctx, deploy)
				Expect(err).ToNot(HaveOccurred())
				Eventually(inputs.HasActiveReplicaSet(inputs.PrimaryNamespace, deploy.Name), inputs.AssertTimeout).Should(BeTrue())
			})

			It("Should rescan Deployment when ConfigAuditReport is deleted", func() {
				By("Getting active ReplicaSet")
				rs, err := inputs.GetActiveReplicaSetForDeployment(inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())
				Expect(rs).ToNot(BeNil())

				By("Waiting for ConfigAuditReport")
				Eventually(inputs.HasConfigAuditReportOwnedBy(rs), inputs.AssertTimeout).Should(BeTrue())
				By("Deleting ConfigAuditReport")
				err = inputs.DeleteConfigAuditReportOwnedBy(rs)
				Expect(err).ToNot(HaveOccurred())

				By("Waiting for new ConfigAuditReport")
				Eventually(inputs.HasConfigAuditReportOwnedBy(rs), inputs.AssertTimeout).Should(BeTrue())
			})

			AfterEach(func() {
				err := inputs.Delete(ctx, deploy)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		// TODO Add scenario for workload with multiple containers

		// TODO Add scenario for ReplicaSet

		// TODO Add scenario for StatefulSet

		// TODO Add scenario for DaemonSet

		Context("When Service is created", func() {
			var ctx context.Context
			var svc *corev1.Service

			BeforeEach(func() {
				ctx = context.Background()
				svc = &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: inputs.PrimaryNamespace,
						Name:      "nginx-" + rand.String(5),
					},
					Spec: corev1.ServiceSpec{
						Selector: map[string]string{
							"app": "nginx",
						},
						Ports: []corev1.ServicePort{
							{
								Port:       80,
								TargetPort: intstr.FromInt(80),
								Protocol:   corev1.ProtocolTCP,
							},
						},
					},
				}
				err := inputs.Create(ctx, svc)
				Expect(err).ToNot(HaveOccurred())
			})

			AfterEach(func() {
				err := inputs.Delete(ctx, svc)
				Expect(err).ToNot(HaveOccurred())
			})

		})
	}
}
