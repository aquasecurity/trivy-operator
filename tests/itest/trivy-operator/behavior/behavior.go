package behavior

import (
	"context"
	"errors"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/tests/itest/helper"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Inputs represents required inputs to shared behavior containers.
type Inputs struct {
	AssertTimeout         time.Duration
	PollingInterval       time.Duration
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
					WithRandomName("unmanaged-vuln-image").
					WithNamespace(inputs.PrimaryNamespace).
					WithContainer("vuln-image", "mirror.gcr.io/knqyf263/vuln-image:1.2.3", []string{"/bin/sh", "-c", "--"}, []string{"while true; do sleep 30; done;"}).
					Build()

				err := inputs.Create(ctx, pod)
				Expect(err).ToNot(HaveOccurred())
			})

			It("Should create VulnerabilityReport", func() {
				Eventually(inputs.HasVulnerabilityReportOwnedBy(ctx, pod), inputs.AssertTimeout).Should(BeTrue())
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
				Eventually(inputs.HasActiveReplicaSet(ctx, inputs.PrimaryNamespace, deploy.Name), inputs.AssertTimeout).Should(BeTrue())
			})

			It("Should create VulnerabilityReport", func() {
				rs, err := inputs.GetActiveReplicaSetForDeployment(ctx, inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())
				Expect(rs).ToNot(BeNil())

				Eventually(inputs.HasVulnerabilityReportOwnedBy(ctx, rs), inputs.AssertTimeout).Should(BeTrue())
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
				Eventually(inputs.HasActiveReplicaSet(ctx, inputs.PrimaryNamespace, deploy.Name), inputs.AssertTimeout).Should(BeTrue())
			})

			It("Should create VulnerabilityReport for new ReplicaSet", func() {
				By("Getting current active ReplicaSet")
				rs, err := inputs.GetActiveReplicaSetForDeployment(ctx, inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())
				Expect(rs).ToNot(BeNil())

				By("Waiting for VulnerabilityReport")
				Eventually(inputs.HasVulnerabilityReportOwnedBy(ctx, rs), inputs.AssertTimeout).Should(BeTrue())

				By("Updating deployment image to wordpress:6.7")
				err = inputs.UpdateDeploymentImage(ctx, inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())

				Eventually(inputs.HasActiveReplicaSet(ctx, inputs.PrimaryNamespace, deploy.Name), inputs.AssertTimeout).Should(BeTrue())

				By("Getting new active replicaset")
				rs, err = inputs.GetActiveReplicaSetForDeployment(ctx, inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())
				Expect(rs).ToNot(BeNil())

				By("Waiting for new VulnerabilityReport")
				Eventually(inputs.HasVulnerabilityReportOwnedBy(ctx, rs), inputs.AssertTimeout).Should(BeTrue())
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
				Eventually(inputs.HasVulnerabilityReportOwnedBy(ctx, cronJob), inputs.AssertTimeout).Should(BeTrue())
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
					WithRandomName("unmanaged-vuln-image").
					WithNamespace(inputs.PrimaryNamespace).
					WithContainer("vuln-image", "mirror.gcr.io/knqyf263/vuln-image:1.2.3", []string{"/bin/sh", "-c", "--"}, []string{"while true; do sleep 30; done;"}).
					Build()

				err := inputs.Create(ctx, pod)
				Expect(err).ToNot(HaveOccurred())
			})

			It("Should create ConfigAuditReport", func() {
				Eventually(inputs.HasConfigAuditReportOwnedBy(ctx, pod), inputs.AssertTimeout).Should(BeTrue())
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
				Eventually(inputs.HasActiveReplicaSet(ctx, inputs.PrimaryNamespace, deploy.Name), inputs.AssertTimeout).Should(BeTrue())
			})

			It("Should create ConfigAuditReport", func() {
				rs, err := inputs.GetActiveReplicaSetForDeployment(ctx, inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())
				Expect(rs).ToNot(BeNil())

				Eventually(inputs.HasConfigAuditReportOwnedBy(ctx, rs), inputs.AssertTimeout).Should(BeTrue())
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
				Eventually(inputs.HasActiveReplicaSet(ctx, inputs.PrimaryNamespace, deploy.Name), inputs.AssertTimeout).Should(BeTrue())
			})

			It("Should create ConfigAuditReport for new ReplicaSet", func() {
				By("Getting current active ReplicaSet")
				rs, err := inputs.GetActiveReplicaSetForDeployment(ctx, inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())
				Expect(rs).ToNot(BeNil())

				By("Waiting for ConfigAuditReport")
				Eventually(inputs.HasConfigAuditReportOwnedBy(ctx, rs), inputs.AssertTimeout).Should(BeTrue())

				By("Updating deployment image to wordpress:6.7")
				err = inputs.UpdateDeploymentImage(ctx, inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())

				Eventually(inputs.HasActiveReplicaSet(ctx, inputs.PrimaryNamespace, deploy.Name), inputs.AssertTimeout).Should(BeTrue())

				By("Getting new active replicaset")
				rs, err = inputs.GetActiveReplicaSetForDeployment(ctx, inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())
				Expect(rs).ToNot(BeNil())

				By("Waiting for new Config Audit Report")
				Eventually(inputs.HasConfigAuditReportOwnedBy(ctx, rs), inputs.AssertTimeout).Should(BeTrue())
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

			It("Should create ConfigAuditReport", func() {
				Eventually(inputs.HasConfigAuditReportOwnedBy(ctx, cronJob), inputs.AssertTimeout).Should(BeTrue())
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
				Eventually(inputs.HasActiveReplicaSet(ctx, inputs.PrimaryNamespace, deploy.Name), inputs.AssertTimeout).Should(BeTrue())
			})

			It("Should rescan Deployment when ConfigAuditReport is deleted", func() {
				By("Getting active ReplicaSet")
				rs, err := inputs.GetActiveReplicaSetForDeployment(ctx, inputs.PrimaryNamespace, deploy.Name)
				Expect(err).ToNot(HaveOccurred())
				Expect(rs).ToNot(BeNil())

				By("Waiting for ConfigAuditReport")
				Eventually(inputs.HasConfigAuditReportOwnedBy(ctx, rs), inputs.AssertTimeout).Should(BeTrue())
				By("Deleting ConfigAuditReport")
				err = inputs.DeleteConfigAuditReportOwnedBy(ctx, rs)
				Expect(err).ToNot(HaveOccurred())

				By("Waiting for new ConfigAuditReport")
				Eventually(inputs.HasConfigAuditReportOwnedBy(ctx, rs), inputs.AssertTimeout).Should(BeTrue())
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

		Context("When PersistentVolume is created", func() {

			var ctx context.Context
			var pv *corev1.PersistentVolume

			BeforeEach(func() {
				ctx = context.Background()
				pv = &corev1.PersistentVolume{
					ObjectMeta: metav1.ObjectMeta{
						Name: "pv-" + rand.String(5),
					},
					Spec: corev1.PersistentVolumeSpec{
						Capacity: corev1.ResourceList{
							corev1.ResourceStorage: resource.MustParse("1Gi"),
						},
						AccessModes:                   []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
						PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimDelete,
						PersistentVolumeSource: corev1.PersistentVolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/tmp"},
						},
					},
				}

				err := inputs.Create(ctx, pv)
				Expect(err).ToNot(HaveOccurred())
			})

			It("Should create ClusterConfigAuditReport", func() {
				Eventually(inputs.HasClusterConfigAuditReportOwnedBy(ctx, pv), inputs.AssertTimeout).Should(BeTrue())
			})

			AfterEach(func() {
				err := inputs.Delete(ctx, pv)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("When PersistentVolumeClaim is created", func() {

			var ctx context.Context
			var pvc *corev1.PersistentVolumeClaim

			BeforeEach(func() {
				ctx = context.Background()
				qty := resource.MustParse("1Gi")
				pvc = &corev1.PersistentVolumeClaim{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: inputs.PrimaryNamespace,
						Name:      "pvc-" + rand.String(5),
					},
					Spec: corev1.PersistentVolumeClaimSpec{
						AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
						Resources: corev1.VolumeResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceStorage: qty,
							},
						},
					},
				}
				err := inputs.Create(ctx, pvc)
				Expect(err).ToNot(HaveOccurred())
			})

			It("Should create ConfigAuditReport", func() {
				Eventually(inputs.HasConfigAuditReportOwnedBy(ctx, pvc), inputs.AssertTimeout).Should(BeTrue())
			})

			AfterEach(func() {
				err := inputs.Delete(ctx, pvc)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("When PersistentVolumeClaim scanning is disabled", func() {

			var (
				ctx           context.Context
				pluginCM      *corev1.ConfigMap
				pvc           *corev1.PersistentVolumeClaim
				originalKinds string
				cleanupPVC    func()
				restoreConfig func()
			)

			findPluginConfigMap := func(ctx context.Context) (*corev1.ConfigMap, error) {
				var cms corev1.ConfigMapList
				if err := inputs.Client.List(ctx, &cms, &client.ListOptions{}); err != nil {
					return nil, err
				}
				name := trivyoperator.GetPluginConfigMapName("Trivy")
				for i := range cms.Items {
					cm := cms.Items[i]
					if cm.Name == name {
						cpy := cm.DeepCopy()
						return cpy, nil
					}
				}
				return nil, nil
			}

			BeforeEach(func() {
				ctx = context.Background()

				var err error
				pluginCM, err = findPluginConfigMap(ctx)
				Expect(err).ToNot(HaveOccurred())
				Expect(pluginCM).ToNot(BeNil(), "plugin configmap not found")

				if pluginCM.Data == nil {
					pluginCM.Data = map[string]string{}
				}
				originalKinds = pluginCM.Data["trivy.supportedConfigAuditKinds"]

				kinds := originalKinds
				if kinds == "" {
					kinds = "Workload,Service,Role,ClusterRole,NetworkPolicy,Ingress,LimitRange,ResourceQuota"
				}
				parts := []string{}
				for _, k := range strings.Split(kinds, ",") {
					k = strings.TrimSpace(k)
					if k == "PersistentVolumeClaim" {
						continue
					}
					parts = append(parts, k)
				}
				pluginCM.Data["trivy.supportedConfigAuditKinds"] = strings.Join(parts, ",")
				err = inputs.Client.Update(ctx, pluginCM)
				Expect(err).ToNot(HaveOccurred())

				// allow operator to reload config
				time.Sleep(2 * time.Second)

				qty := resource.MustParse("1Gi")
				pvc = &corev1.PersistentVolumeClaim{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: inputs.PrimaryNamespace,
						Name:      "pvc-" + rand.String(5),
					},
					Spec: corev1.PersistentVolumeClaimSpec{
						AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
						Resources: corev1.VolumeResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceStorage: qty,
							},
						},
					},
				}
				err = inputs.Create(ctx, pvc)
				Expect(err).ToNot(HaveOccurred())

				cleanupPVC = func() { _ = inputs.Delete(ctx, pvc) }
				restoreConfig = func() {
					cm, err := findPluginConfigMap(ctx)
					if err == nil && cm != nil {
						if cm.Data == nil {
							cm.Data = map[string]string{}
						}
						cm.Data["trivy.supportedConfigAuditKinds"] = originalKinds
						_ = inputs.Client.Update(ctx, cm)
					}
				}
			})

			AfterEach(func() {
				if cleanupPVC != nil {
					cleanupPVC()
				}
				if restoreConfig != nil {
					restoreConfig()
				}
			})

			It("Should not create ConfigAuditReport for PVC", func() {
				Consistently(inputs.HasConfigAuditReportOwnedBy(ctx, pvc), time.Minute, inputs.PollingInterval).Should(BeFalse())
			})
		})
	}
}

func VulnerabilityScanJobTTLBehavior(inputs *Inputs) func() {
	return func() {

		Context("When unmanaged Pod is created", func() {

			var ctx context.Context
			var pod *corev1.Pod

			BeforeAll(func() {
				ctx = context.Background()
				pod = helper.NewPod().
					WithRandomName("unmanaged-nginx").
					WithNamespace(inputs.PrimaryNamespace).
					WithContainer("nginx", "nginx:1.16", nil, nil).
					Build()

				err := inputs.Create(ctx, pod)
				Expect(err).ToNot(HaveOccurred())
			})

			It("Should create VulnerabilityReport", func() {
				Eventually(inputs.HasVulnerabilityReportOwnedBy(ctx, pod), inputs.AssertTimeout, inputs.PollingInterval).Should(BeTrue())
			})

			It("Should keep ScanJob in completed state", func() {
				Eventually(inputs.HasScanJobPodOwnedBy(ctx, pod), inputs.AssertTimeout, inputs.PollingInterval).Should(BeTrue())

				Eventually(ctx, func() (string, error) {
					scanJobPod, err := inputs.GetScanJobPodOwnedBy(ctx, pod)()

					if err != nil {
						return "", err
					}

					if len(scanJobPod.Status.ContainerStatuses) == 0 {
						return "", errors.New("no container statuses found")
					}

					containerStatus := scanJobPod.Status.ContainerStatuses[0]
					if containerStatus.State.Terminated == nil {
						return "", errors.New("container is not terminated")
					}

					return containerStatus.State.Terminated.Reason, nil
				}, inputs.AssertTimeout, inputs.PollingInterval).Should(Equal("Completed"))
			})

			AfterAll(func() {
				err := inputs.Delete(ctx, pod)
				Expect(err).ToNot(HaveOccurred())
			})

			It("Should delete ScanJob after ttl expired", func() {
				Eventually(inputs.HasScanJobPodOwnedBy(ctx, pod), inputs.AssertTimeout, inputs.PollingInterval).Should(BeFalse())
			})

		})
	}
}
