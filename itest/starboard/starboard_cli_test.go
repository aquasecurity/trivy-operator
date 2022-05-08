package starboard

import (
	. "github.com/aquasecurity/trivy-operator/itest/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gstruct"

	"context"
	"time"

	"github.com/aquasecurity/trivy-operator/itest/helper"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/cmd"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

var (
	assertTimeout = 10 * time.Second
)

var _ = Describe("Starboard CLI", func() {

	BeforeEach(func() {
		err := cmd.Run(versionInfo, []string{
			"starboard", "install",
			"-v", starboardCLILogLevel,
		}, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("Command install", func() {

		It("should install Starboard", func() {

			crdList, err := customResourceDefinitions.List(context.TODO(), metav1.ListOptions{
				LabelSelector: "app.kubernetes.io/managed-by=trivy-operator",
			})
			Expect(err).ToNot(HaveOccurred())

			groupByName := func(element interface{}) string {
				return element.(apiextensionsv1beta1.CustomResourceDefinition).Name
			}

			Expect(crdList.Items).To(MatchAllElements(groupByName, Elements{
				"vulnerabilityreports.aquasecurity.github.io": MatchFields(IgnoreExtras, Fields{
					"Spec": MatchFields(IgnoreExtras, Fields{
						"Group":   Equal("aquasecurity.github.io"),
						"Version": Equal("v1alpha1"),
						"Names": Equal(apiextensionsv1beta1.CustomResourceDefinitionNames{
							Plural:     "vulnerabilityreports",
							Singular:   "vulnerabilityreport",
							ShortNames: []string{"vuln", "vulns"},
							Kind:       "VulnerabilityReport",
							ListKind:   "VulnerabilityReportList",
						}),
						"Scope": Equal(apiextensionsv1beta1.NamespaceScoped),
					}),
				}),
				"clustervulnerabilityreports.aquasecurity.github.io": MatchFields(IgnoreExtras, Fields{
					"Spec": MatchFields(IgnoreExtras, Fields{
						"Group":   Equal("aquasecurity.github.io"),
						"Version": Equal("v1alpha1"),
						"Names": Equal(apiextensionsv1beta1.CustomResourceDefinitionNames{
							Plural:     "clustervulnerabilityreports",
							Singular:   "clustervulnerabilityreport",
							ShortNames: []string{"clustervuln", "clustervulns"},
							Kind:       "ClusterVulnerabilityReport",
							ListKind:   "ClusterVulnerabilityReportList",
						}),
						"Scope": Equal(apiextensionsv1beta1.ClusterScoped),
					}),
				}),
				"clustercompliancereports.aquasecurity.github.io": MatchFields(IgnoreExtras, Fields{
					"Spec": MatchFields(IgnoreExtras, Fields{
						"Group":   Equal("aquasecurity.github.io"),
						"Version": Equal("v1alpha1"),
						"Names": Equal(apiextensionsv1beta1.CustomResourceDefinitionNames{
							Plural:     "clustercompliancereports",
							Singular:   "clustercompliancereport",
							ShortNames: []string{"compliance"},
							Kind:       "ClusterComplianceReport",
							ListKind:   "ClusterComplianceReportList",
						}),
						"Scope": Equal(apiextensionsv1beta1.ClusterScoped),
					}),
				}),
				"clustercompliancedetailreports.aquasecurity.github.io": MatchFields(IgnoreExtras, Fields{
					"Spec": MatchFields(IgnoreExtras, Fields{
						"Group":   Equal("aquasecurity.github.io"),
						"Version": Equal("v1alpha1"),
						"Names": Equal(apiextensionsv1beta1.CustomResourceDefinitionNames{
							Plural:     "clustercompliancedetailreports",
							Singular:   "clustercompliancedetailreport",
							ShortNames: []string{"compliancedetail"},
							Kind:       "ClusterComplianceDetailReport",
							ListKind:   "ClusterComplianceDetailReportList",
						}),
						"Scope": Equal(apiextensionsv1beta1.ClusterScoped),
					}),
				}),
				"configauditreports.aquasecurity.github.io": MatchFields(IgnoreExtras, Fields{
					"Spec": MatchFields(IgnoreExtras, Fields{
						"Group":   Equal("aquasecurity.github.io"),
						"Version": Equal("v1alpha1"),
						"Scope":   Equal(apiextensionsv1beta1.NamespaceScoped),
						"Names": Equal(apiextensionsv1beta1.CustomResourceDefinitionNames{
							Plural:     "configauditreports",
							Singular:   "configauditreport",
							ShortNames: []string{"configaudit"},
							Kind:       "ConfigAuditReport",
							ListKind:   "ConfigAuditReportList",
						}),
					}),
				}),
				"clusterconfigauditreports.aquasecurity.github.io": MatchFields(IgnoreExtras, Fields{
					"Spec": MatchFields(IgnoreExtras, Fields{
						"Group":   Equal("aquasecurity.github.io"),
						"Version": Equal("v1alpha1"),
						"Scope":   Equal(apiextensionsv1beta1.ClusterScoped),
						"Names": Equal(apiextensionsv1beta1.CustomResourceDefinitionNames{
							Plural:     "clusterconfigauditreports",
							Singular:   "clusterconfigauditreport",
							ShortNames: []string{"clusterconfigaudit"},
							Kind:       "ClusterConfigAuditReport",
							ListKind:   "ClusterConfigAuditReportList",
						}),
					}),
				}),
				"ciskubebenchreports.aquasecurity.github.io": MatchFields(IgnoreExtras, Fields{
					"Spec": MatchFields(IgnoreExtras, Fields{
						"Group":   Equal("aquasecurity.github.io"),
						"Version": Equal("v1alpha1"),
						"Scope":   Equal(apiextensionsv1beta1.ClusterScoped),
						"Names": Equal(apiextensionsv1beta1.CustomResourceDefinitionNames{
							Plural:     "ciskubebenchreports",
							Singular:   "ciskubebenchreport",
							ShortNames: []string{"kubebench"},
							Kind:       "CISKubeBenchReport",
							ListKind:   "CISKubeBenchReportList",
						}),
					}),
				}),
				"kubehunterreports.aquasecurity.github.io": MatchFields(IgnoreExtras, Fields{
					"Spec": MatchFields(IgnoreExtras, Fields{
						"Group":   Equal("aquasecurity.github.io"),
						"Version": Equal("v1alpha1"),
						"Scope":   Equal(apiextensionsv1beta1.ClusterScoped),
						"Names": Equal(apiextensionsv1beta1.CustomResourceDefinitionNames{
							Plural:     "kubehunterreports",
							Singular:   "kubehunterreport",
							ShortNames: []string{"kubehunter"},
							Kind:       "KubeHunterReport",
							ListKind:   "KubeHunterReportList",
						}),
					}),
				}),
			}))

			err = kubeClient.Get(context.TODO(), types.NamespacedName{
				Name: trivyoperator.NamespaceName,
			}, &corev1.Namespace{})
			Expect(err).ToNot(HaveOccurred())

			var cm corev1.ConfigMap
			err = kubeClient.Get(context.TODO(), types.NamespacedName{
				Name:      trivyoperator.ConfigMapName,
				Namespace: trivyoperator.NamespaceName,
			}, &cm)

			Expect(err).ToNot(HaveOccurred())
			Expect(cm.Data).To(BeEquivalentTo(trivyoperator.GetDefaultConfig()))

			var secret corev1.Secret
			err = kubeClient.Get(context.TODO(), types.NamespacedName{
				Name:      trivyoperator.SecretName,
				Namespace: trivyoperator.NamespaceName,
			}, &secret)
			Expect(err).ToNot(HaveOccurred())
			Expect(secret.Data).To(Equal(map[string][]byte(nil)))

			err = kubeClient.Get(context.TODO(), types.NamespacedName{
				Name:      trivyoperator.ServiceAccountName,
				Namespace: trivyoperator.NamespaceName,
			}, &corev1.ServiceAccount{})
			Expect(err).ToNot(HaveOccurred())
		})
		It("should deploy nsa report", func() {
			nsaSpec := &v1alpha1.ClusterComplianceReport{}
			err := kubeClient.Get(context.TODO(), types.NamespacedName{
				Name: "nsa",
			}, nsaSpec)
			Expect(err).ToNot(HaveOccurred())
			Expect(nsaSpec.Spec.Name == "nsa").To(BeTrue())
			Expect(nsaSpec.Spec.Description == "National Security Agency - Kubernetes Hardening Guidance").To(BeTrue())
			Expect(nsaSpec.Spec.Cron == "0 */3 * * *").To(BeTrue())
			Expect(nsaSpec.Spec.Version == "1.0").To(BeTrue())
			Expect(len(nsaSpec.Spec.Controls) == 27).To(BeTrue())
		})
	})
	Describe("Command version", func() {

		It("should print the current version of the executable binary", func() {
			out := NewBuffer()
			err := cmd.Run(versionInfo, []string{
				"starboard",
				"version",
			}, out, out)
			Expect(err).ToNot(HaveOccurred())
			Eventually(out).Should(Say("Starboard Version: {Version:dev Commit:none Date:unknown}"))
		})
	})

	Describe("Command scan vulnerabilityreports", func() {

		groupByContainerName := func(element interface{}) string {
			return element.(v1alpha1.VulnerabilityReport).
				Labels[trivyoperator.LabelContainerName]
		}

		Context("when unmanaged Pod is specified as workload", func() {

			var ctx context.Context
			var pod *corev1.Pod

			BeforeEach(func() {
				ctx = context.TODO()
				pod = helper.NewPod().WithRandomName("nginx").
					WithNamespace(testNamespace.Name).
					WithContainer("nginx-container", "nginx:1.16").
					Build()
				err := kubeClient.Create(ctx, pod)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create VulnerabilityReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "pod/" + pod.Name,
					"--namespace", pod.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				reports, err := vulnerabilityreport.NewReadWriter(kubeClient).FindByOwner(ctx, kube.ObjectRef{
					Kind:      kube.KindPod,
					Name:      pod.Name,
					Namespace: pod.Namespace,
				})
				Expect(err).ToNot(HaveOccurred())

				Expect(reports).To(MatchAllElements(groupByContainerName, Elements{
					"nginx-container": IsVulnerabilityReportForContainerOwnedBy("nginx-container", pod),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(context.TODO(), pod)
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when unmanaged Pod with multiple containers is specified as workload", func() {

			var ctx context.Context
			var pod *corev1.Pod

			BeforeEach(func() {
				ctx = context.TODO()
				pod = helper.NewPod().WithRandomName("nginx-and-redis").
					WithNamespace(testNamespace.Name).
					WithContainer("nginx-container", "nginx:1.16").
					WithContainer("redis-container", "redis:5").
					Build()
				err := kubeClient.Create(ctx, pod)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create VulnerabilityReports", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "pod/" + pod.Name,
					"--namespace", pod.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				reports, err := vulnerabilityreport.NewReadWriter(kubeClient).FindByOwner(ctx, kube.ObjectRef{
					Kind:      kube.KindPod,
					Name:      pod.Name,
					Namespace: pod.Namespace,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reports).To(MatchAllElements(groupByContainerName, Elements{
					"nginx-container": IsVulnerabilityReportForContainerOwnedBy("nginx-container", pod),
					"redis-container": IsVulnerabilityReportForContainerOwnedBy("redis-container", pod),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(ctx, pod)
				Expect(err).ToNot(HaveOccurred())
			})

		})

		// TODO Run pending specs with other tests used to validate each PR.
		//
		// The only reason these tests are marked as pending is that I don't know how to pass private repository
		// credentials from GitHub Actions runner via STARBOARD_TEST_REGISTRY_USERNAME and STARBOARD_TEST_REGISTRY_PASSWORD
		// environment variables down to Go tests. The main challenge is that GitHub secrets are not available to
		// workflow runs initiated from forked repositories. In other words, expressions like
		// ${{ secrets.STARBOARD_TEST_REGISTRY_PASSWORD }} will evaluate to a blank string.
		PContext("when unmanaged Pod with private image is specified as workload", func() {

			var ctx context.Context
			var imagePullSecret *corev1.Secret
			var pod *corev1.Pod

			BeforeEach(func() {
				var err error

				ctx = context.TODO()

				imagePullSecret, err = helper.NewDockerRegistrySecret().
					WithRandomName("regcred").
					WithNamespace(testNamespace.Name).
					WithServer(privateRegistryConfig.Server).
					WithUsername(privateRegistryConfig.Username).
					WithPassword(privateRegistryConfig.Password).
					Build()
				Expect(err).ToNot(HaveOccurred())
				err = kubeClient.Create(ctx, imagePullSecret)
				Expect(err).ToNot(HaveOccurred())

				pod = helper.NewPod().WithRandomName("private-pod").
					WithNamespace(testNamespace.Name).
					WithContainer("private", privateRegistryConfig.ImageRef).
					WithImagePullSecret(imagePullSecret.Name).
					Build()
				err = kubeClient.Create(ctx, pod)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create VulnerabilityReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "po/" + pod.Name,
					"--namespace", pod.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				var reportList v1alpha1.VulnerabilityReportList
				err = kubeClient.List(ctx, &reportList, client.MatchingLabels{
					trivyoperator.LabelResourceKind:      string(kube.KindPod),
					trivyoperator.LabelResourceName:      pod.Name,
					trivyoperator.LabelResourceNamespace: pod.Namespace,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reportList.Items).To(MatchAllElements(groupByContainerName, Elements{
					"private": IsVulnerabilityReportForContainerOwnedBy("private", pod),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(ctx, pod)
				Expect(err).ToNot(HaveOccurred())

				err = kubeClient.Delete(ctx, imagePullSecret)
				Expect(err).ToNot(HaveOccurred())
			})

		})

		PContext("when unmanaged Pod with private image and service account is specified as workload", func() {

			var ctx context.Context
			var imagePullSecret *corev1.Secret
			var serviceAccount *corev1.ServiceAccount
			var pod *corev1.Pod

			BeforeEach(func() {
				var err error

				ctx = context.TODO()

				imagePullSecret, err = helper.NewDockerRegistrySecret().
					WithRandomName("regcred").
					WithNamespace(testNamespace.Name).
					WithServer(privateRegistryConfig.Server).
					WithUsername(privateRegistryConfig.Username).
					WithPassword(privateRegistryConfig.Password).
					Build()
				Expect(err).ToNot(HaveOccurred())
				err = kubeClient.Create(ctx, imagePullSecret)
				Expect(err).ToNot(HaveOccurred())

				serviceAccount = helper.NewServiceAccount().
					WithRandomName("test-sa").
					WithNamespace(testNamespace.Name).
					WithImagePullSecret(imagePullSecret.Name).
					Build()
				err = kubeClient.Create(ctx, serviceAccount)
				Expect(err).ToNot(HaveOccurred())

				pod = helper.NewPod().
					WithRandomName("private-pod").
					WithNamespace(testNamespace.Name).
					WithContainer("private", privateRegistryConfig.ImageRef).
					WithServiceAccountName(serviceAccount.Name).
					Build()
				err = kubeClient.Create(ctx, pod)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create VulnerabilityReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "po/" + pod.Name,
					"--namespace", pod.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				var reportList v1alpha1.VulnerabilityReportList
				err = kubeClient.List(ctx, &reportList, client.MatchingLabels{
					trivyoperator.LabelResourceKind:      string(kube.KindPod),
					trivyoperator.LabelResourceName:      pod.Name,
					trivyoperator.LabelResourceNamespace: pod.Namespace,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reportList.Items).To(MatchAllElements(groupByContainerName, Elements{
					"private": IsVulnerabilityReportForContainerOwnedBy("private", pod),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(ctx, pod)
				Expect(err).ToNot(HaveOccurred())

				err = kubeClient.Delete(ctx, serviceAccount)
				Expect(err).ToNot(HaveOccurred())

				err = kubeClient.Delete(ctx, imagePullSecret)
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when ReplicaSet is specified as workload", func() {

			var ctx context.Context
			var rs *appsv1.ReplicaSet

			BeforeEach(func() {
				ctx = context.TODO()
				rs = &appsv1.ReplicaSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "nginx",
						Namespace: testNamespace.Name,
					},
					Spec: appsv1.ReplicaSetSpec{
						Replicas: pointer.Int32Ptr(1),
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "nginx"},
						},
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{
								Labels: labels.Set{
									"app": "nginx",
								},
							},
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name:  "nginx",
										Image: "nginx:1.16",
									},
								},
							},
						},
					},
				}
				err := kubeClient.Create(ctx, rs)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create VulnerabilityReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "replicaset/" + rs.Name,
					"--namespace", rs.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				reports, err := vulnerabilityreport.NewReadWriter(kubeClient).FindByOwner(ctx, kube.ObjectRef{
					Kind:      kube.KindReplicaSet,
					Name:      rs.Name,
					Namespace: rs.Namespace,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reports).To(MatchAllElements(groupByContainerName, Elements{
					"nginx": IsVulnerabilityReportForContainerOwnedBy("nginx", rs),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(ctx, rs)
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when ReplicationController is specified as workload", func() {

			var ctx context.Context
			var rc *corev1.ReplicationController

			BeforeEach(func() {
				ctx = context.TODO()
				rc = &corev1.ReplicationController{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "nginx",
						Namespace: testNamespace.Name,
					},
					Spec: corev1.ReplicationControllerSpec{
						Replicas: pointer.Int32Ptr(1),
						Selector: map[string]string{
							"app": "nginx",
						},
						Template: &corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{
								Labels: labels.Set{
									"app": "nginx",
								},
							},
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name:  "nginx",
										Image: "nginx:1.16",
									},
								},
							},
						},
					},
				}
				err := kubeClient.Create(ctx, rc)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create VulnerabilityReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "rc/" + rc.Name,
					"--namespace", rc.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				reports, err := vulnerabilityreport.NewReadWriter(kubeClient).FindByOwner(ctx, kube.ObjectRef{
					Kind:      kube.KindReplicationController,
					Name:      rc.Name,
					Namespace: rc.Namespace,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reports).To(MatchAllElements(groupByContainerName, Elements{
					"nginx": IsVulnerabilityReportForContainerOwnedBy("nginx", rc),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(ctx, rc)
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when Deployment is specified as workload", func() {

			var ctx context.Context
			var deploy *appsv1.Deployment

			BeforeEach(func() {
				ctx = context.TODO()
				deploy = helper.NewDeployment().WithRandomName("nginx").
					WithNamespace(testNamespace.Name).
					WithContainer("nginx-container", "nginx:1.16").
					Build()
				err := kubeClient.Create(ctx, deploy)
				Expect(err).ToNot(HaveOccurred())

				Eventually(help.DeploymentIsReady(
					client.ObjectKey{
						Namespace: deploy.Namespace,
						Name:      deploy.Name,
					}), assertTimeout).Should(BeTrue())

				err = kubeClient.Get(ctx, client.ObjectKey{Namespace: deploy.Namespace, Name: deploy.Name}, deploy)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create VulnerabilityReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "deployment/" + deploy.Name,
					"--namespace", deploy.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				revision, err := objectResolver.ReplicaSetByDeployment(ctx, deploy)
				Expect(err).ToNot(HaveOccurred())

				reports, err := vulnerabilityreport.NewReadWriter(kubeClient).FindByOwner(ctx, kube.ObjectRef{
					Kind:      kube.KindReplicaSet,
					Name:      revision.Name,
					Namespace: revision.Namespace,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reports).To(MatchAllElements(groupByContainerName, Elements{
					"nginx-container": IsVulnerabilityReportForContainerOwnedBy("nginx-container", revision),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(ctx, deploy)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("when Deployment with very long name is specified as workload", func() {

			var ctx context.Context
			var deploy *appsv1.Deployment

			BeforeEach(func() {
				ctx = context.TODO()
				deploy = helper.NewDeployment().
					WithName("core-competency-matrix-production-prometheus-redis-exporter").
					WithNamespace(testNamespace.Name).
					WithContainer("redis-exporter", "docker.io/oliver006/redis_exporter:v1.29.0").
					Build()
				err := kubeClient.Create(ctx, deploy)
				Expect(err).ToNot(HaveOccurred())

				Eventually(help.DeploymentIsReady(
					client.ObjectKey{
						Name:      deploy.Name,
						Namespace: deploy.Namespace,
					}), assertTimeout).Should(BeTrue())

				err = kubeClient.Get(ctx, client.ObjectKey{Namespace: deploy.Namespace, Name: deploy.Name}, deploy)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create VulnerabilityReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "deployment/" + deploy.Name,
					"--namespace", deploy.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				revision, err := objectResolver.ReplicaSetByDeployment(ctx, deploy)
				Expect(err).ToNot(HaveOccurred())

				reports, err := vulnerabilityreport.NewReadWriter(kubeClient).FindByOwner(ctx, kube.ObjectRef{
					Kind:      kube.KindReplicaSet,
					Name:      revision.Name,
					Namespace: revision.Namespace,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reports).To(MatchAllElements(groupByContainerName, Elements{
					"redis-exporter": IsVulnerabilityReportForContainerOwnedBy("redis-exporter", revision),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(ctx, deploy)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("when StatefulSet is specified as workload", func() {

			var ctx context.Context
			var sts *appsv1.StatefulSet

			BeforeEach(func() {
				ctx = context.TODO()
				sts = &appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-sts",
						Namespace: testNamespace.Name,
					},
					Spec: appsv1.StatefulSetSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "test-sts",
							},
						},
						ServiceName: "test-sts",
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{
								Labels: map[string]string{
									"app": "test-sts",
								},
							},
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name:    "test-sts-container",
										Image:   "busybox:1.28",
										Command: []string{"sleep", "5000"},
									},
								},
							},
						},
					},
				}
				err := kubeClient.Create(ctx, sts)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create VulnerabilityReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "sts/" + sts.Name,
					"--namespace", sts.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				reports, err := vulnerabilityreport.NewReadWriter(kubeClient).FindByOwner(ctx, kube.ObjectRef{
					Kind:      kube.KindStatefulSet,
					Name:      sts.Name,
					Namespace: sts.Namespace,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reports).To(MatchAllElements(groupByContainerName, Elements{
					"test-sts-container": IsVulnerabilityReportForContainerOwnedBy("test-sts-container", sts),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(ctx, sts)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("when DaemonSet is specified as workload", func() {

			var ctx context.Context
			var ds *appsv1.DaemonSet

			BeforeEach(func() {
				ctx = context.TODO()
				ds = &appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-ds",
						Namespace: testNamespace.Name,
					},
					Spec: appsv1.DaemonSetSpec{
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"app": "test-ds",
							},
						},
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{
								Labels: map[string]string{
									"app": "test-ds",
								},
							},
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name:    "test-ds-container",
										Image:   "busybox:1.28",
										Command: []string{"sleep", "5000"},
									},
								},
							},
						},
					},
				}
				err := kubeClient.Create(ctx, ds)
				Expect(err).ToNot(HaveOccurred())
			})

			It("Should create VulnerabilityReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "vulnerabilityreports", "ds/" + ds.Name,
					"--namespace", ds.Namespace,
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				reports, err := vulnerabilityreport.NewReadWriter(kubeClient).FindByOwner(ctx, kube.ObjectRef{
					Kind:      kube.KindDaemonSet,
					Name:      ds.Name,
					Namespace: ds.Namespace,
				})
				Expect(err).ToNot(HaveOccurred())
				Expect(reports).To(MatchAllElements(groupByContainerName, Elements{
					"test-ds-container": IsVulnerabilityReportForContainerOwnedBy("test-ds-container", ds),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(ctx, ds)
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Describe("Command get vulnerabilityreports", func() {
		Context("for deployment/nginx resource", func() {
			When("vulnerabilities are associated with the deployment itself", func() {

				var ctx context.Context
				var deploy *appsv1.Deployment
				var report *v1alpha1.VulnerabilityReport

				BeforeEach(func() {
					ctx = context.TODO()
					deploy = helper.NewDeployment().WithName("nginx").
						WithNamespace(testNamespace.Name).
						WithContainer("nginx", "nginx:1.16").
						Build()
					err := kubeClient.Create(ctx, deploy)
					Expect(err).ToNot(HaveOccurred())

					report = helper.NewVulnerabilityReport().WithName("0e1e25ab-8c55-4cdc-af64-21fb8f412cb0").
						WithNamespace(testNamespace.Name).
						WithOwnerKind(kube.KindDeployment).
						WithOwnerName(deploy.Name).
						Build()
					err = kubeClient.Create(ctx, report)
					Expect(err).ToNot(HaveOccurred())
				})

				When("getting vulnerabilities by deployment name", func() {
					It("should return the vulnerabilities", func() {
						stdout := NewBuffer()
						stderr := NewBuffer()

						err := cmd.Run(versionInfo, []string{
							"starboard", "get", "vulnerabilityreports",
							"deployment/" + deploy.Name,
							"--namespace", deploy.Namespace,
							"--output", "yaml",
							"-v", starboardCLILogLevel,
						}, stdout, stderr)
						Expect(err).ToNot(HaveOccurred())

						var list v1alpha1.VulnerabilityReportList
						err = yaml.Unmarshal(stdout.Contents(), &list)
						Expect(err).ToNot(HaveOccurred())

						if Expect(len(list.Items)).To(Equal(1)) {
							item := list.Items[0]
							item.Report.UpdateTimestamp = report.Report.UpdateTimestamp // TODO A Hack to skip comparing timestamp
							Expect(item.Report).To(Equal(report.Report))
						}

						Expect(stderr).Should(Say(""))
					})
				})

				AfterEach(func() {
					err := kubeClient.Delete(ctx, report)
					Expect(err).ToNot(HaveOccurred())

					err = kubeClient.Delete(ctx, deploy)
					Expect(err).ToNot(HaveOccurred())
				})
			})

			When("vulnerabilities are associated with the managed replicaset", func() {
				var deploy *appsv1.Deployment
				var replicasetName string
				var podName string
				var report *v1alpha1.VulnerabilityReport

				BeforeEach(func() {
					deploy = helper.NewDeployment().WithRandomName("nginx").
						WithNamespace(testNamespace.Name).
						WithContainer("nginx", "nginx:1.16").
						Build()
					err := kubeClient.Create(context.TODO(), deploy)
					Expect(err).ToNot(HaveOccurred())

					replicasetName = ""
					for i := 0; i < 10; i++ {
						var rsList appsv1.ReplicaSetList
						err := kubeClient.List(context.TODO(), &rsList)
						Expect(err).ToNot(HaveOccurred())
						if len(rsList.Items) > 0 {
							for _, rs := range rsList.Items {
								for _, ownerRef := range rs.OwnerReferences {
									if ownerRef.Name == deploy.Name && *ownerRef.Controller {
										replicasetName = rs.Name
									}
								}
							}
							if replicasetName != "" {
								break
							}
						}
						time.Sleep(time.Second)
					}
					Expect(replicasetName).ToNot(BeEmpty())

					podName = ""
					for i := 0; i < 10; i++ {
						var podList corev1.PodList
						err := kubeClient.List(context.TODO(), &podList)
						Expect(err).ToNot(HaveOccurred())
						if len(podList.Items) > 0 {
							for _, pod := range podList.Items {
								for _, ownerRef := range pod.OwnerReferences {
									if ownerRef.Name == replicasetName && *ownerRef.Controller {
										podName = pod.Name
									}
								}
							}
							if podName != "" {
								break
							}
						}
						time.Sleep(time.Second)
					}
					Expect(podName).ToNot(BeEmpty())

					report = helper.NewVulnerabilityReport().WithName("0e1e25ab-8c55-4cdc-af64-21fb8f412cb0").
						WithNamespace(testNamespace.Name).
						WithOwnerKind(kube.KindReplicaSet).
						WithOwnerName(replicasetName).
						Build()
					err = kubeClient.Create(context.TODO(), report)
					Expect(err).ToNot(HaveOccurred())
				})

				When("getting vulnerabilities by deployment name", func() {
					It("should return the vulnerabilities", func() {
						stdout := NewBuffer()
						stderr := NewBuffer()

						err := cmd.Run(versionInfo, []string{
							"starboard", "get", "vulnerabilities",
							"deployment/" + deploy.Name,
							"--namespace", testNamespace.Name,
							"--output", "yaml",
							"-v", starboardCLILogLevel,
						}, stdout, stderr)
						Expect(err).ToNot(HaveOccurred())

						var list v1alpha1.VulnerabilityReportList
						err = yaml.Unmarshal(stdout.Contents(), &list)
						Expect(err).ToNot(HaveOccurred())

						if Expect(len(list.Items)).To(Equal(1)) {
							item := list.Items[0]
							item.Report.UpdateTimestamp = report.Report.UpdateTimestamp // TODO A Hack to skip comparing timestamp
							Expect(item.Report).To(Equal(report.Report))
						}

						Expect(stderr).Should(Say(""))
					})
				})

				When("getting vulnerabilities by replicaset name", func() {
					It("should return the vulnerabilities", func() {
						stdout := NewBuffer()
						stderr := NewBuffer()

						err := cmd.Run(versionInfo, []string{
							"starboard", "get", "vulnerabilities",
							"replicaset/" + replicasetName,
							"--namespace", testNamespace.Name,
							"--output", "yaml",
							"-v", starboardCLILogLevel,
						}, stdout, stderr)
						Expect(err).ToNot(HaveOccurred())

						var list v1alpha1.VulnerabilityReportList
						err = yaml.Unmarshal(stdout.Contents(), &list)
						Expect(err).ToNot(HaveOccurred())

						if Expect(len(list.Items)).To(Equal(1)) {
							item := list.Items[0]
							item.Report.UpdateTimestamp = report.Report.UpdateTimestamp // TODO A Hack to skip comparing timestamp
							Expect(item.Report).To(Equal(report.Report))
						}

						Expect(stderr).Should(Say(""))
					})
				})

				When("getting vulnerabilities by pod name", func() {
					It("should return the vulnerabilities", func() {
						stdout := NewBuffer()
						stderr := NewBuffer()

						err := cmd.Run(versionInfo, []string{
							"starboard", "get", "vulnerabilities",
							"pod/" + podName,
							"--namespace", testNamespace.Name,
							"--output", "yaml",
							"-v", starboardCLILogLevel,
						}, stdout, stderr)
						Expect(err).ToNot(HaveOccurred())

						var list v1alpha1.VulnerabilityReportList
						err = yaml.Unmarshal(stdout.Contents(), &list)
						Expect(err).ToNot(HaveOccurred())

						if Expect(len(list.Items)).To(Equal(1)) {
							item := list.Items[0]
							item.Report.UpdateTimestamp = report.Report.UpdateTimestamp // TODO A Hack to skip comparing timestamp
							Expect(item.Report).To(Equal(report.Report))
						}

						Expect(stderr).Should(Say(""))
					})
				})

				AfterEach(func() {
					err := kubeClient.Delete(context.TODO(), report)
					Expect(err).ToNot(HaveOccurred())

					err = kubeClient.Delete(context.TODO(), deploy)
					Expect(err).ToNot(HaveOccurred())
				})
			})
		})
	})

	Describe("Command scan configauditreports", func() {
		var object client.Object

		groupByWorkloadName := func(element interface{}) string {
			return element.(v1alpha1.ConfigAuditReport).
				Labels[trivyoperator.LabelResourceName]
		}

		Context("when unmanaged Pod is specified as workload", func() {

			var ctx context.Context

			BeforeEach(func() {
				ctx = context.TODO()

				object = helper.NewPod().
					WithRandomName("nginx-polaris").
					WithNamespace(testNamespace.Name).
					WithContainer("nginx-container", "nginx:1.16").
					Build()
				err := kubeClient.Create(ctx, object)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create ConfigAuditReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "configauditreports", "pod" + "/" + object.GetName(),
					"--namespace", object.GetNamespace(),
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				var reportList v1alpha1.ConfigAuditReportList
				err = kubeClient.List(ctx, &reportList, client.MatchingLabels{
					trivyoperator.LabelResourceKind:      "Pod",
					trivyoperator.LabelResourceName:      object.GetName(),
					trivyoperator.LabelResourceNamespace: object.GetNamespace(),
				})
				Expect(err).ToNot(HaveOccurred())

				Expect(reportList.Items).To(MatchAllElements(groupByWorkloadName, Elements{
					object.GetName(): IsConfigAuditReportOwnedBy(object),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(ctx, object)
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when unmanaged Pod with multiple containers is specified as workload", func() {

			var ctx context.Context

			BeforeEach(func() {
				ctx = context.TODO()
				object = helper.NewPod().
					WithRandomName("nginx-and-tomcat-starboard").
					WithNamespace(testNamespace.Name).
					WithContainer("nginx-container", "nginx:1.16").
					WithContainer("tomcat-container", "tomcat:8").
					Build()
				err := kubeClient.Create(ctx, object)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create ConfigAuditReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "configauditreports", "pod" + "/" + object.GetName(),
					"--namespace", object.GetNamespace(),
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				var reportList v1alpha1.ConfigAuditReportList
				err = kubeClient.List(ctx, &reportList, client.MatchingLabels{
					trivyoperator.LabelResourceKind:      "Pod",
					trivyoperator.LabelResourceName:      object.GetName(),
					trivyoperator.LabelResourceNamespace: object.GetNamespace(),
				})
				Expect(err).ToNot(HaveOccurred())

				Expect(reportList.Items).To(MatchAllElements(groupByWorkloadName, Elements{
					object.GetName(): IsConfigAuditReportOwnedBy(object),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(ctx, object)
				Expect(err).ToNot(HaveOccurred())
			})

		})

		Context("when CronJob is specified as workload", func() {

			var ctx context.Context

			BeforeEach(func() {
				ctx = context.TODO()
				object = &batchv1beta1.CronJob{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "hello" + "-" + rand.String(5),
						Namespace: testNamespace.Name,
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
				err := kubeClient.Create(ctx, object)
				Expect(err).ToNot(HaveOccurred())
			})

			It("should create ConfigAuditReport", func() {
				err := cmd.Run(versionInfo, []string{
					"starboard",
					"scan", "configauditreports", "cronjob" + "/" + object.GetName(),
					"--namespace", object.GetNamespace(),
					"-v", starboardCLILogLevel,
				}, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())

				var reportList v1alpha1.ConfigAuditReportList
				err = kubeClient.List(context.TODO(), &reportList, client.MatchingLabels{
					trivyoperator.LabelResourceKind:      "CronJob",
					trivyoperator.LabelResourceName:      object.GetName(),
					trivyoperator.LabelResourceNamespace: object.GetNamespace(),
				})
				Expect(err).ToNot(HaveOccurred())

				Expect(reportList.Items).To(MatchAllElements(groupByWorkloadName, Elements{
					object.GetName(): IsConfigAuditReportOwnedBy(object),
				}))
			})

			AfterEach(func() {
				err := kubeClient.Delete(ctx, object)
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})

	Describe("Command scan ciskubebenchreports", func() {

		It("should create CISKubeBenchReports", func() {
			err := cmd.Run(versionInfo, []string{
				"starboard",
				"scan", "ciskubebenchreports",
				"-v", starboardCLILogLevel,
			}, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())

			var nodeList corev1.NodeList
			err = kubeClient.List(context.TODO(), &nodeList)
			Expect(err).ToNot(HaveOccurred())

			for _, node := range nodeList.Items {
				var report v1alpha1.CISKubeBenchReport
				err := kubeClient.Get(context.TODO(), types.NamespacedName{Name: node.Name}, &report)
				Expect(err).ToNot(HaveOccurred(), "Expected CISKubeBenchReport for node %s but not found", node.Name)

				// Note: The MatchFieldsMatcher expects struct, not pointer.
				Expect(report).To(MatchFields(IgnoreExtras, Fields{
					"ObjectMeta": MatchFields(IgnoreExtras, Fields{
						"Labels": MatchAllKeys(Keys{
							trivyoperator.LabelResourceKind: Equal("Node"),
							trivyoperator.LabelResourceName: Equal(node.Name),
						}),
						"OwnerReferences": ConsistOf(metav1.OwnerReference{
							APIVersion:         "v1",
							Kind:               "Node",
							Name:               node.Name,
							UID:                node.UID,
							Controller:         pointer.BoolPtr(true),
							BlockOwnerDeletion: pointer.BoolPtr(false),
						}),
					}),
					"Report": MatchFields(IgnoreExtras, Fields{
						"Scanner": Equal(v1alpha1.Scanner{
							Name:    "kube-bench",
							Vendor:  "Aqua Security",
							Version: "v0.6.6",
						}),
					}),
				}))
			}
		})
	})

	Describe("Command get nsa compliance report", func() {

		It("should create nsa compliance report", func() {
			// create ciskubebenchreports
			err := cmd.Run(versionInfo, []string{
				"starboard",
				"scan", "ciskubebenchreports",
				"-v", starboardCLILogLevel,
			}, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())

			// create configauditreports
			ctx := context.TODO()
			object := helper.NewPod().
				WithRandomName("nginx-polaris").
				WithNamespace(testNamespace.Name).
				WithContainer("nginx-container", "nginx:1.16").
				Build()
			err = kubeClient.Create(ctx, object)
			Expect(err).ToNot(HaveOccurred())

			err = cmd.Run(versionInfo, []string{
				"starboard",
				"scan", "configauditreports", "pod" + "/" + object.GetName(),
				"--namespace", object.GetNamespace(),
				"-v", starboardCLILogLevel,
			}, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())

			// get cluster compliance report
			stdout := NewBuffer()
			stderr := NewBuffer()
			err = cmd.Run(versionInfo, []string{
				"starboard", "get", "clustercompliancereports",
				"nsa", "--output", "yaml",
				"-v", starboardCLILogLevel,
			}, stdout, stderr)
			Expect(err).ToNot(HaveOccurred())

			var ccr v1alpha1.ClusterComplianceReport
			err = yaml.Unmarshal(stdout.Contents(), &ccr)
			Expect(err).ToNot(HaveOccurred())
			Expect(ccr.Status.Summary.PassCount > 0).To(BeTrue())
			Expect(ccr.Status.Summary.FailCount > 0).To(BeTrue())
			Expect(len(ccr.Status.ControlChecks) > 0).To(BeTrue())

			// get cluster compliance detail report
			stdout = NewBuffer()
			stderr = NewBuffer()
			err = cmd.Run(versionInfo, []string{
				"starboard", "get", "clustercompliancereports",
				"nsa", "--output", "yaml", "--detail",
				"-v", starboardCLILogLevel,
			}, stdout, stderr)
			Expect(err).ToNot(HaveOccurred())

			var ccdr v1alpha1.ClusterComplianceDetailReport
			err = yaml.Unmarshal(stdout.Contents(), &ccdr)
			Expect(err).ToNot(HaveOccurred())
			Expect(ccdr.Report.Summary.PassCount > 0).To(BeTrue())
			Expect(ccdr.Report.Summary.FailCount > 0).To(BeTrue())
			Expect(len(ccdr.Report.ControlChecks) > 0).To(BeTrue())
		})
	})

	Describe("Command scan kubehunterreports", func() {

		BeforeEach(func() {
			var cm corev1.ConfigMap
			err := kubeClient.Get(context.TODO(), types.NamespacedName{
				Name:      trivyoperator.ConfigMapName,
				Namespace: trivyoperator.NamespaceName,
			}, &cm)
			Expect(err).ToNot(HaveOccurred())

			// Need to use kube-hunter quick scanning mode (subnet 24), otherwise
			// when running the test in Azure (e.g., in a GitHub actions runner)
			// kube-hunter may attempt to scan a large CIDR (subnet 16), which takes a long
			// time and isn't necessary for the purposes of the test.
			cm.Data["kube-hunter.quick"] = "true"
			err = kubeClient.Update(context.TODO(), &cm)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should create KubeHunterReport", func() {
			err := cmd.Run(versionInfo, []string{
				"starboard",
				"scan", "kubehunterreports",
				"-v", starboardCLILogLevel,
			}, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())

			var report v1alpha1.KubeHunterReport
			err = kubeClient.Get(context.TODO(), types.NamespacedName{Name: "cluster"}, &report)
			Expect(err).ToNot(HaveOccurred())
			Expect(report.Labels).To(MatchAllKeys(Keys{
				trivyoperator.LabelResourceKind: Equal("Cluster"),
				trivyoperator.LabelResourceName: Equal("cluster"),
			}))
		})
	})

	AfterEach(func() {
		err := cmd.Run(versionInfo, []string{
			"starboard",
			"uninstall",
			"-v", starboardCLILogLevel,
		}, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())
	})

})
