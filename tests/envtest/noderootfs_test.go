package operator_test

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/nodevulnerabilityreport"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

var _ = Describe("Node rootfs scan controller", func() {

	const (
		timeout  = time.Second * 30
		interval = time.Millisecond * 250
	)

	Context("When a Linux node exists", func() {
		var testNode *corev1.Node

		BeforeEach(func() {
			testNode = &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("test-worker-node-%d", time.Now().UnixNano()),
					Labels: map[string]string{
						"kubernetes.io/os": "linux",
					},
				},
				Spec: corev1.NodeSpec{},
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{
						{
							Type:   corev1.NodeReady,
							Status: corev1.ConditionTrue,
						},
					},
				},
			}
		})

		AfterEach(func() {
			// Cleanup node
			_ = k8sClient.Delete(ctx, testNode)

			// Cleanup any scan jobs for this node
			jobList := &batchv1.JobList{}
			_ = k8sClient.List(ctx, jobList, client.MatchingLabels{
				trivyoperator.LabelNodeScanning: "Trivy",
				trivyoperator.LabelResourceName: testNode.Name,
			})
			for _, job := range jobList.Items {
				_ = k8sClient.Delete(ctx, &job, client.PropagationPolicy(metav1.DeletePropagationBackground))
			}

			// Cleanup any reports for this node
			reportList := &v1alpha1.NodeVulnerabilityReportList{}
			_ = k8sClient.List(ctx, reportList, client.MatchingLabels{
				trivyoperator.LabelResourceName: testNode.Name,
			})
			for _, report := range reportList.Items {
				_ = k8sClient.Delete(ctx, &report)
			}
		})

		It("Should create a scan job for the node", func() {
			// Create the node
			Expect(k8sClient.Create(ctx, testNode)).Should(Succeed())

			// Expected job name
			expectedJobName := nodevulnerabilityreport.GetNodeScanningJobName(testNode.Name)

			// Wait for scan job to be created
			createdJob := &batchv1.Job{}
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{
					Namespace: "default",
					Name:      expectedJobName,
				}, createdJob)
			}, timeout, interval).Should(Succeed())

			// Verify job labels
			Expect(createdJob.Labels).To(HaveKeyWithValue(trivyoperator.LabelK8SAppManagedBy, trivyoperator.AppTrivyOperator))
			Expect(createdJob.Labels).To(HaveKeyWithValue(trivyoperator.LabelNodeScanning, "Trivy"))
			Expect(createdJob.Labels).To(HaveKeyWithValue(trivyoperator.LabelResourceKind, "Node"))
			Expect(createdJob.Labels).To(HaveKeyWithValue(trivyoperator.LabelResourceName, testNode.Name))
			Expect(createdJob.Labels).To(HaveKey(trivyoperator.LabelResourceSpecHash))

			// Verify pod spec
			podSpec := createdJob.Spec.Template.Spec
			Expect(podSpec.NodeName).To(Equal(testNode.Name))

			// Verify hostfs volume
			var hasHostfsVolume bool
			for _, vol := range podSpec.Volumes {
				if vol.Name == "hostfs" && vol.HostPath != nil && vol.HostPath.Path == "/" {
					hasHostfsVolume = true
					break
				}
			}
			Expect(hasHostfsVolume).To(BeTrue(), "Job should have hostfs volume mounted")

			// Verify main container
			Expect(podSpec.Containers).To(HaveLen(1))
			mainContainer := podSpec.Containers[0]
			Expect(mainContainer.Name).To(Equal("node-rootfs-scanner"))
			Expect(mainContainer.Command).To(Equal([]string{"trivy"}))

			// Verify args include rootfs command
			Expect(mainContainer.Args).To(ContainElement("rootfs"))
			Expect(mainContainer.Args).To(ContainElement("/hostfs"))
		})
	})

	Context("When NodeVulnerabilityReport already exists with matching hash", func() {
		var testNode *corev1.Node
		var existingReport *v1alpha1.NodeVulnerabilityReport
		var nodeHash string

		BeforeEach(func() {
			testNode = &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("test-worker-existing-%d", time.Now().UnixNano()),
					Labels: map[string]string{
						"kubernetes.io/os": "linux",
					},
				},
			}
		})

		AfterEach(func() {
			_ = k8sClient.Delete(ctx, testNode)
			if existingReport != nil {
				_ = k8sClient.Delete(ctx, existingReport)
			}
		})

		It("Should not create a new scan job when report hash matches", func() {
			// Create node first to get its hash
			Expect(k8sClient.Create(ctx, testNode)).Should(Succeed())

			// Compute hash the same way controller does
			nodeHash = nodevulnerabilityreport.ComputeNodeHash(testNode)

			// Create report with matching hash
			existingReport = &v1alpha1.NodeVulnerabilityReport{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodevulnerabilityreport.GetNodeVulnerabilityReportName(testNode.Name),
					Labels: map[string]string{
						trivyoperator.LabelResourceKind:     "Node",
						trivyoperator.LabelResourceName:     testNode.Name,
						trivyoperator.LabelK8SAppManagedBy:  trivyoperator.AppTrivyOperator,
						trivyoperator.LabelNodeScanning:     "Trivy",
						trivyoperator.LabelResourceSpecHash: nodeHash,
					},
				},
				Report: v1alpha1.NodeVulnerabilityReportData{
					UpdateTimestamp: metav1.Now(),
					Scanner: v1alpha1.Scanner{
						Name:    "Trivy",
						Vendor:  "Aqua Security",
						Version: "0.67.2",
					},
					Artifact: v1alpha1.NodeArtifact{
						NodeName: testNode.Name,
						Kind:     "node-rootfs",
						RootPath: "/hostfs",
					},
					Summary: v1alpha1.VulnerabilitySummary{
						CriticalCount: 0,
						HighCount:     0,
						MediumCount:   0,
						LowCount:      0,
						UnknownCount:  0,
					},
					Vulnerabilities: []v1alpha1.Vulnerability{},
				},
			}
			Expect(k8sClient.Create(ctx, existingReport)).Should(Succeed())

			// Wait a bit and verify no job is created
			expectedJobName := nodevulnerabilityreport.GetNodeScanningJobName(testNode.Name)
			createdJob := &batchv1.Job{}

			Consistently(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{
					Namespace: "default",
					Name:      expectedJobName,
				}, createdJob)
			}, time.Second*5, interval).ShouldNot(Succeed())
		})
	})

	Context("Manual rescan via annotation", func() {
		var testNode *corev1.Node
		var existingReport *v1alpha1.NodeVulnerabilityReport

		BeforeEach(func() {
			testNode = &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("test-worker-rescan-%d", time.Now().UnixNano()),
					Labels: map[string]string{
						"kubernetes.io/os": "linux",
					},
					Annotations: map[string]string{
						trivyoperator.AnnotationNodeScanningToken: "initial",
					},
				},
			}
		})

		AfterEach(func() {
			_ = k8sClient.Delete(ctx, testNode)
			if existingReport != nil {
				_ = k8sClient.Delete(ctx, existingReport)
			}

			// Cleanup any scan jobs
			jobList := &batchv1.JobList{}
			_ = k8sClient.List(ctx, jobList, client.MatchingLabels{
				trivyoperator.LabelResourceName: testNode.Name,
			})
			for _, job := range jobList.Items {
				_ = k8sClient.Delete(ctx, &job, client.PropagationPolicy(metav1.DeletePropagationBackground))
			}
		})

		It("Should trigger rescan when annotation changes", func() {
			// Create node
			Expect(k8sClient.Create(ctx, testNode)).Should(Succeed())

			// Create existing report with old hash (based on "initial" annotation)
			existingReport = &v1alpha1.NodeVulnerabilityReport{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodevulnerabilityreport.GetNodeVulnerabilityReportName(testNode.Name),
					Labels: map[string]string{
						trivyoperator.LabelResourceKind:     "Node",
						trivyoperator.LabelResourceName:     testNode.Name,
						trivyoperator.LabelResourceSpecHash: "old-hash-that-wont-match",
					},
				},
				Report: v1alpha1.NodeVulnerabilityReportData{
					Artifact: v1alpha1.NodeArtifact{
						NodeName: testNode.Name,
					},
				},
			}
			Expect(k8sClient.Create(ctx, existingReport)).Should(Succeed())

			// Wait for initial job to be created (hash mismatch should trigger this)
			expectedJobName := nodevulnerabilityreport.GetNodeScanningJobName(testNode.Name)
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{
					Namespace: "default",
					Name:      expectedJobName,
				}, &batchv1.Job{})
			}, timeout, interval).Should(Succeed())

			// Verify the old report was deleted
			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{Name: existingReport.Name}, &v1alpha1.NodeVulnerabilityReport{})
			}, timeout, interval).ShouldNot(Succeed())
		})
	})

	Context("Node selector filtering", func() {
		var workerNode *corev1.Node
		var masterNode *corev1.Node

		BeforeEach(func() {
			workerNode = &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("test-worker-%d", time.Now().UnixNano()),
					Labels: map[string]string{
						"kubernetes.io/os":               "linux",
						"node-role.kubernetes.io/worker": "",
					},
				},
			}
			masterNode = &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("test-master-%d", time.Now().UnixNano()),
					Labels: map[string]string{
						"kubernetes.io/os":                      "linux",
						"node-role.kubernetes.io/control-plane": "",
					},
				},
			}
		})

		AfterEach(func() {
			_ = k8sClient.Delete(ctx, workerNode)
			_ = k8sClient.Delete(ctx, masterNode)

			// Cleanup jobs
			for _, nodeName := range []string{workerNode.Name, masterNode.Name} {
				jobList := &batchv1.JobList{}
				_ = k8sClient.List(ctx, jobList, client.MatchingLabels{
					trivyoperator.LabelResourceName: nodeName,
				})
				for _, job := range jobList.Items {
					_ = k8sClient.Delete(ctx, &job, client.PropagationPolicy(metav1.DeletePropagationBackground))
				}
			}
		})

		It("Should create scan jobs for all Linux nodes when no selector is configured", func() {
			// Create both nodes
			Expect(k8sClient.Create(ctx, workerNode)).Should(Succeed())
			Expect(k8sClient.Create(ctx, masterNode)).Should(Succeed())

			// Both should get scan jobs
			workerJobName := nodevulnerabilityreport.GetNodeScanningJobName(workerNode.Name)
			masterJobName := nodevulnerabilityreport.GetNodeScanningJobName(masterNode.Name)

			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: workerJobName}, &batchv1.Job{})
			}, timeout, interval).Should(Succeed())

			Eventually(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: masterJobName}, &batchv1.Job{})
			}, timeout, interval).Should(Succeed())
		})
	})

	Context("Windows node handling", func() {
		var windowsNode *corev1.Node

		BeforeEach(func() {
			windowsNode = &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("test-windows-%d", time.Now().UnixNano()),
					Labels: map[string]string{
						"kubernetes.io/os": "windows",
					},
				},
			}
		})

		AfterEach(func() {
			_ = k8sClient.Delete(ctx, windowsNode)
		})

		It("Should not create scan job for Windows nodes", func() {
			Expect(k8sClient.Create(ctx, windowsNode)).Should(Succeed())

			expectedJobName := nodevulnerabilityreport.GetNodeScanningJobName(windowsNode.Name)
			createdJob := &batchv1.Job{}

			// Windows nodes should be ignored
			Consistently(func() error {
				return k8sClient.Get(ctx, client.ObjectKey{
					Namespace: "default",
					Name:      expectedJobName,
				}, createdJob)
			}, time.Second*5, interval).ShouldNot(Succeed())
		})
	})
})
