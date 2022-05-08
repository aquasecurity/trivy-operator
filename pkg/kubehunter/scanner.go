package kubehunter

import (
	"context"
	"fmt"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/runner"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/hashicorp/go-version"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/utils/pointer"
)

const (
	kubeHunterContainerName = "kube-hunter"
)

type Config interface {
	GetKubeHunterImageRef() (string, error)
	GetKubeHunterQuick() (bool, error)
}

type Scanner struct {
	scheme     *runtime.Scheme
	clientset  kubernetes.Interface
	opts       kube.ScannerOpts
	logsReader kube.LogsReader
	config     trivyoperator.ConfigData
}

func NewScanner(
	scheme *runtime.Scheme,
	clientset kubernetes.Interface,
	config trivyoperator.ConfigData,
	opts kube.ScannerOpts,
) *Scanner {
	return &Scanner{
		scheme:     scheme,
		clientset:  clientset,
		logsReader: kube.NewLogsReader(clientset),
		config:     config,
		opts:       opts,
	}
}

func (s *Scanner) Scan(ctx context.Context) (v1alpha1.KubeHunterReportData, error) {
	// 1. Prepare descriptor for the Kubernetes Job which will run kube-hunter
	job, err := s.prepareKubeHunterJob()
	if err != nil {
		return v1alpha1.KubeHunterReportData{}, err
	}

	// 2. Run the prepared Job and wait for its completion or failure
	err = runner.New().Run(ctx, kube.NewRunnableJob(s.scheme, s.clientset, job))
	if err != nil {
		return v1alpha1.KubeHunterReportData{}, fmt.Errorf("running kube-hunter job: %w", err)
	}

	defer func() {
		if !s.opts.DeleteScanJob {
			klog.V(3).Infof("Skipping scan job deletion: %s/%s", job.Namespace, job.Name)
			return
		}
		// 5. Delete the kube-hunter Job
		klog.V(3).Infof("Deleting job: %s/%s", job.Namespace, job.Name)
		background := metav1.DeletePropagationBackground
		_ = s.clientset.BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, metav1.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	// 3. Get kube-hunter JSON output from the kube-hunter Pod
	klog.V(3).Infof("Getting logs for %s container in job: %s/%s", kubeHunterContainerName,
		job.Namespace, job.Name)
	logsStream, err := s.logsReader.GetLogsByJobAndContainerName(ctx, job, kubeHunterContainerName)
	if err != nil {
		return v1alpha1.KubeHunterReportData{}, fmt.Errorf("getting logs: %w", err)
	}
	defer func() {
		_ = logsStream.Close()
	}()

	// 4. Parse the KubeHuberOutput from the logs Reader
	return OutputFrom(s.config, logsStream)
}

func (s *Scanner) prepareKubeHunterJob() (*batchv1.Job, error) {
	imageRef, err := s.config.GetKubeHunterImageRef()
	if err != nil {
		return nil, err
	}
	kubeHunterArgs := []string{"--pod", "--report", "json", "--log", "none"}
	// Temporary fix for logging: https://github.com/aquasecurity/kube-hunter/issues/465
	quick, err := s.config.GetKubeHunterQuick()
	if err != nil {
		return nil, err
	}
	if quick {
		kubeHunterArgs = append(kubeHunterArgs, "--quick")
	}

	scanJobTolerations, err := s.config.GetScanJobTolerations()
	if err != nil {
		return nil, err
	}

	scanJobAnnotations, err := s.config.GetScanJobAnnotations()
	if err != nil {
		return nil, err
	}

	scanJobPodTemplateLabels, err := s.config.GetScanJobPodTemplateLabels()
	if err != nil {
		return nil, err
	}

	var (
		podSecurityContext       *corev1.PodSecurityContext
		containerSecurityContext *corev1.SecurityContext
	)
	ver, err := trivyoperator.GetVersionFromImageRef(imageRef)
	if err != nil {
		return nil, err
	}
	if isAtLeast(ver, "0.4.1") || ver == "latest" {
		podSecurityContext = &corev1.PodSecurityContext{
			RunAsUser:  pointer.Int64Ptr(0),
			RunAsGroup: pointer.Int64Ptr(0),
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
		}
		containerSecurityContext = &corev1.SecurityContext{
			Privileged:               pointer.BoolPtr(false),
			AllowPrivilegeEscalation: pointer.BoolPtr(false),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"all"},
				Add:  []corev1.Capability{"NET_RAW"},
			},
			ReadOnlyRootFilesystem: pointer.BoolPtr(false),
		}
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("scan-kubehunterreports-%s", kube.ComputeHash("cluster")),
			Namespace: trivyoperator.NamespaceName,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: kube.GetActiveDeadlineSeconds(s.opts.ScanJobTimeout),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: scanJobAnnotations,
					Labels:      scanJobPodTemplateLabels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: trivyoperator.ServiceAccountName,
					RestartPolicy:      corev1.RestartPolicyNever,
					HostPID:            true,
					Affinity:           trivyoperator.LinuxNodeAffinity(),
					Tolerations:        scanJobTolerations,
					SecurityContext:    podSecurityContext,
					Containers: []corev1.Container{
						{
							Name:                     kubeHunterContainerName,
							Image:                    imageRef,
							ImagePullPolicy:          corev1.PullIfNotPresent,
							TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
							Args:                     kubeHunterArgs,
							SecurityContext:          containerSecurityContext,
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("300m"),
									corev1.ResourceMemory: resource.MustParse("400M"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("100M"),
								},
							},
						},
					},
				},
			},
		},
	}, nil
}

func isAtLeast(ver string, targetVer string) bool {
	v, err := version.NewVersion(ver)
	if err != nil {
		return false
	}
	tv, err := version.NewVersion(targetVer)
	if err != nil {
		return false
	}
	return v.GreaterThanOrEqual(tv)
}
