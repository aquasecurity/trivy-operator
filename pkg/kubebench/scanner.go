package kubebench

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/runner"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/utils/pointer"
)

type Scanner struct {
	scheme     *runtime.Scheme
	clientset  kubernetes.Interface
	logsReader kube.LogsReader
	plugin Plugin
	config trivyoperator.ConfigData
	opts   kube.ScannerOpts
}

func NewScanner(
	scheme *runtime.Scheme,
	clientset kubernetes.Interface,
	plugin Plugin,
	config trivyoperator.ConfigData,
	opts kube.ScannerOpts,
) *Scanner {
	return &Scanner{
		scheme:     scheme,
		clientset:  clientset,
		logsReader: kube.NewLogsReader(clientset),
		plugin:     plugin,
		config:     config,
		opts:       opts,
	}
}

func (s *Scanner) Scan(ctx context.Context, node corev1.Node) (v1alpha1.CISKubeBenchReport, error) {
	// 1. Prepare descriptor for the Kubernetes Job which will run kube-bench
	job, err := s.prepareKubeBenchJob(node)
	if err != nil {
		return v1alpha1.CISKubeBenchReport{}, err
	}

	// 2. Run the prepared Job and wait for its completion or failure
	err = runner.New().Run(ctx, kube.NewRunnableJob(s.scheme, s.clientset, job))
	if err != nil {
		return v1alpha1.CISKubeBenchReport{}, fmt.Errorf("running kube-bench job: %w", err)
	}

	defer func() {
		if !s.opts.DeleteScanJob {
			klog.V(3).Infof("Skipping scan job deletion: %s/%s", job.Namespace, job.Name)
			return
		}
		// 5. Delete the kube-bench Job
		klog.V(3).Infof("Deleting job %q", job.Namespace+"/"+job.Name)
		background := metav1.DeletePropagationBackground
		_ = s.clientset.BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, metav1.DeleteOptions{
			PropagationPolicy: &background,
		})
	}()

	containerName := s.plugin.GetContainerName()
	// 3. Get kube-bench JSON output from the kube-bench Pod
	klog.V(3).Infof("Getting logs for %q container in job %q", containerName,
		job.Namespace+"/"+job.Name)
	logsStream, err := s.logsReader.GetLogsByJobAndContainerName(ctx, job, containerName)
	if err != nil {
		return v1alpha1.CISKubeBenchReport{}, fmt.Errorf("getting logs: %w", err)
	}
	defer func() {
		_ = logsStream.Close()
	}()

	// 4. Parse the CISBenchmarkReport from the logs Reader
	output, err := s.plugin.ParseCISKubeBenchReportData(logsStream)
	if err != nil {
		return v1alpha1.CISKubeBenchReport{}, err
	}

	report, err := NewBuilder(s.scheme).
		Controller(&node).
		Data(output).
		Get()
	if err != nil {
		return v1alpha1.CISKubeBenchReport{}, fmt.Errorf("building report: %w", err)
	}

	return report, nil
}

func (s *Scanner) prepareKubeBenchJob(node corev1.Node) (*batchv1.Job, error) {
	templateSpec, err := s.plugin.GetScanJobSpec(node)
	if err != nil {
		return nil, err
	}

	scanJobTolerations, err := s.config.GetScanJobTolerations()
	if err != nil {
		return nil, err
	}
	templateSpec.Tolerations = append(templateSpec.Tolerations, scanJobTolerations...)

	scanJobAnnotations, err := s.config.GetScanJobAnnotations()
	if err != nil {
		return nil, err
	}

	scanJobPodTemplateLabels, err := s.config.GetScanJobPodTemplateLabels()
	if err != nil {
		return nil, err
	}

	labelsSet := labels.Set{
		trivyoperator.LabelResourceKind: string(kube.KindNode),
		trivyoperator.LabelResourceName: node.Name,
	}

	podTemplateLabelsSet := make(labels.Set)
	for index, element := range labelsSet {
		podTemplateLabelsSet[index] = element
	}
	for index, element := range scanJobPodTemplateLabels {
		podTemplateLabelsSet[index] = element
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "scan-cisbenchmark-" + kube.ComputeHash(node.Name),
			Namespace: trivyoperator.NamespaceName,
			Labels:    labelsSet,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: kube.GetActiveDeadlineSeconds(s.opts.ScanJobTimeout),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      podTemplateLabelsSet,
					Annotations: scanJobAnnotations,
				},
				Spec: templateSpec,
			},
		},
	}, nil
}

const (
	kubeBenchContainerName = "kube-bench"
)

type Config interface {
	GetKubeBenchImageRef() (string, error)
}

type kubeBenchPlugin struct {
	clock  ext.Clock
	config Config
}

// NewKubeBenchPlugin constructs a new Plugin, which is using an official
// Kube-Bench container image, with the specified Config.
func NewKubeBenchPlugin(clock ext.Clock, config Config) Plugin {
	return &kubeBenchPlugin{
		clock:  clock,
		config: config,
	}
}

func (k *kubeBenchPlugin) GetScanJobSpec(node corev1.Node) (corev1.PodSpec, error) {
	imageRef, err := k.config.GetKubeBenchImageRef()
	if err != nil {
		return corev1.PodSpec{}, err
	}
	return corev1.PodSpec{
		ServiceAccountName:           trivyoperator.ServiceAccountName,
		AutomountServiceAccountToken: pointer.BoolPtr(true),
		RestartPolicy:                corev1.RestartPolicyNever,
		HostPID:                      true,
		NodeName:                     node.Name,
		SecurityContext: &corev1.PodSecurityContext{
			RunAsUser:  pointer.Int64Ptr(0),
			RunAsGroup: pointer.Int64Ptr(0),
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
		},
		Volumes: []corev1.Volume{
			{
				Name: "var-lib-etcd",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/lib/etcd",
					},
				},
			},
			{
				Name: "var-lib-kubelet",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/lib/kubelet",
					},
				},
			},
			{
				Name: "etc-systemd",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/etc/systemd",
					},
				},
			},
			{
				Name: "etc-kubernetes",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/etc/kubernetes",
					},
				},
			},
			{
				Name: "usr-bin",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/usr/bin",
					},
				},
			},
		},
		Containers: []corev1.Container{
			{
				Name:                     kubeBenchContainerName,
				Image:                    imageRef,
				ImagePullPolicy:          corev1.PullIfNotPresent,
				TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
				Command:                  []string{"sh"},
				Args:                     []string{"-c", "kube-bench --json 2> /dev/null"},
				SecurityContext: &corev1.SecurityContext{
					Privileged:               pointer.BoolPtr(false),
					AllowPrivilegeEscalation: pointer.BoolPtr(false),
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"all"},
					},
					ReadOnlyRootFilesystem: pointer.BoolPtr(true),
				},
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("300m"),
						corev1.ResourceMemory: resource.MustParse("300M"),
					},
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("50m"),
						corev1.ResourceMemory: resource.MustParse("50M"),
					},
				},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "var-lib-etcd",
						MountPath: "/var/lib/etcd",
						ReadOnly:  true,
					},
					{
						Name:      "var-lib-kubelet",
						MountPath: "/var/lib/kubelet",
						ReadOnly:  true,
					},
					{
						Name:      "etc-systemd",
						MountPath: "/etc/systemd",
						ReadOnly:  true,
					},
					{
						Name:      "etc-kubernetes",
						MountPath: "/etc/kubernetes",
						ReadOnly:  true,
					},
					{
						Name:      "usr-bin",
						MountPath: "/usr/local/mount-from-host/bin",
						ReadOnly:  true,
					},
				},
			},
		},
	}, nil
}

func (k *kubeBenchPlugin) ParseCISKubeBenchReportData(logsStream io.ReadCloser) (v1alpha1.CISKubeBenchReportData, error) {
	output := &struct {
		Controls []v1alpha1.CISKubeBenchSection `json:"Controls"`
	}{}

	decoder := json.NewDecoder(logsStream)
	err := decoder.Decode(output)
	if err != nil {
		return v1alpha1.CISKubeBenchReportData{}, err
	}

	imageRef, err := k.config.GetKubeBenchImageRef()
	if err != nil {
		return v1alpha1.CISKubeBenchReportData{}, err
	}
	version, err := trivyoperator.GetVersionFromImageRef(imageRef)
	if err != nil {
		return v1alpha1.CISKubeBenchReportData{}, err
	}

	return v1alpha1.CISKubeBenchReportData{
		Scanner: v1alpha1.Scanner{
			Name:    "kube-bench",
			Vendor:  "Aqua Security",
			Version: version,
		},
		Summary:         k.summary(output.Controls),
		UpdateTimestamp: metav1.NewTime(k.clock.Now()),
		Sections:        output.Controls,
	}, nil
}

func (k *kubeBenchPlugin) summary(sections []v1alpha1.CISKubeBenchSection) v1alpha1.CISKubeBenchSummary {
	totalPass := 0
	totalInfo := 0
	totalWarn := 0
	totalFail := 0

	for _, section := range sections {
		totalPass += section.TotalPass
		totalInfo += section.TotalInfo
		totalWarn += section.TotalWarn
		totalFail += section.TotalFail
	}

	return v1alpha1.CISKubeBenchSummary{
		PassCount: totalPass,
		InfoCount: totalInfo,
		WarnCount: totalWarn,
		FailCount: totalFail,
	}
}

func (k *kubeBenchPlugin) GetContainerName() string {
	return kubeBenchContainerName
}
