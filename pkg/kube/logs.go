package kube

import (
	"context"
	"errors"
	"fmt"
	"io"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var podControlledByJobNotFoundErr = errors.New("pod for job not found")

type LogsReader interface {
	GetLogsByJobAndContainerName(ctx context.Context, job *batchv1.Job, containerName string) (io.ReadCloser, error)
	GetTerminatedContainersStatusesByJob(ctx context.Context, job *batchv1.Job) (map[string]*corev1.ContainerStateTerminated, error)
}

// +kubebuilder:rbac:groups="",resources=pods/log,verbs=get;list

type logsReader struct {
	clientset kubernetes.Interface
}

func NewLogsReader(clientset kubernetes.Interface) LogsReader {
	return &logsReader{
		clientset: clientset,
	}
}

func (r *logsReader) GetLogsByJobAndContainerName(ctx context.Context, job *batchv1.Job, containerName string) (io.ReadCloser, error) {
	pod, err := r.getPodByJob(ctx, job)
	if err != nil {
		return nil, fmt.Errorf("getting pod controlled by job: %q: %w", job.Namespace+"/"+job.Name, err)
	}
	if pod == nil {
		return nil, fmt.Errorf("getting pod controlled by job: %q: %w", job.Namespace+"/"+job.Name, podControlledByJobNotFoundErr)
	}

	return r.clientset.CoreV1().Pods(pod.Namespace).
		GetLogs(pod.Name, &corev1.PodLogOptions{
			Follow:    true,
			Container: containerName,
		}).Stream(ctx)
}

func (r *logsReader) GetTerminatedContainersStatusesByJob(ctx context.Context, job *batchv1.Job) (map[string]*corev1.ContainerStateTerminated, error) {
	pod, err := r.getPodByJob(ctx, job)
	if err != nil {
		return nil, err
	}
	statuses := GetTerminatedContainersStatusesByPod(pod)
	return statuses, nil
}

func (r *logsReader) getPodByJob(ctx context.Context, job *batchv1.Job) (*corev1.Pod, error) {
	refreshedJob, err := r.clientset.BatchV1().Jobs(job.Namespace).Get(ctx, job.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	podList, err := r.podListLookup(ctx, job.Namespace, refreshedJob)
	if err != nil {
		return nil, err
	}
	if podList != nil && len(podList.Items) > 0 {
		return &podList.Items[0], nil
	}
	return nil, nil
}

func (r *logsReader) podListLookup(ctx context.Context, namespace string, refreshedJob *batchv1.Job) (*corev1.PodList, error) {
	matchingLabelKey := "controller-uid"
	matchingLabelValue := refreshedJob.Spec.Selector.MatchLabels[matchingLabelKey]
	if len(matchingLabelValue) == 0 {
		matchingLabelKey = "batch.kubernetes.io/controller-uid" // for k8s v1.27.x and above
		matchingLabelValue = refreshedJob.Spec.Selector.MatchLabels[matchingLabelKey]
	}
	selector := fmt.Sprintf("%s=%s", matchingLabelKey, matchingLabelValue)
	return r.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector})
}

func GetTerminatedContainersStatusesByPod(pod *corev1.Pod) map[string]*corev1.ContainerStateTerminated {
	states := make(map[string]*corev1.ContainerStateTerminated)
	if pod == nil {
		return states
	}
	for _, status := range pod.Status.InitContainerStatuses {
		if status.State.Terminated == nil {
			continue
		}
		states[status.Name] = status.State.Terminated
	}
	for _, status := range pod.Status.ContainerStatuses {
		if status.State.Terminated == nil {
			continue
		}
		states[status.Name] = status.State.Terminated
	}
	return states
}

func IsPodControlledByJobNotFound(err error) bool {
	return errors.Is(err, podControlledByJobNotFoundErr)
}
