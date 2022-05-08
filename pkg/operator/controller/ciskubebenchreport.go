package controller

import (
	. "github.com/aquasecurity/trivy-operator/pkg/operator/predicate"

	"context"
	"fmt"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/kubebench"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// CISKubeBenchReportReconciler reconciles corev1.Node and corev1.Job objects
// to check cluster nodes configuration with CIS Kubernetes Benchmark and saves
// results as v1alpha1.CISKubeBenchReport objects.
// Each v1alpha1.CISKubeBenchReport is controlled by the corev1.Node for which
// it was generated. Additionally, the CISKubeBenchReportReconciler.SetupWithManager
// method informs the ctrl.Manager that this controller reconciles nodes that
// own benchmark reports, so that it will automatically call the reconcile
// callback on the underlying corev1.Node when a v1alpha1.CISKubeBenchReport
// changes, is deleted, etc.
type CISKubeBenchReportReconciler struct {
	logr.Logger
	etc.Config
	client.Client
	kube.LogsReader
	LimitChecker
	kubebench.ReadWriter
	kubebench.Plugin
	trivyoperator.ConfigData
}

func (r *CISKubeBenchReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}, builder.WithPredicates(IsLinuxNode)).
		Owns(&v1alpha1.CISKubeBenchReport{}).
		Complete(r.reconcileNodes())
	if err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&batchv1.Job{}, builder.WithPredicates(
			InNamespace(r.Config.Namespace),
			ManagedByTrivyOperator,
			IsKubeBenchReportScan,
			JobHasAnyCondition,
		)).
		Complete(r.reconcileJobs())
}

func (r *CISKubeBenchReportReconciler) reconcileNodes() reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := r.Logger.WithValues("node", req.NamespacedName)

		node := &corev1.Node{}

		log.V(1).Info("Getting node from cache")
		err := r.Client.Get(ctx, req.NamespacedName, node)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring cached node that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting node from cache: %w", err)
		}

		log.V(1).Info("Checking whether CIS Kubernetes Benchmark report exists")
		hasReport, err := r.hasReport(ctx, node)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("checking whether report exists: %w", err)
		}

		if hasReport {
			log.V(1).Info("CIS Kubernetes Benchmark report exists")
			return ctrl.Result{}, nil
		}

		log.V(1).Info("Checking whether CIS Kubernetes Benchmark checks have been scheduled")
		_, job, err := r.hasScanJob(ctx, node)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("checking whether scan job has been scheduled: %w", err)
		}
		if job != nil {
			log.V(1).Info("CIS Kubernetes Benchmark have been scheduled",
				"job", fmt.Sprintf("%s/%s", job.Namespace, job.Name))
			return ctrl.Result{}, nil
		}

		limitExceeded, jobsCount, err := r.LimitChecker.Check(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		log.V(1).Info("Checking scan jobs limit", "count", jobsCount, "limit", r.ConcurrentScanJobsLimit)

		if limitExceeded {
			log.V(1).Info("Pushing back scan job", "count", jobsCount, "retryAfter", r.ScanJobRetryAfter)
			return ctrl.Result{RequeueAfter: r.Config.ScanJobRetryAfter}, nil
		}

		job, err = r.newScanJob(node)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("preparing job: %w", err)
		}

		log.V(1).Info("Scheduling CIS Kubernetes Benchmark checks")
		err = r.Client.Create(ctx, job)
		if err != nil {
			if errors.IsAlreadyExists(err) {
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("creating job: %w", err)
		}

		return ctrl.Result{}, nil
	}
}

func (r *CISKubeBenchReportReconciler) hasReport(ctx context.Context, node *corev1.Node) (bool, error) {
	report, err := r.ReadWriter.FindByOwner(ctx, kube.ObjectRef{Kind: kube.KindNode, Name: node.Name})
	if err != nil {
		return false, err
	}
	return report != nil, nil
}

func (r *CISKubeBenchReportReconciler) hasScanJob(ctx context.Context, node *corev1.Node) (bool, *batchv1.Job, error) {
	jobName := r.getScanJobName(node)
	job := &batchv1.Job{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: r.Config.Namespace, Name: jobName}, job)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("getting job from cache: %w", err)
	}
	return true, job, nil
}

func (r *CISKubeBenchReportReconciler) newScanJob(node *corev1.Node) (*batchv1.Job, error) {
	templateSpec, err := r.Plugin.GetScanJobSpec(*node)
	if err != nil {
		return nil, err
	}

	templateSpec.ServiceAccountName = r.Config.ServiceAccount

	scanJobTolerations, err := r.ConfigData.GetScanJobTolerations()
	if err != nil {
		return nil, err
	}
	templateSpec.Tolerations = append(templateSpec.Tolerations, scanJobTolerations...)

	scanJobAnnotations, err := r.ConfigData.GetScanJobAnnotations()
	if err != nil {
		return nil, err
	}

	scanJobPodTemplateLabels, err := r.ConfigData.GetScanJobPodTemplateLabels()
	if err != nil {
		return nil, err
	}

	labelsSet := labels.Set{
		trivyoperator.LabelResourceKind:           string(kube.KindNode),
		trivyoperator.LabelResourceName:           node.Name,
		trivyoperator.LabelK8SAppManagedBy:        trivyoperator.AppTrivyOperator,
		trivyoperator.LabelKubeBenchReportScanner: "true",
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
			Name:      r.getScanJobName(node),
			Namespace: r.Config.Namespace,
			Labels:    labelsSet,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: kube.GetActiveDeadlineSeconds(r.Config.ScanJobTimeout),
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

func (r *CISKubeBenchReportReconciler) getScanJobName(node *corev1.Node) string {
	return "scan-cisbenchmark-" + kube.ComputeHash(node.Name)
}

func (r *CISKubeBenchReportReconciler) reconcileJobs() reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := r.Logger.WithValues("job", req.NamespacedName)

		job := &batchv1.Job{}
		log.V(1).Info("Getting job from cache")
		err := r.Client.Get(ctx, req.NamespacedName, job)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring cached job that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting job from cache: %w", err)
		}

		if len(job.Status.Conditions) == 0 {
			log.V(1).Info("Ignoring job without conditions")
			return ctrl.Result{}, nil
		}

		switch jobCondition := job.Status.Conditions[0].Type; jobCondition {
		case batchv1.JobComplete:
			err = r.processCompleteScanJob(ctx, job)
		case batchv1.JobFailed:
			err = r.processFailedScanJob(ctx, job)
		default:
			err = fmt.Errorf("unrecognized job condition: %v", jobCondition)
		}

		return ctrl.Result{}, err
	}
}

func (r *CISKubeBenchReportReconciler) processCompleteScanJob(ctx context.Context, job *batchv1.Job) error {
	log := r.Logger.WithValues("job", fmt.Sprintf("%s/%s", job.Namespace, job.Name))

	nodeRef, err := kube.ObjectRefFromObjectMeta(job.ObjectMeta)
	if err != nil {
		return fmt.Errorf("getting owner ref from scan job metadata: %w", err)
	}

	node := &corev1.Node{}
	err = r.Client.Get(ctx, client.ObjectKey{Name: nodeRef.Name}, node)
	if err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("Ignore processing scan job for node that must have been deleted")
			log.V(1).Info("Deleting complete scan job")
			return r.deleteJob(ctx, job)
		}
		return fmt.Errorf("getting node from cache: %w", err)
	}

	log.V(1).Info("Checking whether CIS Kubernetes Benchmark report exists")
	hasReport, err := r.hasReport(ctx, node)
	if err != nil {
		return fmt.Errorf("checking whether report exists: %w", err)
	}

	if hasReport {
		log.V(1).Info("CISKubeBenchReport already exist")
		log.V(1).Info("Deleting complete scan job")
		return r.deleteJob(ctx, job)
	}

	logsStream, err := r.LogsReader.GetLogsByJobAndContainerName(ctx, job, r.Plugin.GetContainerName())
	if err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("Cached job must have been deleted")
			return nil
		}
		if kube.IsPodControlledByJobNotFound(err) {
			log.V(1).Info("Pod must have been deleted")
			return r.deleteJob(ctx, job)
		}
		return fmt.Errorf("getting logs: %w", err)
	}

	output, err := r.Plugin.ParseCISKubeBenchReportData(logsStream)
	defer func() {
		_ = logsStream.Close()
	}()

	report, err := kubebench.NewBuilder(r.Client.Scheme()).
		Controller(node).
		Data(output).
		Get()
	if err != nil {
		return fmt.Errorf("building report: %w", err)
	}

	log.V(1).Info("Writing CIS Kubernetes Benchmark report", "reportName", report.Name)
	err = r.ReadWriter.Write(ctx, report)
	if err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	log.V(1).Info("Deleting complete scan job")
	return r.deleteJob(ctx, job)
}

func (r *CISKubeBenchReportReconciler) deleteJob(ctx context.Context, job *batchv1.Job) error {
	err := r.Client.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground))
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("deleting job: %w", err)
	}
	return nil
}

func (r *CISKubeBenchReportReconciler) processFailedScanJob(ctx context.Context, job *batchv1.Job) error {
	log := r.Logger.WithValues("job", fmt.Sprintf("%s/%s", job.Namespace, job.Name))

	statuses, err := r.LogsReader.GetTerminatedContainersStatusesByJob(ctx, job)
	if err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("Cached job must have been deleted")
			return nil
		}
		if kube.IsPodControlledByJobNotFound(err) {
			log.V(1).Info("Pod must have been deleted")
			return r.deleteJob(ctx, job)
		}
		return err
	}
	for container, status := range statuses {
		if status.ExitCode == 0 {
			continue
		}
		log.Error(nil, "Scan job container", "container", container, "status.reason", status.Reason, "status.message", status.Message)
	}
	log.V(1).Info("Deleting failed scan job")
	return r.deleteJob(ctx, job)
}
