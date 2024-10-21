package controller

import (
	"context"
	"fmt"
	"io"

	j "github.com/aquasecurity/trivy-kubernetes/pkg/jobs"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/infraassessment"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	. "github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	"github.com/aquasecurity/trivy-operator/pkg/policy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	k8sapierror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// NodeCollectorJobController watches Kubernetes jobs generates
// v1alpha1.ClusterInfraAssessmentReport instances using infra assessment scanner
type NodeCollectorJobController struct {
	logr.Logger
	etc.Config
	kube.ObjectResolver
	kube.LogsReader
	PolicyLoader policy.Loader
	trivyoperator.ConfigData
	trivyoperator.PluginContext
	configauditreport.PluginInMemory
	InfraReadWriter infraassessment.ReadWriter
	trivyoperator.BuildInfo
}

// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;delete

func (r *NodeCollectorJobController) SetupWithManager(mgr ctrl.Manager) error {
	var predicates []predicate.Predicate

	predicates = append(predicates, ManagedByTrivyOperator, IsNodeInfoCollector, JobHasAnyCondition)
	return ctrl.NewControllerManagedBy(mgr).
		For(&batchv1.Job{}, builder.WithPredicates(predicates...)).
		Complete(r.reconcileJobs())
}

func (r *NodeCollectorJobController) reconcileJobs() reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := r.Logger.WithValues("job", req.NamespacedName)

		job := &batchv1.Job{}
		err := r.Client.Get(ctx, req.NamespacedName, job)
		if err != nil {
			if k8sapierror.IsNotFound(err) {
				log.V(1).Info("Ignoring cached job that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting job from cache: %w", err)
		}

		if len(job.Status.Conditions) == 0 {
			log.V(1).Info("Ignoring Job without conditions")
			return ctrl.Result{}, nil
		}

		switch jobCondition := job.Status.Conditions[0].Type; jobCondition {
		case batchv1.JobComplete, batchv1.JobSuccessCriteriaMet:
			err = r.processCompleteScanJob(ctx, job)
		case batchv1.JobFailed:
			err = r.processFailedScanJob(ctx, job)
		default:
			err = fmt.Errorf("unrecognized scan job condition: %v", jobCondition)
		}

		return ctrl.Result{}, err
	}

}

func (r *NodeCollectorJobController) processCompleteScanJob(ctx context.Context, job *batchv1.Job) error {
	log := r.Logger.WithValues("job", fmt.Sprintf("%s/%s", job.Namespace, job.Name))

	nodeRef, err := kube.ObjectRefFromObjectMeta(job.ObjectMeta)
	if err != nil {
		return fmt.Errorf("getting owner ref from scan job metadata: %w", err)
	}

	node := &corev1.Node{}
	err = r.Client.Get(ctx, client.ObjectKey{Name: nodeRef.Name}, node)
	if err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("Ignore processing node info collector job for node that must have been deleted")
			log.V(1).Info("Deleting complete node info collector job")
			return r.deleteJob(ctx, job)
		}
		return fmt.Errorf("getting node from cache: %w", err)
	}

	hasReport, err := hasInfraReport(ctx, node, r.InfraReadWriter)
	if err != nil {
		return err
	}

	if hasReport {
		log.V(1).Info("node info collector already exist")
		log.V(1).Info("Deleting complete scan job")
		return r.deleteJob(ctx, job)
	}

	logsStream, err := r.LogsReader.GetLogsByJobAndContainerName(ctx, job, j.NodeCollectorName)
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
	nodeInfo, err := io.ReadAll(logsStream)
	if err != nil {
		return err
	}
	cac, err := r.NewConfigForConfigAudit(r.PluginContext)
	if err != nil {
		return err
	}
	policies, err := Policies(ctx, r.Config, r.Client, cac, r.Logger, r.PolicyLoader)
	if err != nil {
		return fmt.Errorf("getting policies: %w", err)
	}
	resourceHash, err := kube.ComputeSpecHash(node)
	if err != nil {
		return fmt.Errorf("computing spec hash: %w", err)
	}

	policiesHash, err := policies.Hash(string(kube.KindNode))
	if err != nil {
		return fmt.Errorf("computing policies hash: %w", err)
	}
	resourceLabelsToInclude := r.GetReportResourceLabels()
	additionalCustomLabels, err := r.GetAdditionalReportLabels()
	if err != nil {
		return err
	}
	misConfigData, err := evaluate(ctx, policies, node, r.BuildInfo, r.ConfigData, r.Config, nodeInfo)
	if err != nil {
		return fmt.Errorf("failed to evaluate policies on Node : %w", err)
	}
	infraReportBuilder := infraassessment.NewReportBuilder(r.Client.Scheme()).
		Controller(node).
		ResourceSpecHash(resourceHash).
		PluginConfigHash(policiesHash).
		ResourceLabelsToInclude(resourceLabelsToInclude).
		AdditionalReportLabels(additionalCustomLabels).
		Data(misConfigData.infraAssessmentReportData)
	if r.Config.ScannerReportTTL != nil {
		infraReportBuilder.ReportTTL(r.Config.ScannerReportTTL)
	}
	if err := infraReportBuilder.Write(ctx, r.InfraReadWriter); err != nil {
		return err
	}
	log.V(1).Info("Deleting complete scan job", "owner", job)
	return r.deleteJob(ctx, job)
}

func (r *NodeCollectorJobController) processFailedScanJob(ctx context.Context, scanJob *batchv1.Job) error {
	log := r.Logger.WithValues("job", fmt.Sprintf("%s/%s", scanJob.Namespace, scanJob.Name))

	statuses, err := r.GetTerminatedContainersStatusesByJob(ctx, scanJob)
	if err != nil {
		if k8sapierror.IsNotFound(err) {
			log.V(1).Info("Cached job must have been deleted")
			return nil
		}
		if kube.IsPodControlledByJobNotFound(err) {
			log.V(1).Info("Pod must have been deleted")
			return r.deleteJob(ctx, scanJob)
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
	return r.deleteJob(ctx, scanJob)
}

func (r *NodeCollectorJobController) deleteJob(ctx context.Context, job *batchv1.Job) error {
	err := r.Client.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground))
	if err != nil {
		if k8sapierror.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("deleting job: %w", err)
	}
	return nil
}
