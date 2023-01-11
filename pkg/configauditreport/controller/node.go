package controller

import (
	j "github.com/aquasecurity/trivy-kubernetes/pkg/jobs"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/infraassessment"
	"github.com/aquasecurity/trivy-operator/pkg/operator/jobs"
	. "github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"

	"context"
	"fmt"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"

	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// NodeInfoCollectorReconciler reconciles corev1.Node and corev1.Job objects
// to collect cluster nodes information (fileSystem permission and process arguments)
// the node information will be evaluated by the complaince control checks per relevant reports, examples: cis-benchmark and nsa
type NodeReconciler struct {
	logr.Logger
	etc.Config
	trivyoperator.ConfigData
	kube.ObjectResolver
	trivyoperator.PluginContext
	configauditreport.PluginInMemory
	jobs.LimitChecker
	InfraReadWriter infraassessment.ReadWriter
	trivyoperator.BuildInfo
}

func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}, builder.WithPredicates(IsLinuxNode)).
		Owns(&v1alpha1.ClusterInfraAssessmentReport{}).
		Complete(r.reconcileNodes())
}

func (r *NodeReconciler) reconcileNodes() reconcile.Func {
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

		log.V(1).Info("Checking whether cluster Infra assessments report exists")
		hasReport, err := r.hasReport(ctx, node)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("checking whether report exists: %w", err)
		}

		if hasReport {
			log.V(1).Info("cluster infra assessments report exists")
			return ctrl.Result{}, nil
		}

		log.V(1).Info("Checking whether Node info collector job have been scheduled")
		_, job, err := r.hasNodeCollectorJob(ctx, node)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("checking whether node collector job has been scheduled: %w", err)
		}
		if job != nil {
			log.V(1).Info("Node info collector job have been scheduled",
				"job", fmt.Sprintf("%s/%s", job.Namespace, job.Name))
			return ctrl.Result{}, nil
		}

		limitExceeded, jobsCount, err := r.LimitChecker.Check(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		log.V(1).Info("Checking node collector jobs limit", "count", jobsCount, "limit", r.ConcurrentScanJobsLimit)

		if limitExceeded {
			log.V(1).Info("Pushing back node collector job", "count", jobsCount, "retryAfter", r.ScanJobRetryAfter)
			return ctrl.Result{RequeueAfter: r.Config.ScanJobRetryAfter}, nil
		}
		cluster, err := k8s.GetCluster()
		if err != nil {
			return ctrl.Result{}, nil
		}
		coll := j.NewCollector(cluster)
		on, err := r.GetOperatorNamespace()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("preparing job: %w", err)
		}
		log.V(1).Info("Scheduling Node collector job")
		_, err = coll.Apply(ctx, j.ContainerName, node.Name, on)
		if err != nil {
			if errors.IsAlreadyExists(err) {
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("creating job: %w", err)
		}
		return ctrl.Result{}, nil
	}
}

func (r *NodeReconciler) hasNodeCollectorJob(ctx context.Context, node *corev1.Node) (bool, *batchv1.Job, error) {
	jobName := r.getNodeCollectorName(node)
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

func (r *NodeReconciler) getNodeCollectorName(node *corev1.Node) string {
	return "node-collector-" + kube.ComputeHash(node.Name)
}

func (r *NodeReconciler) hasReport(ctx context.Context, node *corev1.Node) (bool, error) {
	report, err := r.InfraReadWriter.FindClusterReportByOwner(ctx, kube.ObjectRef{Kind: kube.KindNode, Name: node.Name})
	if err != nil {
		return false, err
	}
	return report != nil, nil
}
