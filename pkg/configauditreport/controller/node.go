package controller

import (
	"time"

	j "github.com/aquasecurity/trivy-kubernetes/pkg/jobs"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/infraassessment"
	"github.com/aquasecurity/trivy-operator/pkg/operator/jobs"
	"github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	. "github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	"github.com/aquasecurity/trivy-operator/pkg/plugins/trivy"
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
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

//	NodeReconciler reconciles corev1.Node and corev1.Job objects
//
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
	InfraReadWriter  infraassessment.ReadWriter
	CacheSyncTimeout time.Duration
	trivyoperator.BuildInfo
}

// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=clusterinfraassessmentreports,verbs=get;list;watch;create;update;patch;delete

func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	excludeNodePredicate, err := predicate.ExcludeNode(r.ConfigData)
	if err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).WithOptions(controller.Options{
		CacheSyncTimeout: r.CacheSyncTimeout,
	}).
		For(&corev1.Node{}, builder.WithPredicates(IsLinuxNode, predicate.Not((excludeNodePredicate)))).
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
		hasReport, err := hasInfraReport(ctx, node, r.InfraReadWriter)
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

		limitExceeded, jobsCount, err := r.LimitChecker.CheckNodes(ctx)
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
		on, err := r.GetOperatorNamespace()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("preparing job: %w", err)
		}
		jobTolerations, err := r.GetScanJobTolerations()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting job tolerations: %w", err)
		}
		nodeCollectorVolumes, err := r.GetNodeCollectorVolumes()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting node-collector volumes: %w", err)
		}
		nodeCollectorVolumeMounts, err := r.GetGetNodeCollectorVolumeMounts()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting node-collector volumes mount: %w", err)
		}
		scanJobSecurityContext, err := r.GetScanJobPodSecurityContext()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting scan job podSecurityContext: %w", err)
		}
		scanJobContainerSecurityContext, err := r.GetScanJobContainerSecurityContext()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting scan job [container] securityContext: %w", err)
		}
		scanJobAnnotations, err := r.GetScanJobAnnotations()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting scan job annotations: %w", err)
		}
		pConfig, err := r.PluginContext.GetConfig()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting getting config: %w", err)
		}
		tc := trivy.Config{PluginConfig: pConfig}

		requirements, err := tc.GetResourceRequirements()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting node-collector resource requierments: %w", err)
		}

		scanJobPodPriorityClassName, err := r.GetScanJobPodPriorityClassName()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting scan job priority class name: %w", err)
		}
		nodeCollectorImageRef := r.GetTrivyOperatorConfig().NodeCollectorImageRef()
		coll := j.NewCollector(cluster,
			j.WithJobTemplateName(j.NodeCollectorName),
			j.WithName(r.getNodeCollectorName(node)),
			j.WithJobNamespace(on),
			j.WithServiceAccount(r.ServiceAccount),
			j.WithCollectorTimeout(r.Config.ScanJobTimeout),
			j.WithJobTolerations(jobTolerations),
			j.WithPodSpecSecurityContext(scanJobSecurityContext),
			j.WithContainerSecurityContext(scanJobContainerSecurityContext),
			j.WithPodImagePullSecrets(r.GetNodeCollectorImagePullsecret()),
			j.WithJobAnnotation(scanJobAnnotations),
			j.WithImageRef(nodeCollectorImageRef),
			j.WithVolumes(nodeCollectorVolumes),
			j.WithPodPriorityClassName(scanJobPodPriorityClassName),
			j.WithVolumesMount(nodeCollectorVolumeMounts),
			j.WithContainerResourceRequirements(&requirements),
			j.WithJobLabels(map[string]string{
				trivyoperator.LabelNodeInfoCollector: "Trivy",
				trivyoperator.LabelK8SAppManagedBy:   trivyoperator.AppTrivyOperator,
				trivyoperator.LabelResourceKind:      node.Kind,
				trivyoperator.LabelResourceName:      node.Name,
			}))

		log.V(1).Info("Scheduling Node collector job")
		_, err = coll.Apply(ctx, node.Name)
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
