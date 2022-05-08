package configauditreport

import (
	"context"
	"fmt"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	"github.com/aquasecurity/trivy-operator/pkg/policy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// ResourceController watches all Kubernetes kinds and generates
// v1alpha1.ConfigAuditReport instances based on OPA Rego policies as fast as
// possible.
type ResourceController struct {
	logr.Logger
	etc.Config
	trivyoperator.ConfigData
	client.Client
	kube.ObjectResolver
	ReadWriter
	trivyoperator.BuildInfo
}

func (r *ResourceController) SetupWithManager(mgr ctrl.Manager) error {
	installModePredicate, err := predicate.InstallModePredicate(r.Config)
	if err != nil {
		return err
	}

	resources := []struct {
		kind       kube.Kind
		forObject  client.Object
		ownsObject client.Object
	}{
		{kind: kube.KindPod, forObject: &corev1.Pod{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindReplicaSet, forObject: &appsv1.ReplicaSet{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindReplicationController, forObject: &corev1.ReplicationController{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindStatefulSet, forObject: &appsv1.StatefulSet{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindDaemonSet, forObject: &appsv1.DaemonSet{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindCronJob, forObject: &batchv1beta1.CronJob{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindJob, forObject: &batchv1.Job{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindService, forObject: &corev1.Service{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindConfigMap, forObject: &corev1.ConfigMap{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindRole, forObject: &rbacv1.Role{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindRoleBinding, forObject: &rbacv1.RoleBinding{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindNetworkPolicy, forObject: &networkingv1.NetworkPolicy{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindIngress, forObject: &networkingv1.Ingress{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindResourceQuota, forObject: &corev1.ResourceQuota{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
		{kind: kube.KindLimitRange, forObject: &corev1.LimitRange{}, ownsObject: &v1alpha1.ConfigAuditReport{}},
	}

	clusterResources := []struct {
		kind       kube.Kind
		forObject  client.Object
		ownsObject client.Object
	}{
		{kind: kube.KindClusterRole, forObject: &rbacv1.ClusterRole{}, ownsObject: &v1alpha1.ClusterConfigAuditReport{}},
		{kind: kube.KindClusterRoleBindings, forObject: &rbacv1.ClusterRoleBinding{}, ownsObject: &v1alpha1.ClusterConfigAuditReport{}},
		{kind: kube.KindCustomResourceDefinition, forObject: &apiextensionsv1.CustomResourceDefinition{}, ownsObject: &v1alpha1.ClusterConfigAuditReport{}},
		{kind: kube.KindPodSecurityPolicy, forObject: &policyv1beta1.PodSecurityPolicy{}, ownsObject: &v1alpha1.ClusterConfigAuditReport{}},
	}

	for _, resource := range resources {
		err = ctrl.NewControllerManagedBy(mgr).
			For(resource.forObject, builder.WithPredicates(
				predicate.Not(predicate.ManagedByTrivyOperator),
				predicate.Not(predicate.IsLeaderElectionResource),
				predicate.Not(predicate.IsBeingTerminated),
				installModePredicate,
			)).
			Owns(resource.ownsObject).
			Complete(r.reconcileResource(resource.kind))
		if err != nil {
			return fmt.Errorf("constructing controller for %s: %w", resource.kind, err)
		}

		err = ctrl.NewControllerManagedBy(mgr).
			For(&corev1.ConfigMap{}, builder.WithPredicates(
				predicate.Not(predicate.IsBeingTerminated),
				predicate.HasName(trivyoperator.PoliciesConfigMapName),
				predicate.InNamespace(r.Config.Namespace),
			)).
			Complete(r.reconcileConfig(resource.kind))
		if err != nil {
			return err
		}

	}

	for _, resource := range clusterResources {

		err = ctrl.NewControllerManagedBy(mgr).
			For(resource.forObject, builder.WithPredicates(
				predicate.Not(predicate.ManagedByTrivyOperator),
				predicate.Not(predicate.IsBeingTerminated),
			)).
			Owns(resource.ownsObject).
			Complete(r.reconcileResource(resource.kind))
		if err != nil {
			return fmt.Errorf("constructing controller for %s: %w", resource.kind, err)
		}

		err = ctrl.NewControllerManagedBy(mgr).
			For(&corev1.ConfigMap{}, builder.WithPredicates(
				predicate.Not(predicate.IsBeingTerminated),
				predicate.HasName(trivyoperator.PoliciesConfigMapName),
				predicate.InNamespace(r.Config.Namespace))).
			Complete(r.reconcileClusterConfig(resource.kind))
		if err != nil {
			return err
		}
	}

	return nil

}

func (r *ResourceController) reconcileResource(resourceKind kube.Kind) reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := r.Logger.WithValues("kind", resourceKind, "name", req.NamespacedName)

		resourceRef := kube.ObjectRefFromKindAndObjectKey(resourceKind, req.NamespacedName)

		resource, err := r.ObjectFromObjectRef(ctx, resourceRef)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring cached resource that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting %s from cache: %w", resourceKind, err)
		}

		// Skip processing if a resource is a Pod controlled by a built-in K8s workload.
		if resourceKind == kube.KindPod {
			controller := metav1.GetControllerOf(resource)
			if kube.IsBuiltInWorkload(controller) {
				log.V(1).Info("Ignoring managed pod",
					"controllerKind", controller.Kind,
					"controllerName", controller.Name)
				return ctrl.Result{}, nil
			}
		}

		if r.Config.ConfigAuditScannerScanOnlyCurrentRevisions && resourceKind == kube.KindReplicaSet {
			controller := metav1.GetControllerOf(resource)
			activeReplicaSet, err := r.IsActiveReplicaSet(ctx, resource, controller)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed checking current revision: %w", err)
			}
			if !activeReplicaSet {
				log.V(1).Info("Ignoring inactive ReplicaSet", "controllerKind", controller.Kind, "controllerName", controller.Name)
				return ctrl.Result{}, nil
			}
		}

		// Skip processing if a resource is a Job controlled by CronJob.
		if resourceKind == kube.KindJob {
			controller := metav1.GetControllerOf(resource)
			if controller != nil && controller.Kind == string(kube.KindCronJob) {
				log.V(1).Info("Ignoring managed job", "controllerKind", controller.Kind, "controllerName", controller.Name)
				return ctrl.Result{}, nil
			}
		}

		policies, err := r.policies(ctx)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting policies: %w", err)
		}

		// Skip processing if there are no policies applicable to the resource
		applicable, reason, err := policies.Applicable(resource)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("checking whether plugin is applicable: %w", err)
		}

		if !applicable {
			log.V(1).Info("Pushing back reconcile key",
				"reason", reason,
				"retryAfter", r.ScanJobRetryAfter)
			return ctrl.Result{RequeueAfter: r.Config.ScanJobRetryAfter}, nil
		}

		resourceHash, err := kube.ComputeSpecHash(resource)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("computing spec hash: %w", err)
		}

		policiesHash, err := policies.Hash(string(resourceKind))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("computing policies hash: %w", err)
		}

		log.V(1).Info("Checking whether configuration audit report exists")
		hasReport, err := r.hasReport(ctx, resourceRef, resourceHash, policiesHash)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("checking whether configuration audit report exists: %w", err)
		}

		if hasReport {
			log.V(1).Info("Configuration audit report exists")
			return ctrl.Result{}, nil
		}

		reportData, err := r.evaluate(ctx, policies, resource)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("evaluating resource: %w", err)
		}

		reportBuilder := NewReportBuilder(r.Client.Scheme()).
			Controller(resource).
			ResourceSpecHash(resourceHash).
			PluginConfigHash(policiesHash).
			Data(reportData)
		err = reportBuilder.Write(ctx, r.ReadWriter)
		if err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	}
}

func (r *ResourceController) hasReport(ctx context.Context, owner kube.ObjectRef, podSpecHash string, pluginConfigHash string) (bool, error) {
	if kube.IsClusterScopedKind(string(owner.Kind)) {
		return r.hasClusterReport(ctx, owner, podSpecHash, pluginConfigHash)
	}
	// TODO FindByOwner should accept optional label selector to further narrow down search results
	report, err := r.ReadWriter.FindReportByOwner(ctx, owner)
	if err != nil {
		return false, err
	}
	if report != nil {
		return report.Labels[trivyoperator.LabelResourceSpecHash] == podSpecHash &&
			report.Labels[trivyoperator.LabelPluginConfigHash] == pluginConfigHash, nil
	}
	return false, nil
}

func (r *ResourceController) hasClusterReport(ctx context.Context, owner kube.ObjectRef, podSpecHash string, pluginConfigHash string) (bool, error) {
	report, err := r.ReadWriter.FindClusterReportByOwner(ctx, owner)
	if err != nil {
		return false, err
	}
	if report != nil {
		return report.Labels[trivyoperator.LabelResourceSpecHash] == podSpecHash &&
			report.Labels[trivyoperator.LabelPluginConfigHash] == pluginConfigHash, nil
	}
	return false, nil
}

func (r *ResourceController) policies(ctx context.Context) (*policy.Policies, error) {
	cm := &corev1.ConfigMap{}

	err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: r.Config.Namespace,
		Name:      trivyoperator.PoliciesConfigMapName,
	}, cm)
	if err != nil {
		return nil, fmt.Errorf("failed getting policies from configmap: %s/%s: %w", r.Config.Namespace, trivyoperator.PoliciesConfigMapName, err)
	}
	return policy.NewPolicies(cm.Data), nil
}

func (r *ResourceController) evaluate(ctx context.Context, policies *policy.Policies, resource client.Object) (v1alpha1.ConfigAuditReportData, error) {
	results, err := policies.Eval(ctx, resource)
	if err != nil {
		return v1alpha1.ConfigAuditReportData{}, err
	}

	checks := make([]v1alpha1.Check, len(results))
	for i, result := range results {
		checks[i] = v1alpha1.Check{
			ID:          result.Metadata.ID,
			Title:       result.Metadata.Title,
			Description: result.Metadata.Description,
			Severity:    result.Metadata.Severity,
			Category:    result.Metadata.Type,

			Success:  result.Success,
			Messages: result.Messages,
		}
	}

	return v1alpha1.ConfigAuditReportData{
		Scanner: v1alpha1.Scanner{
			Name:    "Trivy-Operator",
			Vendor:  "Aqua Security",
			Version: r.BuildInfo.Version,
		},
		Summary: v1alpha1.ConfigAuditSummaryFromChecks(checks),
		Checks:  checks,

		PodChecks:       checks,
		ContainerChecks: map[string][]v1alpha1.Check{},
	}, nil
}

func (r *ResourceController) reconcileConfig(kind kube.Kind) reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := r.Logger.WithValues("configMap", req.NamespacedName)

		cm := &corev1.ConfigMap{}

		err := r.Client.Get(ctx, req.NamespacedName, cm)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring cached ConfigMap that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting ConfigMap from cache: %w", err)
		}

		policies, err := r.policies(ctx)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting policies: %w", err)
		}

		configHash, err := policies.Hash(string(kind))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting config hash: %w", err)
		}

		labelSelector, err := labels.Parse(fmt.Sprintf("%s!=%s,%s=%s",
			trivyoperator.LabelPluginConfigHash, configHash,
			trivyoperator.LabelResourceKind, kind))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("parsing label selector: %w", err)
		}

		var reportList v1alpha1.ConfigAuditReportList
		err = r.Client.List(ctx, &reportList,
			client.Limit(r.Config.BatchDeleteLimit+1),
			client.MatchingLabelsSelector{Selector: labelSelector})
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("listing reports: %w", err)
		}

		log.V(1).Info("Listing ConfigAuditReports",
			"reportsCount", len(reportList.Items),
			"batchDeleteLimit", r.Config.BatchDeleteLimit,
			"labelSelector", labelSelector.String())

		for i := 0; i < ext.MinInt(r.Config.BatchDeleteLimit, len(reportList.Items)); i++ {
			report := reportList.Items[i]
			log.V(1).Info("Deleting ConfigAuditReport", "report", report.Namespace+"/"+report.Name)
			err := r.Client.Delete(ctx, &report)
			if err != nil {
				if !errors.IsNotFound(err) {
					return ctrl.Result{}, fmt.Errorf("deleting ConfigAuditReport: %w", err)
				}
			}
		}
		if len(reportList.Items)-r.Config.BatchDeleteLimit > 0 {
			log.V(1).Info("Requeuing reconciliation key", "requeueAfter", r.Config.BatchDeleteDelay)
			return ctrl.Result{RequeueAfter: r.Config.BatchDeleteDelay}, nil
		}

		log.V(1).Info("Finished reconciling key", "labelSelector", labelSelector)
		return ctrl.Result{}, nil
	}
}

func (r *ResourceController) reconcileClusterConfig(kind kube.Kind) reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := r.Logger.WithValues("configMap", req.NamespacedName)

		cm := &corev1.ConfigMap{}

		err := r.Client.Get(ctx, req.NamespacedName, cm)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring cached ConfigMap that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting ConfigMap from cache: %w", err)
		}

		policies, err := r.policies(ctx)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting policies: %w", err)
		}

		configHash, err := policies.Hash(string(kind))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting config hash: %w", err)
		}

		labelSelector, err := labels.Parse(fmt.Sprintf("%s!=%s,%s=%s",
			trivyoperator.LabelPluginConfigHash, configHash,
			trivyoperator.LabelResourceKind, kind))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("parsing label selector: %w", err)
		}

		var clusterReportList v1alpha1.ClusterConfigAuditReportList
		err = r.Client.List(ctx, &clusterReportList,
			client.Limit(r.Config.BatchDeleteLimit+1),
			client.MatchingLabelsSelector{Selector: labelSelector})
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("listing reports: %w", err)
		}

		log.V(1).Info("Listing ClusterConfigAuditReports",
			"reportsCount", len(clusterReportList.Items),
			"batchDeleteLimit", r.Config.BatchDeleteLimit,
			"labelSelector", labelSelector)

		for i := 0; i < ext.MinInt(r.Config.BatchDeleteLimit, len(clusterReportList.Items)); i++ {
			report := clusterReportList.Items[i]
			log.V(1).Info("Deleting ClusterConfigAuditReport", "report", report.Name)
			err := r.Client.Delete(ctx, &report)
			if err != nil {
				if !errors.IsNotFound(err) {
					return ctrl.Result{}, fmt.Errorf("deleting ClusterConfigAuditReport: %w", err)
				}
			}
		}
		if len(clusterReportList.Items)-r.Config.BatchDeleteLimit > 0 {
			log.V(1).Info("Requeuing reconciliation key", "requeueAfter", r.Config.BatchDeleteDelay)
			return ctrl.Result{RequeueAfter: r.Config.BatchDeleteDelay}, nil
		}

		log.V(1).Info("Finished reconciling key", "labelSelector", labelSelector)
		return ctrl.Result{}, nil
	}
}
