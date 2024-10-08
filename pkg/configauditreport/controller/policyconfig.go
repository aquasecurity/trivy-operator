package controller

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/policy"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// PolicyConfigController watches changes on policies config map and generates
// v1alpha1.ConfigAuditReport instances based on OPA Rego policies as fast as
// possible.
type PolicyConfigController struct {
	logr.Logger
	etc.Config
	kube.ObjectResolver
	trivyoperator.PluginContext
	PolicyLoader policy.Loader
	configauditreport.PluginInMemory
	ClusterVersion string
}

// Controller for trivy-operator-policies-config in the operator namespace; must be cluster scoped even with namespace predicate
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

func (r *PolicyConfigController) SetupWithManager(mgr ctrl.Manager) error {

	// Determine which Kubernetes workloads the controller will reconcile and add them to resources
	targetWorkloads := r.Config.GetTargetWorkloads()
	workloadResources := make([]kube.Resource, 0)
	for _, tw := range targetWorkloads {
		var resource kube.Resource
		if err := resource.GetWorkloadResource(tw, &v1alpha1.ConfigAuditReport{}, r.ObjectResolver); err != nil {
			return err
		}
		workloadResources = append(workloadResources, resource)
	}

	// Add non workload related resources
	resources := []kube.Resource{
		{Kind: kube.KindService, ForObject: &corev1.Service{}, OwnsObject: &v1alpha1.ConfigAuditReport{}},
		{Kind: kube.KindConfigMap, ForObject: &corev1.ConfigMap{}, OwnsObject: &v1alpha1.ConfigAuditReport{}},
		{Kind: kube.KindRole, ForObject: &rbacv1.Role{}, OwnsObject: &v1alpha1.RbacAssessmentReport{}},
		{Kind: kube.KindRoleBinding, ForObject: &rbacv1.RoleBinding{}, OwnsObject: &v1alpha1.RbacAssessmentReport{}},
		{Kind: kube.KindNetworkPolicy, ForObject: &networkingv1.NetworkPolicy{}, OwnsObject: &v1alpha1.ConfigAuditReport{}},
		{Kind: kube.KindResourceQuota, ForObject: &corev1.ResourceQuota{}, OwnsObject: &v1alpha1.ConfigAuditReport{}},
		{Kind: kube.KindLimitRange, ForObject: &corev1.LimitRange{}, OwnsObject: &v1alpha1.ConfigAuditReport{}},
	}

	resources = append(resources, workloadResources...)
	for _, configResource := range resources {
		// Extract the kind of the resource
		typeName := reflect.TypeOf(configResource.ForObject).Elem().Name()
		kind := strings.ToLower(typeName)

		// Assign a unique name to the controller
		if err := ctrl.NewControllerManagedBy(mgr).
			Named(fmt.Sprintf("policy-config-controller-%s", kind)).
			For(&corev1.ConfigMap{}, builder.WithPredicates(
				predicate.Not(predicate.IsBeingTerminated),
				predicate.HasName(trivyoperator.PoliciesConfigMapName),
				predicate.InNamespace(r.Config.Namespace),
			)).
			Complete(r.reconcileConfig(configResource.Kind)); err != nil {
			return fmt.Errorf("constructing controller for %s: %w", configResource.Kind, err)
		}
	}

	clusterResources := []kube.Resource{
		{Kind: kube.KindClusterRole, ForObject: &rbacv1.ClusterRole{}, OwnsObject: &v1alpha1.ClusterRbacAssessmentReport{}},
		{Kind: kube.KindClusterRoleBindings, ForObject: &rbacv1.ClusterRoleBinding{}, OwnsObject: &v1alpha1.ClusterRbacAssessmentReport{}},
		{Kind: kube.KindCustomResourceDefinition, ForObject: &apiextensionsv1.CustomResourceDefinition{}, OwnsObject: &v1alpha1.ClusterConfigAuditReport{}},
	}

	for _, resource := range clusterResources {
		typeName := reflect.TypeOf(resource.ForObject).Elem().Name()
		kind := strings.ToLower(typeName)

		if err := ctrl.NewControllerManagedBy(mgr).
			Named(fmt.Sprintf("policy-config-controller-%s", kind)).
			For(&corev1.ConfigMap{}, builder.WithPredicates(
				predicate.Not(predicate.IsBeingTerminated),
				predicate.HasName(trivyoperator.PoliciesConfigMapName),
				predicate.InNamespace(r.Config.Namespace))).
			Complete(r.reconcileClusterConfig(resource.Kind)); err != nil {
			return err
		}
	}

	return nil

}

func (r *PolicyConfigController) reconcileConfig(kind kube.Kind) reconcile.Func {
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
		cac, err := r.NewConfigForConfigAudit(r.PluginContext)
		if err != nil {
			return ctrl.Result{}, err
		}
		policies, err := Policies(ctx, r.Config, r.Client, cac, r.Logger, r.PolicyLoader, r.ClusterVersion)
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
		carl := v1alpha1.ConfigAuditReportList{}
		configRequeueAfter, err := r.deleteReports(ctx, labelSelector, &carl, auditConfigReportItems(&carl))
		if err != nil {
			return ctrl.Result{}, err
		}
		var rbacRequeueAfter bool
		if r.RbacAssessmentScannerEnabled {
			cral := v1alpha1.RbacAssessmentReportList{}
			rbacRequeueAfter, err = r.deleteReports(ctx, labelSelector, &cral, rbacReportItems(&cral))
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		if r.InfraAssessmentScannerEnabled {
			ial := v1alpha1.InfraAssessmentReportList{}
			rbacRequeueAfter, err = r.deleteReports(ctx, labelSelector, &ial, infraReportItems(&ial))
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		if configRequeueAfter || rbacRequeueAfter {
			return ctrl.Result{RequeueAfter: r.Config.BatchDeleteDelay}, nil
		}
		return ctrl.Result{}, nil
	}
}

func (r *PolicyConfigController) deleteReports(ctx context.Context, labelSelector labels.Selector, reportList client.ObjectList, reportItems func() []client.Object) (bool, error) {
	err := r.Client.List(ctx, reportList,
		client.Limit(r.Config.BatchDeleteLimit+1),
		client.MatchingLabelsSelector{Selector: labelSelector})
	if err != nil {
		return false, fmt.Errorf("listing reports: %w", err)
	}
	items := reportItems()
	reportSize := len(items)
	for i := 0; i < ext.MinInt(r.Config.BatchDeleteLimit, reportSize); i++ {
		reportItem := items[i]
		b, err := r.deleteReport(ctx, reportItem)
		if err != nil {
			return b, err
		}
	}
	return reportSize-r.Config.BatchDeleteLimit > 0, nil
}

func (r *PolicyConfigController) deleteReport(ctx context.Context, report client.Object) (bool, error) {
	err := r.Client.Delete(ctx, report)
	if err != nil {
		if !errors.IsNotFound(err) {
			return false, fmt.Errorf("deleting ConfigAuditReport: %w", err)
		}
	}
	return false, nil
}

func (r *PolicyConfigController) reconcileClusterConfig(kind kube.Kind) reconcile.Func {
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
		cac, err := r.NewConfigForConfigAudit(r.PluginContext)
		if err != nil {
			return ctrl.Result{}, err
		}
		policies, err := Policies(ctx, r.Config, r.Client, cac, r.Logger, r.PolicyLoader)
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
		cacrl := v1alpha1.ClusterConfigAuditReportList{}
		configRequeueAfter, err := r.deleteReports(ctx, labelSelector, &cacrl, clusterAuditConfigReportItems(&cacrl))
		if err != nil {
			return ctrl.Result{}, err
		}
		var rbacRequeueAfter bool
		if r.RbacAssessmentScannerEnabled {
			rarl := v1alpha1.ClusterRbacAssessmentReportList{}
			rbacRequeueAfter, err = r.deleteReports(ctx, labelSelector, &rarl, clusterRbacReportItems(&rarl))
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		if configRequeueAfter || rbacRequeueAfter {
			return ctrl.Result{RequeueAfter: r.Config.BatchDeleteDelay}, nil
		}
		return ctrl.Result{}, nil
	}
}
