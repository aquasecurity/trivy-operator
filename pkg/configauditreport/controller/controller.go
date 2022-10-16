package controller

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/operator/workload"
	"github.com/aquasecurity/trivy-operator/pkg/rbacassessment"

	"github.com/aquasecurity/defsec/pkg/scan"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	"github.com/aquasecurity/trivy-operator/pkg/policy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
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
	trivyoperator.PluginContext
	configauditreport.PluginInMemory
	configauditreport.ReadWriter
	RbacReadWriter rbacassessment.ReadWriter
	trivyoperator.BuildInfo
}

//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups=apps,resources=replicasets,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=replicationcontrollers,verbs=get;list;watch
//+kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch
//+kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch
//+kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch
//+kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch
//+kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch
//+kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=resourcequotas,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=limitranges,verbs=get;list;watch
//+kubebuilder:rbac:groups=aquasecurity.github.io,resources=configauditreports,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=aquasecurity.github.io,resources=rbacassessmentreports,verbs=get;list;watch;create;update;patch;delete

//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch
//+kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch
//+kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,verbs=get;list;watch
//+kubebuilder:rbac:groups=aquasecurity.github.io,resources=clusterconfigauditreports,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=aquasecurity.github.io,resources=clusterrbacassessmentreports,verbs=get;list;watch;create;update;patch;delete

// Controller for trivy-operator-policies-config in the operator namespace; must be cluster scoped even with namespace predicate
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

func (r *ResourceController) SetupWithManager(mgr ctrl.Manager) error {
	installModePredicate, err := predicate.InstallModePredicate(r.Config)
	if err != nil {
		return err
	}

	// Add non workload related resources
	resources := []kube.Resource{
		{Kind: kube.KindService, ForObject: &corev1.Service{}, OwnsObject: &v1alpha1.ConfigAuditReport{}},
		{Kind: kube.KindConfigMap, ForObject: &corev1.ConfigMap{}, OwnsObject: &v1alpha1.ConfigAuditReport{}},
		{Kind: kube.KindRole, ForObject: &rbacv1.Role{}, OwnsObject: &v1alpha1.RbacAssessmentReport{}},
		{Kind: kube.KindRoleBinding, ForObject: &rbacv1.RoleBinding{}, OwnsObject: &v1alpha1.RbacAssessmentReport{}},
		{Kind: kube.KindNetworkPolicy, ForObject: &networkingv1.NetworkPolicy{}, OwnsObject: &v1alpha1.ConfigAuditReport{}},
		{Kind: kube.KindIngress, ForObject: &networkingv1.Ingress{}, OwnsObject: &v1alpha1.ConfigAuditReport{}},
		{Kind: kube.KindResourceQuota, ForObject: &corev1.ResourceQuota{}, OwnsObject: &v1alpha1.ConfigAuditReport{}},
		{Kind: kube.KindLimitRange, ForObject: &corev1.LimitRange{}, OwnsObject: &v1alpha1.ConfigAuditReport{}},
	}

	// Determine which Kubernetes workloads the controller will reconcile and add them to resources
	targetWorkloads := r.Config.GetTargetWorkloads()
	for _, tw := range targetWorkloads {
		var resource kube.Resource
		err := resource.GetWorkloadResource(tw, &v1alpha1.ConfigAuditReport{}, r.ObjectResolver)
		if err != nil {
			return err
		}
		resources = append(resources, resource)
	}

	clusterResources := []kube.Resource{

		{Kind: kube.KindClusterRole, ForObject: &rbacv1.ClusterRole{}, OwnsObject: &v1alpha1.ClusterRbacAssessmentReport{}},
		{Kind: kube.KindClusterRoleBindings, ForObject: &rbacv1.ClusterRoleBinding{}, OwnsObject: &v1alpha1.ClusterRbacAssessmentReport{}},
		{Kind: kube.KindCustomResourceDefinition, ForObject: &apiextensionsv1.CustomResourceDefinition{}, OwnsObject: &v1alpha1.ClusterConfigAuditReport{}},
	}

	for _, resource := range resources {
		err = ctrl.NewControllerManagedBy(mgr).
			For(resource.ForObject, builder.WithPredicates(
				predicate.Not(predicate.ManagedByTrivyOperator),
				predicate.Not(predicate.IsLeaderElectionResource),
				predicate.Not(predicate.IsBeingTerminated),
				installModePredicate,
			)).
			Owns(resource.OwnsObject).
			Complete(r.reconcileResource(resource.Kind))
		if err != nil {
			return fmt.Errorf("constructing controller for %s: %w", resource.Kind, err)
		}

		err = ctrl.NewControllerManagedBy(mgr).
			For(&corev1.ConfigMap{}, builder.WithPredicates(
				predicate.Not(predicate.IsBeingTerminated),
				predicate.HasName(trivyoperator.PoliciesConfigMapName),
				predicate.InNamespace(r.Config.Namespace),
			)).
			Complete(r.reconcileConfig(resource.Kind))
		if err != nil {
			return err
		}

	}

	for _, resource := range clusterResources {

		err = ctrl.NewControllerManagedBy(mgr).
			For(resource.ForObject, builder.WithPredicates(
				predicate.Not(predicate.ManagedByTrivyOperator),
				predicate.Not(predicate.IsBeingTerminated),
			)).
			Owns(resource.OwnsObject).
			Complete(r.reconcileResource(resource.Kind))
		if err != nil {
			return fmt.Errorf("constructing controller for %s: %w", resource.Kind, err)
		}

		err = ctrl.NewControllerManagedBy(mgr).
			For(&corev1.ConfigMap{}, builder.WithPredicates(
				predicate.Not(predicate.IsBeingTerminated),
				predicate.HasName(trivyoperator.PoliciesConfigMapName),
				predicate.InNamespace(r.Config.Namespace))).
			Complete(r.reconcileClusterConfig(resource.Kind))
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
		// validate if workload require continuing with processing
		if skip, err := workload.SkipProcessing(ctx, resource, r.ObjectResolver,
			r.Config.ConfigAuditScannerScanOnlyCurrentRevisions, log); skip {
			return ctrl.Result{}, err
		}
		cac, err := r.NewConfigForConfigAudit(r.PluginContext)
		if err != nil {
			return ctrl.Result{}, err
		}
		policies, err := r.policies(ctx, cac)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting policies: %w", err)
		}

		// Skip processing if there are no policies applicable to the resource
		supported, err := policies.SupportedKind(resource, r.RbacAssessmentScannerEnabled)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("checking whether plugin is applicable: %w", err)
		}
		if !supported {
			log.V(1).Info("resource not supported",
				"kind", resource.GetObjectKind())
			return ctrl.Result{}, nil
		}
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

		resourceLabelsToInclude := r.GetScanJobResourceLabelsToInclude()

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
			if err.Error() == policy.PoliciesNotFoundError {
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("evaluating resource: %w", err)
		}
		switch rd := reportData.(type) {
		case v1alpha1.ConfigAuditReportData:
			reportBuilder := configauditreport.NewReportBuilder(r.Client.Scheme()).
				Controller(resource).
				ResourceSpecHash(resourceHash).
				PluginConfigHash(policiesHash).
				ResourceLabelsToInclude(resourceLabelsToInclude).
				Data(rd)
			if err := reportBuilder.Write(ctx, r.ReadWriter); err != nil {
				return ctrl.Result{}, err
			}
		case v1alpha1.RbacAssessmentReportData:
			rbacReportBuilder := rbacassessment.NewReportBuilder(r.Client.Scheme()).
				Controller(resource).
				ResourceSpecHash(resourceHash).
				PluginConfigHash(policiesHash).
				ResourceLabelsToInclude(resourceLabelsToInclude).
				Data(rd)
			if err := rbacReportBuilder.Write(ctx, r.RbacReadWriter); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
}

func (r *ResourceController) hasReport(ctx context.Context, owner kube.ObjectRef, podSpecHash string, pluginConfigHash string) (bool, error) {
	var io rbacassessment.Reader = r.ReadWriter
	if kube.IsRoleTypes(owner.Kind) {
		io = r.RbacReadWriter
	}
	if kube.IsClusterScopedKind(string(owner.Kind)) {
		hasClusterReport, err := r.hasClusterReport(ctx, owner, podSpecHash, pluginConfigHash, io)
		if err != nil {
			return false, err
		}
		return hasClusterReport, nil
	}
	return r.findReportOwner(ctx, owner, podSpecHash, pluginConfigHash, io)
}

func (r *ResourceController) hasClusterReport(ctx context.Context, owner kube.ObjectRef, podSpecHash string, pluginConfigHash string, io rbacassessment.Reader) (bool, error) {
	report, err := io.FindClusterReportByOwner(ctx, owner)
	if err != nil {
		return false, err
	}
	if report != nil {
		switch r := report.(type) {
		case *v1alpha1.ClusterConfigAuditReport:
			return r.Labels[trivyoperator.LabelResourceSpecHash] == podSpecHash &&
				r.Labels[trivyoperator.LabelPluginConfigHash] == pluginConfigHash, nil
		case *v1alpha1.ClusterRbacAssessmentReport:
			return r.Labels[trivyoperator.LabelResourceSpecHash] == podSpecHash &&
				r.Labels[trivyoperator.LabelPluginConfigHash] == pluginConfigHash, nil
		}
	}
	return false, nil
}
func (r *ResourceController) findReportOwner(ctx context.Context, owner kube.ObjectRef, podSpecHash string, pluginConfigHash string, io rbacassessment.Reader) (bool, error) {
	report, err := io.FindReportByOwner(ctx, owner)
	if err != nil {
		return false, err
	}
	if report != nil {
		switch r := report.(type) {
		case *v1alpha1.ConfigAuditReport:
			return r.Labels[trivyoperator.LabelResourceSpecHash] == podSpecHash &&
				r.Labels[trivyoperator.LabelPluginConfigHash] == pluginConfigHash, nil
		case *v1alpha1.RbacAssessmentReport:
			return r.Labels[trivyoperator.LabelResourceSpecHash] == podSpecHash &&
				r.Labels[trivyoperator.LabelPluginConfigHash] == pluginConfigHash, nil
		}
	}
	return false, nil
}

func (r *ResourceController) policies(ctx context.Context, cac configauditreport.ConfigAuditConfig) (*policy.Policies, error) {
	cm := &corev1.ConfigMap{}

	err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: r.Config.Namespace,
		Name:      trivyoperator.PoliciesConfigMapName,
	}, cm)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("failed getting policies from configmap: %s/%s: %w", r.Config.Namespace, trivyoperator.PoliciesConfigMapName, err)
		}
	}
	return policy.NewPolicies(cm.Data, cac, r.Logger), nil
}

func (r *ResourceController) evaluate(ctx context.Context, policies *policy.Policies, resource client.Object) (interface{}, error) {
	results, err := policies.Eval(ctx, resource)
	if err != nil {
		return nil, err
	}
	checks := make([]v1alpha1.Check, 0)
	for _, result := range results {
		id := policies.GetResultID(result)
		// ignore infra components until it will be officially supported
		if strings.HasPrefix(id, "KCV") || strings.HasPrefix(id, "AVD-KCV") || strings.HasPrefix(id, "N/A") {
			continue
		}
		checks = append(checks, v1alpha1.Check{
			ID:          id,
			Title:       result.Rule().Summary,
			Description: result.Rule().Explanation,
			Severity:    v1alpha1.Severity(result.Rule().Severity),
			Category:    "Kubernetes Security Check",

			Success:  result.Status() == scan.StatusPassed,
			Messages: []string{result.Description()},
		})
	}
	kind := resource.GetObjectKind().GroupVersionKind().Kind
	if kube.IsRoleTypes(kube.Kind(kind)) {
		return v1alpha1.RbacAssessmentReportData{
			Scanner: r.scanner(),
			Summary: v1alpha1.RbacAssessmentSummaryFromChecks(checks),
			Checks:  checks,
		}, nil
	}
	return v1alpha1.ConfigAuditReportData{
		UpdateTimestamp: metav1.NewTime(ext.NewSystemClock().Now()),
		Scanner:         r.scanner(),
		Summary:         v1alpha1.ConfigAuditSummaryFromChecks(checks),
		Checks:          checks,
	}, nil
}

func (r *ResourceController) scanner() v1alpha1.Scanner {
	return v1alpha1.Scanner{
		Name:    v1alpha1.ScannerNameTrivy,
		Vendor:  "Aqua Security",
		Version: r.BuildInfo.Version,
	}
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
		cac, err := r.NewConfigForConfigAudit(r.PluginContext)
		if err != nil {
			return ctrl.Result{}, err
		}
		policies, err := r.policies(ctx, cac)
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
		configRequeueAfter, err := r.deleteReports(ctx, labelSelector, auditConfigReportItems(v1alpha1.ConfigAuditReportList{}))
		if err != nil {
			return ctrl.Result{}, err
		}
		var rbacRequeueAfter bool
		if r.RbacAssessmentScannerEnabled {
			rbacRequeueAfter, err = r.deleteReports(ctx, labelSelector, rbacReportItems(v1alpha1.RbacAssessmentReportList{}))
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

func (r *ResourceController) deleteReports(ctx context.Context, labelSelector labels.Selector, reportItems func() (client.ObjectList, []client.Object)) (bool, error) {
	reportList, items := reportItems()
	err := r.Client.List(ctx, reportList,
		client.Limit(r.Config.BatchDeleteLimit+1),
		client.MatchingLabelsSelector{Selector: labelSelector})
	if err != nil {
		return false, fmt.Errorf("listing reports: %w", err)
	}
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

func (r *ResourceController) deleteReport(ctx context.Context, report client.Object) (bool, error) {
	err := r.Client.Delete(ctx, report)
	if err != nil {
		if !errors.IsNotFound(err) {
			return false, fmt.Errorf("deleting ConfigAuditReport: %w", err)
		}
	}
	return false, nil
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
		cac, err := r.NewConfigForConfigAudit(r.PluginContext)
		if err != nil {
			return ctrl.Result{}, err
		}
		policies, err := r.policies(ctx, cac)
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

		configRequeueAfter, err := r.deleteReports(ctx, labelSelector, clusterAuditConfigReportItems(v1alpha1.ClusterConfigAuditReportList{}))
		if err != nil {
			return ctrl.Result{}, err
		}
		var rbacRequeueAfter bool
		if r.RbacAssessmentScannerEnabled {
			rbacRequeueAfter, err = r.deleteReports(ctx, labelSelector, clusterRbacReportItems(v1alpha1.ClusterRbacAssessmentReportList{}))
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

func clusterRbacReportItems(crar v1alpha1.ClusterRbacAssessmentReportList) func() (client.ObjectList, []client.Object) {
	return func() (client.ObjectList, []client.Object) {
		objlist := make([]client.Object, 0)
		for idx := range crar.Items {
			objlist = append(objlist, &crar.Items[idx])
		}
		return &crar, objlist
	}
}

func rbacReportItems(rar v1alpha1.RbacAssessmentReportList) func() (client.ObjectList, []client.Object) {
	return func() (client.ObjectList, []client.Object) {
		objlist := make([]client.Object, 0)
		for idx := range rar.Items {
			objlist = append(objlist, &rar.Items[idx])
		}
		return &rar, objlist
	}
}

func clusterAuditConfigReportItems(ccar v1alpha1.ClusterConfigAuditReportList) func() (client.ObjectList, []client.Object) {
	return func() (client.ObjectList, []client.Object) {
		objlist := make([]client.Object, 0)
		for idx := range ccar.Items {
			objlist = append(objlist, &ccar.Items[idx])
		}
		return &ccar, objlist
	}
}
func auditConfigReportItems(car v1alpha1.ConfigAuditReportList) func() (client.ObjectList, []client.Object) {
	return func() (client.ObjectList, []client.Object) {
		objlist := make([]client.Object, 0)
		for idx := range car.Items {
			objlist = append(objlist, &car.Items[idx])
		}
		return &car, objlist
	}
}
