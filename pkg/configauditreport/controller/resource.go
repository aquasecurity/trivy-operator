package controller

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/infraassessment"
	"github.com/aquasecurity/trivy-operator/pkg/operator/workload"
	"github.com/aquasecurity/trivy-operator/pkg/rbacassessment"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	"github.com/aquasecurity/trivy-operator/pkg/policy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	k8s_predicate "sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// ResourceController watches all Kubernetes kinds and generates
// v1alpha1.ConfigAuditReport instances based on OPA Rego policies as fast as
// possible.
type ResourceController struct {
	logr.Logger
	etc.Config
	PolicyLoader policy.Loader
	trivyoperator.ConfigData
	kube.ObjectResolver
	trivyoperator.PluginContext
	configauditreport.PluginInMemory
	configauditreport.ReadWriter
	RbacReadWriter  rbacassessment.ReadWriter
	InfraReadWriter infraassessment.ReadWriter
	trivyoperator.BuildInfo
	ClusterVersion   string
	CacheSyncTimeout time.Duration
}

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=replicasets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=replicationcontrollers,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=cronjobs,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=resourcequotas,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=limitranges,verbs=get;list;watch
// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=configauditreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=rbacassessmentreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=infraassessmentreports,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch
// +kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,verbs=get;list;watch
// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=clusterconfigauditreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=clusterrbacassessmentreports,verbs=get;list;watch;create;update;patch;delete

func (r *ResourceController) SetupWithManager(mgr ctrl.Manager) error {
	installModePredicate, err := predicate.InstallModePredicate(r.Config)
	if err != nil {
		return err
	}

	// Determine which Kubernetes workloads the controller will reconcile and add them to resources
	targetWorkloads := r.Config.GetTargetWorkloads()
	targetWorkloads = append(targetWorkloads, strings.ToLower(string(kube.KindIngress)))
	for _, tw := range targetWorkloads {
		var resource kube.Resource
		if err = resource.GetWorkloadResource(tw, &v1alpha1.ConfigAuditReport{}, r.ObjectResolver); err != nil {
			return err
		}
		resourceBuilder := r.buildControlMgr(mgr, resource, installModePredicate)
		if r.Config.InfraAssessmentScannerEnabled {
			resourceBuilder.Owns(&v1alpha1.InfraAssessmentReport{})
		}
		if err = resourceBuilder.Complete(r.reconcileResource(resource.Kind)); err != nil {
			return fmt.Errorf("constructing controller for %s: %w", resource.Kind, err)
		}
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

	for _, configResource := range resources {
		if err := r.buildControlMgr(mgr, configResource, installModePredicate).
			Complete(r.reconcileResource(configResource.Kind)); err != nil {
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

		// Log the controller name for debugging
		r.Logger.Info("Setting up cluster resource controller", "controllerName", fmt.Sprintf("resource-controller-%s", kind))

		if err = ctrl.NewControllerManagedBy(mgr).
			WithOptions(controller.Options{
				CacheSyncTimeout: r.CacheSyncTimeout,
			}).
			Named(fmt.Sprintf("resource-controller-%s", kind)).
			For(resource.ForObject, builder.WithPredicates(
				predicate.Not(predicate.ManagedByTrivyOperator),
				predicate.Not(predicate.IsBeingTerminated),
			)).
			Owns(resource.OwnsObject).
			Complete(r.reconcileResource(resource.Kind)); err != nil {
			return fmt.Errorf("constructing controller for %s: %w", resource.Kind, err)
		}
	}

	return nil
}

func (r *ResourceController) buildControlMgr(mgr ctrl.Manager, configResource kube.Resource, installModePredicate k8s_predicate.Predicate) *builder.Builder {
	// Extract the kind using reflection
	typeName := reflect.TypeOf(configResource.ForObject).Elem().Name()
	kind := strings.ToLower(typeName)

	// Log the controller name for debugging
	r.Logger.Info("Setting up controller", "controllerName", fmt.Sprintf("resource-controller-%s", kind))

	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{
			CacheSyncTimeout: r.CacheSyncTimeout,
		}).
		Named(fmt.Sprintf("resource-controller-%s", kind)).
		For(configResource.ForObject, builder.WithPredicates(
			predicate.Not(predicate.ManagedByTrivyOperator),
			predicate.Not(predicate.IsLeaderElectionResource),
			predicate.Not(predicate.IsBeingTerminated),
			installModePredicate,
		)).
		Owns(configResource.OwnsObject)
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
			r.Config.ConfigAuditScannerScanOnlyCurrentRevisions, log, r.ConfigData.GetSkipResourceByLabels()); skip {
			return ctrl.Result{}, err
		}
		cac, err := r.NewConfigForConfigAudit(r.PluginContext)
		if err != nil {
			return ctrl.Result{}, err
		}
		policies, err := Policies(ctx, r.Config, r.Client, cac, r.Logger, r.PolicyLoader, r.ClusterVersion)
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
		applicable, reason, err := policies.Applicable(resource.GetObjectKind().GroupVersionKind().Kind)
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

		resourceLabelsToInclude := r.GetReportResourceLabels()
		additionalCustomLabel, err := r.GetAdditionalReportLabels()
		if err != nil {
			return ctrl.Result{}, err
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
		misConfigData, err := evaluate(ctx, policies, resource, r.BuildInfo, r.ConfigData, r.Config)
		if err != nil {
			if err.Error() == policy.PoliciesNotFoundError {
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("evaluating resource: %w", err)
		}
		kind := resource.GetObjectKind().GroupVersionKind().Kind
		// create config-audit report
		if !kube.IsRoleTypes(kube.Kind(kind)) || r.MergeRbacFindingWithConfigAudit {
			reportBuilder := configauditreport.NewReportBuilder(r.Client.Scheme()).
				Controller(resource).
				ResourceSpecHash(resourceHash).
				PluginConfigHash(policiesHash).
				ResourceLabelsToInclude(resourceLabelsToInclude).
				AdditionalReportLabels(additionalCustomLabel).
				Data(misConfigData.configAuditReportData)
			if r.Config.ScannerReportTTL != nil {
				reportBuilder.ReportTTL(r.Config.ScannerReportTTL)
			}
			if err := reportBuilder.Write(ctx, r.ReadWriter); err != nil {
				return ctrl.Result{}, err
			}
			// create infra-assessment report
			if k8sCoreComponent(resource) && r.Config.InfraAssessmentScannerEnabled {
				infraReportBuilder := infraassessment.NewReportBuilder(r.Client.Scheme()).
					Controller(resource).
					ResourceSpecHash(resourceHash).
					PluginConfigHash(policiesHash).
					ResourceLabelsToInclude(resourceLabelsToInclude).
					AdditionalReportLabels(additionalCustomLabel).
					Data(misConfigData.infraAssessmentReportData)
				if r.Config.ScannerReportTTL != nil {
					infraReportBuilder.ReportTTL(r.Config.ScannerReportTTL)
				}
				if err := infraReportBuilder.Write(ctx, r.InfraReadWriter); err != nil {
					return ctrl.Result{}, err
				}
			}
		}
		// create rbac-assessment report
		if kube.IsRoleTypes(kube.Kind(kind)) && r.Config.RbacAssessmentScannerEnabled && !r.MergeRbacFindingWithConfigAudit {
			rbacReportBuilder := rbacassessment.NewReportBuilder(r.Client.Scheme()).
				Controller(resource).
				ResourceSpecHash(resourceHash).
				PluginConfigHash(policiesHash).
				ResourceLabelsToInclude(resourceLabelsToInclude).
				AdditionalReportLabels(additionalCustomLabel).
				Data(misConfigData.rbacAssessmentReportData)
			if r.Config.ScannerReportTTL != nil {
				rbacReportBuilder.ReportTTL(r.Config.ScannerReportTTL)
			}
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

type Misconfiguration struct {
	configAuditReportData     v1alpha1.ConfigAuditReportData
	rbacAssessmentReportData  v1alpha1.RbacAssessmentReportData
	infraAssessmentReportData v1alpha1.InfraAssessmentReportData
}

func infraCheck(id string) bool {
	return strings.HasPrefix(id, "KCV") || strings.HasPrefix(id, "AVD-KCV")
}

func k8sCoreComponent(resource client.Object) bool {
	return resource.GetObjectKind().GroupVersionKind().Kind == string(kube.KindNode) ||
		(resource.GetNamespace() == kube.KubeSystemNamespace &&
			(strings.Contains(resource.GetName(), "kube-apiserver") ||
				strings.Contains(resource.GetName(), "kube-controller-manager") ||
				strings.Contains(resource.GetName(), "kube-scheduler") ||
				strings.Contains(resource.GetName(), "etcd")))
}

func getCheck(result scan.Result, id string) v1alpha1.Check {
	return v1alpha1.Check{
		ID:          id,
		Title:       result.Rule().Summary,
		Description: result.Rule().Explanation,
		Severity:    v1alpha1.Severity(result.Rule().Severity),
		Category:    "Kubernetes Security Check",

		Success:     result.Status() == scan.StatusPassed,
		Messages:    []string{result.Description()},
		Remediation: result.Rule().Resolution,
	}
}

func clusterRbacReportItems(crar *v1alpha1.ClusterRbacAssessmentReportList) func() []client.Object {
	return func() []client.Object {
		objlist := make([]client.Object, 0)
		for idx := range crar.Items {
			objlist = append(objlist, &crar.Items[idx])
		}
		return objlist
	}
}

func rbacReportItems(rar *v1alpha1.RbacAssessmentReportList) func() []client.Object {
	return func() []client.Object {
		objlist := make([]client.Object, 0)
		for idx := range rar.Items {
			objlist = append(objlist, &rar.Items[idx])
		}
		return objlist
	}
}

func infraReportItems(rar *v1alpha1.InfraAssessmentReportList) func() []client.Object {
	return func() []client.Object {
		objlist := make([]client.Object, 0)
		for idx := range rar.Items {
			objlist = append(objlist, &rar.Items[idx])
		}
		return objlist
	}
}

func clusterAuditConfigReportItems(ccar *v1alpha1.ClusterConfigAuditReportList) func() []client.Object {
	return func() []client.Object {
		objlist := make([]client.Object, 0)
		for idx := range ccar.Items {
			objlist = append(objlist, &ccar.Items[idx])
		}
		return objlist
	}
}
func auditConfigReportItems(car *v1alpha1.ConfigAuditReportList) func() []client.Object {
	return func() []client.Object {
		objlist := make([]client.Object, 0)
		for idx := range car.Items {
			objlist = append(objlist, &car.Items[idx])
		}
		return objlist
	}
}
