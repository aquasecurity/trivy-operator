package operator

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	control "github.com/aquasecurity/trivy-operator/pkg/configauditreport/controller"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/utils"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	"github.com/aquasecurity/trivy-operator/pkg/policy"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type TTLReportReconciler struct {
	logr.Logger
	etc.Config
	PolicyLoader policy.Loader
	trivyoperator.PluginContext
	client.Client
	configauditreport.PluginInMemory
	ext.Clock
}

func (r *TTLReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// watch reports for ttl
	ttlResources := make([]kube.Resource, 0)
	if r.Config.RbacAssessmentScannerEnabled {
		ttlResources = append(ttlResources, kube.Resource{ForObject: &v1alpha1.RbacAssessmentReport{}})
	}
	if r.Config.ConfigAuditScannerEnabled {
		ttlResources = append(ttlResources, kube.Resource{ForObject: &v1alpha1.ConfigAuditReport{}})
	}
	if r.Config.VulnerabilityScannerEnabled {
		ttlResources = append(ttlResources, kube.Resource{ForObject: &v1alpha1.VulnerabilityReport{}})
	}
	if r.Config.ExposedSecretScannerEnabled {
		ttlResources = append(ttlResources, kube.Resource{ForObject: &v1alpha1.ExposedSecretReport{}})
	}
	if r.Config.InfraAssessmentScannerEnabled {
		ttlResources = append(ttlResources, kube.Resource{ForObject: &v1alpha1.InfraAssessmentReport{}})
	}
	if r.Config.SbomGenerationEnable {
		ttlResources = append(ttlResources, kube.Resource{ForObject: &v1alpha1.SbomReport{}})
	}
	if r.Config.ClusterSbomCacheEnable {
		ttlResources = append(ttlResources, kube.Resource{ForObject: &v1alpha1.ClusterSbomReport{}})
	}
	installModePredicate, err := predicate.InstallModePredicate(r.Config)
	if err != nil {
		return err
	}
	for _, reportType := range ttlResources {
		// Extract the kind of the report using reflection
		typeName := reflect.TypeOf(reportType.ForObject).Elem().Name()
		kind := strings.ToLower(typeName)

		err = ctrl.NewControllerManagedBy(mgr).
			Named(fmt.Sprintf("ttl-report-reconciler-%s", kind)).
			For(reportType.ForObject, builder.WithPredicates(
				predicate.Not(predicate.IsBeingTerminated),
				installModePredicate)).
			Complete(r.reconcileReport(reportType.ForObject))
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *TTLReportReconciler) reconcileReport(reportType client.Object) reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		return r.DeleteReportIfExpired(ctx, req.NamespacedName, reportType)
	}
}

func (r *TTLReportReconciler) DeleteReportIfExpired(ctx context.Context, namespacedName types.NamespacedName, reportType client.Object, arr ...string) (ctrl.Result, error) {
	log := r.Logger.WithValues("report", namespacedName)

	err := r.Client.Get(ctx, namespacedName, reportType)
	if err != nil {
		if errors.IsNotFound(err) {
			log.V(1).Info("Ignoring cached report that must have been deleted")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("getting report from cache: %w", err)
	}
	ttlReportAnnotationStr, ok := reportType.GetAnnotations()[v1alpha1.TTLReportAnnotation]
	if !ok {
		log.V(1).Info("Ignoring report without TTL set")
		return ctrl.Result{}, nil
	}
	reportTTLTime, err := time.ParseDuration(ttlReportAnnotationStr)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed parsing %v with value %v %w", v1alpha1.TTLReportAnnotation, ttlReportAnnotationStr, err)
	}
	ttlExpired, durationToTTLExpiration := utils.IsTTLExpired(reportTTLTime, reportType.GetCreationTimestamp().Time, r.Clock)

	if ttlExpired && r.applicableForDeletion(reportType, ttlReportAnnotationStr) {
		log.V(1).Info("Removing report with expired TTL or Historical")
		err := r.Client.Delete(ctx, reportType, &client.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		// Since the report is deleted there is no reason to requeue
		return ctrl.Result{}, nil
	}
	log.V(1).Info("RequeueAfter", "durationToTTLExpiration", durationToTTLExpiration)
	if ttlExpired {
		durationToTTLExpiration = reportTTLTime
	}
	return ctrl.Result{RequeueAfter: durationToTTLExpiration}, nil
}

func (r *TTLReportReconciler) applicableForDeletion(report client.Object, ttlReportAnnotationStr string) bool {
	reportKind := report.GetObjectKind().GroupVersionKind().Kind
	if reportKind == "VulnerabilityReport" || reportKind == "ExposedSecretReport" || reportKind == "ClusterSbomReport" || reportKind == "SbomReport" {
		return true
	}
	if ttlReportAnnotationStr == time.Duration(0).String() { // check if it marked as historical report
		return true
	}
	if !r.Config.ConfigAuditScannerEnabled {
		return false
	}
	resourceKind, ok := report.GetLabels()[trivyoperator.LabelResourceKind]
	if !ok {
		return false
	}
	policiesHash, ok := report.GetLabels()[trivyoperator.LabelPluginConfigHash]
	if !ok {
		return false
	}
	cac, err := r.NewConfigForConfigAudit(r.PluginContext)
	if err != nil {
		return false
	}
	policies, err := control.Policies(context.Background(), r.Config, r.Client, cac, r.Logger, r.PolicyLoader)
	if err != nil {
		return false
	}
	applicable, err := policies.ExternalPoliciesApplicable(resourceKind)
	if err != nil {
		return false
	}
	currentPoliciesHash, err := policies.Hash(resourceKind)
	if err != nil {
		return false
	}
	return applicable && (currentPoliciesHash != policiesHash)
}

type TTLSecretReconciler struct {
	logr.Logger
	etc.Config
	client.Client
	ext.Clock
}

func (r *TTLSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// watch reports for ttl
	secretTTLResources := make([]kube.Resource, 0)
	if r.Config.VulnerabilityScannerEnabled || r.Config.ExposedSecretScannerEnabled {
		secretTTLResources = append(secretTTLResources, kube.Resource{ForObject: &corev1.Secret{}})
	}
	installModePredicate, err := predicate.InstallModePredicate(r.Config)
	if err != nil {
		return err
	}
	for _, reportType := range secretTTLResources {
		err = ctrl.NewControllerManagedBy(mgr).
			For(reportType.ForObject, builder.WithPredicates(
				predicate.ManagedByTrivyOperator,
				predicate.InNamespace(r.Config.Namespace),
				installModePredicate)).
			Complete(r.reconcileSecret(reportType.ForObject))
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *TTLSecretReconciler) reconcileSecret(scanJobSecret client.Object) reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := r.Logger.WithValues("secret", req.NamespacedName)

		err := r.Client.Get(ctx, req.NamespacedName, scanJobSecret)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring cached report that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting secret from cache: %w", err)
		}
		ttlSecretAnnotationStr, ok := scanJobSecret.GetAnnotations()[v1alpha1.TTLSecretAnnotation]
		if !ok {
			log.V(1).Info("Ignoring report without TTL set")
			return ctrl.Result{}, nil
		}
		secretTTLTime, err := time.ParseDuration(ttlSecretAnnotationStr)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed parsing %v with value %v %w", v1alpha1.TTLSecretAnnotation, ttlSecretAnnotationStr, err)
		}
		ttlExpired, durationToTTLExpiration := utils.IsTTLExpired(secretTTLTime, scanJobSecret.GetCreationTimestamp().Time, r.Clock)

		if ttlExpired {
			log.V(1).Info("Removing secret with expired TTL")
			err := r.Client.Delete(ctx, scanJobSecret, &client.DeleteOptions{})
			if err != nil && !errors.IsNotFound(err) {
				return ctrl.Result{}, err
			}
			// Since the secret is deleted there is no reason to requeue
			return ctrl.Result{}, nil
		}
		log.V(1).Info("RequeueAfter", "durationToTTLExpiration", durationToTTLExpiration)
		return ctrl.Result{RequeueAfter: durationToTTLExpiration}, nil
	}
}
