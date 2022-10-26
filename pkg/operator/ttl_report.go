package operator

import (
	"context"
	"fmt"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/utils"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	"github.com/go-logr/logr"
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
	client.Client
	ext.Clock
}

func (r *TTLReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// watch reports for ttl
	ttlResources := []kube.Resource{
		{ForObject: &v1alpha1.VulnerabilityReport{}},
		{ForObject: &v1alpha1.ConfigAuditReport{}},
		{ForObject: &v1alpha1.ExposedSecretReport{}},
		{ForObject: &v1alpha1.RbacAssessmentReport{}},
	}
	installModePredicate, err := predicate.InstallModePredicate(r.Config)
	if err != nil {
		return err
	}
	for _, reportType := range ttlResources {
		err = ctrl.NewControllerManagedBy(mgr).
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

func (r *TTLReportReconciler) DeleteReportIfExpired(ctx context.Context, namespacedName types.NamespacedName, reportType client.Object) (ctrl.Result, error) {
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
	if ttlExpired {
		log.V(1).Info("Removing report with expired TTL")
		err := r.Client.Delete(ctx, reportType, &client.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		// Since the report is deleted there is no reason to requeue
		return ctrl.Result{}, nil
	}
	log.V(1).Info("RequeueAfter", "durationToTTLExpiration", durationToTTLExpiration)
	return ctrl.Result{RequeueAfter: durationToTTLExpiration}, nil
}
