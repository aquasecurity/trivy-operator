package compliance

import (
	"context"
	"fmt"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/utils"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type ClusterComplianceReportReconciler struct {
	logr.Logger
	client.Client
	Mgr
	ext.Clock
}

func (r *ClusterComplianceReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ClusterComplianceReport{}).
		Owns(&v1alpha1.ClusterComplianceDetailReport{}).
		Complete(r.reconcileComplianceReport()); err != nil {
		return err
	}
	return nil
}

func (r *ClusterComplianceReportReconciler) reconcileComplianceReport() reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		return r.generateComplianceReport(ctx, req.NamespacedName)
	}
}

func (r *ClusterComplianceReportReconciler) generateComplianceReport(ctx context.Context, namespaceName types.NamespacedName) (ctrl.Result, error) {
	ctrlResult := ctrl.Result{}
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		log := r.Logger.WithValues("compliance report", namespaceName)
		var report v1alpha1.ClusterComplianceReport
		err := r.Client.Get(ctx, namespaceName, &report)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring cached report that must have been deleted")
				return nil
			}
			return fmt.Errorf("getting report from cache: %w", err)
		}
		durationToNextGeneration, err := utils.NextCronDuration(report.Spec.Cron, r.reportLastUpdatedTime(&report), r.Clock)
		if err != nil {
			return fmt.Errorf("failed to check report cron expression %w", err)
		}
		if utils.DurationExceeded(durationToNextGeneration) {
			err = r.Mgr.GenerateComplianceReport(ctx, report.Spec)
			if err != nil {
				log.Error(err, "failed to generate compliance report")
			}
			return err
		}
		log.V(1).Info("RequeueAfter", "durationToNextGeneration", durationToNextGeneration)
		ctrlResult.RequeueAfter = durationToNextGeneration
		return nil
	})
	return ctrlResult, err
}

func (r *ClusterComplianceReportReconciler) reportLastUpdatedTime(report *v1alpha1.ClusterComplianceReport) time.Time {
	updateTimeStamp := report.Status.UpdateTimestamp.Time
	lastUpdated := updateTimeStamp
	if updateTimeStamp.Before(report.ObjectMeta.CreationTimestamp.Time) {
		lastUpdated = report.ObjectMeta.CreationTimestamp.Time
	}
	return lastUpdated
}
