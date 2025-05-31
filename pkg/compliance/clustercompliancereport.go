package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/utils"
)

type ClusterComplianceReportReconciler struct {
	logr.Logger
	client.Client
	etc.Config
	Mgr
	ext.Clock
}

// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=clustercompliancereports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=clustercompliancereports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=clustercompliancedetailreports,verbs=get;list;watch;create;update;patch;delete

func (r *ClusterComplianceReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ClusterComplianceReport{}).
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
		if utils.DurationExceeded(durationToNextGeneration) || r.Config.InvokeClusterComplianceOnce {
			if r.Config.AltReportStorageEnabled && r.Config.AltReportDir != "" {
				// Write the compliance report to a file
				reportDir := r.Config.AltReportDir
				complianceReportDir := filepath.Join(reportDir, "cluster_compliance_report")
				if err := os.MkdirAll(complianceReportDir, 0750); err != nil {
					return fmt.Errorf("failed to create report directory: %w", err)
				}
				reportData, err := json.Marshal(report)
				if err != nil {
					log.Error(err, "Failed to marshal compliance report")
					return err
				}

				reportPath := filepath.Join(complianceReportDir, fmt.Sprintf("%s-%s.json", report.Kind, report.Name))
				log.Info("Writing cluster compliance report to alternate storage", "path", reportPath)
				err = os.WriteFile(reportPath, reportData, 0600)
				if err != nil {
					log.Error(err, "Failed to write compliance report", "path", reportPath)
					return err
				}
				log.Info("Cluster compliance report written", "path", reportPath)

				return nil
			}
			err = r.Mgr.GenerateComplianceReport(ctx, report.Spec)
			if err != nil {
				log.Error(err, "failed to generate compliance report")
				return err
			}
		}
		if r.Config.InvokeClusterComplianceOnce { // for demo or testing purposes
			return nil
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
