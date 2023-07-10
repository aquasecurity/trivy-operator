package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type WebhookReconciler struct {
	logr.Logger
	etc.Config
	client.Client
}

const (
	Update string = "update"
	Delete string = "delete"
)

type WebhookMsg struct {
	Verb           string        `json:"verb"`
	OperatorObject client.Object `json:"operatorObject"`
}

// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=vulnerabilityreports,verbs=get;list;watch;delete

func (r *WebhookReconciler) SetupWithManager(mgr ctrl.Manager) error {
	installModePredicate, err := predicate.InstallModePredicate(r.Config)
	if err != nil {
		return err
	}

	reports := []client.Object{
		&v1alpha1.VulnerabilityReport{},
		&v1alpha1.ExposedSecretReport{},
		&v1alpha1.ConfigAuditReport{},
		&v1alpha1.InfraAssessmentReport{},
		&v1alpha1.ClusterComplianceReport{},
		&v1alpha1.RbacAssessmentReport{},
		&v1alpha1.ClusterRbacAssessmentReport{},
		&v1alpha1.ClusterConfigAuditReport{},
		&v1alpha1.ClusterInfraAssessmentReport{},
		&v1alpha1.SbomReport{},
	}

	for _, reportType := range reports {
		err = ctrl.NewControllerManagedBy(mgr).
			For(reportType, builder.WithPredicates(
				predicate.Not(predicate.IsBeingTerminated),
				installModePredicate)).
			Complete(r.reconcileReport(reportType))
		if err != nil {
			return err
		}

	}
	return nil
}

func (r *WebhookReconciler) reconcileReport(reportType client.Object) reconcile.Func {
	return func(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
		log := r.Logger.WithValues("report", request.NamespacedName)
		verb := Update
		err := r.Client.Get(ctx, request.NamespacedName, reportType)
		if err != nil {
			if !errors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("getting report from cache: %w", err)
			}
			if !r.WebhookSendDeletedReports {
				log.V(1).Info("Ignoring cached report that must have been deleted")
				return ctrl.Result{}, nil
			}
			verb = Delete
		}

		if ignoreHistoricalReport(reportType) {
			log.V(1).Info("Ignoring historical report")
			return ctrl.Result{}, nil
		}

		if r.WebhookSendDeletedReports {
			msg := WebhookMsg{OperatorObject: reportType, Verb: verb}

			return ctrl.Result{}, sendReport(msg, r.WebhookBroadcastURL, *r.WebhookBroadcastTimeout)
		}
		return ctrl.Result{}, sendReport(reportType, r.WebhookBroadcastURL, *r.WebhookBroadcastTimeout)
	}
}

func sendReport[T any](reports T, endpoint string, timeout time.Duration) error {
	b, err := json.Marshal(reports)
	if err != nil {
		return fmt.Errorf("failed to marshal reports: %w", err)
	}
	hc := http.Client{
		Timeout: timeout,
	}
	_, err = hc.Post(endpoint, "application/json", bytes.NewBuffer(b))
	if err != nil {
		return fmt.Errorf("failed to send reports to endpoint: %w", err)
	}
	return nil
}

func ignoreHistoricalReport(reportType client.Object) bool {
	ttlReportAnnotationStr, ok := reportType.GetAnnotations()[v1alpha1.TTLReportAnnotation]
	if !ok {
		return false
	}
	if ttlReportAnnotationStr == time.Duration(0).String() { // check if it marked as historical report
		return true
	}
	return false
}
