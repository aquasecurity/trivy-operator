package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"net/http"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"time"
)

type WebhookReconciler struct {
	logr.Logger
	etc.Config
	client.Client
}

//+kubebuilder:rbac:groups=aquasecurity.github.io,resources=vulnerabilityreports,verbs=get;list;watch;delete

func (r *WebhookReconciler) SetupWithManager(mgr ctrl.Manager) error {
	installModePredicate, err := predicate.InstallModePredicate(r.Config)
	if err != nil {
		return err
	}

	reports := []client.Object{
		&v1alpha1.VulnerabilityReport{},
		&v1alpha1.ExposedSecretReport{},
		// TODO: Add more report types if needed
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

		err := r.Client.Get(ctx, request.NamespacedName, reportType)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring cached report that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting report from cache: %w", err)
		}

		if err := sendReport(reportType, r.WebhookBroadcastURL, *r.WebhookBroadcastTimeout); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to send report: %w", err)
		}
		return ctrl.Result{}, nil
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
