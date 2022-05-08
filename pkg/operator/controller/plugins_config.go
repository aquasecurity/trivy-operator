package controller

import (
	"context"
	"fmt"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type PluginsConfigReconciler struct {
	logr.Logger
	etc.Config
	client.Client
	trivyoperator.PluginContext
	configauditreport.Plugin
}

func (r *PluginsConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	opts := builder.WithPredicates(
		predicate.Not(predicate.IsBeingTerminated),
		predicate.HasName(trivyoperator.GetPluginConfigMapName(r.PluginContext.GetName())),
		predicate.InNamespace(r.Config.Namespace))

	for _, kind := range r.Plugin.SupportedKinds() {
		if kube.IsClusterScopedKind(string(kind)) {
			err := ctrl.NewControllerManagedBy(mgr).
				For(&corev1.ConfigMap{}, opts).
				Complete(r.reconcileClusterConfig(kind))
			if err != nil {
				return err
			}
		} else {
			err := ctrl.NewControllerManagedBy(mgr).
				For(&corev1.ConfigMap{}, opts).
				Complete(r.reconcileConfig(kind))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *PluginsConfigReconciler) reconcileConfig(kind kube.Kind) reconcile.Func {
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

		configHash, err := r.Plugin.ConfigHash(r.PluginContext, kind)
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

func (r *PluginsConfigReconciler) reconcileClusterConfig(kind kube.Kind) reconcile.Func {
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

		configHash, err := r.Plugin.ConfigHash(r.PluginContext, kind)
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
