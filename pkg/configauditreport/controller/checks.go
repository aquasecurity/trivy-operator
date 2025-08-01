package controller

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8spredicate "sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	"github.com/aquasecurity/trivy-operator/pkg/policy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

type ChecksLoader struct {
	mu             sync.Mutex
	cfg            etc.Config
	logger         logr.Logger
	cl             client.Client
	objectResolver kube.ObjectResolver
	pluginContext  trivyoperator.PluginContext
	pluginConfig   configauditreport.PluginInMemory
	policyLoader   policy.Loader
	policies       *policy.Policies
}

func NewChecksLoader(
	cfg etc.Config,
	logger logr.Logger,
	cl client.Client,
	objectResolver kube.ObjectResolver,
	pluginContext trivyoperator.PluginContext,
	pluginConfig configauditreport.PluginInMemory,
	policyLoader policy.Loader,
) *ChecksLoader {
	return &ChecksLoader{
		cfg:            cfg,
		logger:         logger,
		cl:             cl,
		objectResolver: objectResolver,
		pluginContext:  pluginContext,
		pluginConfig:   pluginConfig,
		policyLoader:   policyLoader,
	}
}

func (r *ChecksLoader) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	log := r.logger.WithValues("configMap", req.NamespacedName)

	var cm corev1.ConfigMap
	if err := r.cl.Get(ctx, req.NamespacedName, &cm); err != nil {
		if req.Name == trivyoperator.TrivyConfigMapName {
			log.V(1).Info("Checks removed since trivy config is removed")
			r.policies = nil
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.loadChecks(ctx); err != nil {
		return ctrl.Result{}, fmt.Errorf("load checks: %w", err)
	}

	return ctrl.Result{}, nil
}

func (r *ChecksLoader) loadChecks(ctx context.Context) error {
	log := r.logger

	log.V(1).Info("Load checks")
	cac, err := r.pluginConfig.NewConfigForConfigAudit(r.pluginContext)
	if err != nil {
		return fmt.Errorf("new config for config audit: %w", err)
	}
	policies, err := ConfigurePolicies(
		ctx, r.cfg, r.objectResolver, cac, r.logger, r.policyLoader,
	)
	if err != nil {
		return fmt.Errorf("getting policies: %w", err)
	}
	r.policies = policies
	log.V(1).Info("Checks loaded")

	return nil
}

func (r *ChecksLoader) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}, builder.WithPredicates(
			k8spredicate.Or(
				predicate.HasName(trivyoperator.TrivyConfigMapName),
				predicate.HasName(trivyoperator.PoliciesConfigMapName),
			),
			predicate.InNamespace(r.cfg.Namespace),
		)).
		Complete(r)
}

func (r *ChecksLoader) GetPolicies(ctx context.Context) (*policy.Policies, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.policies == nil {
		if err := r.loadChecks(ctx); err != nil {
			return nil, fmt.Errorf("load checks: %w", err)
		}
	}

	return r.policies, nil
}
