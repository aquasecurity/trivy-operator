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
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/policy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy/pkg/set"
)

type ChecksLoader struct {
	mu             sync.Mutex
	checksLoaded   bool
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
			log.V(1).Info("Checks removed")
			r.checksLoaded = false
			r.policies = nil
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.V(1).Info("Load checks")
	cac, err := r.pluginConfig.NewConfigForConfigAudit(r.pluginContext)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("new config for config audit: %w", err)
	}
	policies, err := ConfigurePolicies(
		ctx, r.cfg, r.objectResolver, cac, r.logger, r.policyLoader,
	)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("getting policies: %w", err)
	}
	if err := policies.Load(); err != nil {
		return ctrl.Result{}, fmt.Errorf("load checks: %w", err)
	}
	if err := policies.InitScanner(); err != nil {
		return ctrl.Result{}, fmt.Errorf("init k8s scanner: %w", err)
	}
	r.policies = policies
	r.checksLoaded = true
	log.V(1).Info("Checks loaded")
	return ctrl.Result{}, nil
}

var allowedConfigMaps = set.New[string](trivyoperator.TrivyConfigMapName, trivyoperator.PoliciesConfigMapName)

var configPredicate = func(namespace string) predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if allowedConfigMaps.Contains(obj.GetName()) {
			return false
		}
		return obj.GetNamespace() == namespace
	})
}

func (r *ChecksLoader) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}, builder.WithPredicates(configPredicate(r.cfg.Namespace))).
		Complete(r)
}

func (r *ChecksLoader) IsChecksReady() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.checksLoaded
}

func (r *ChecksLoader) GetPolicies() *policy.Policies {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.policies
}
