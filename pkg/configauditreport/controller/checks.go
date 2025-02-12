package controller

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/policy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

type ChecksLoader struct {
	mu             sync.Mutex
	configReady    atomic.Bool
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
	r.logger.V(1).Info(fmt.Sprintf("ChecksLoader %s", req.String()))
	var cm corev1.ConfigMap
	if err := r.cl.Get(ctx, req.NamespacedName, &cm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	switch req.Name {
	case "trivy-operator-trivy-config", "trivy-operator-policies-config":
		r.logger.V(1).Info("Checks updated")
		cac, err := r.pluginConfig.NewConfigForConfigAudit(r.pluginContext)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("new config for config audit: %w", err)
		}
		policies, err := ConfiguredPolicies(
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
		r.configReady.Store(true)
	}
	return ctrl.Result{}, nil
}

func (r *ChecksLoader) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}).
		Complete(r)
}

func (r *ChecksLoader) IsChecksReady() bool {
	return r.configReady.Load()
}

func (r *ChecksLoader) GetPolicies() *policy.Policies {
	return r.policies
}
