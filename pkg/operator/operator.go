package operator

import (
	"context"
	"fmt"
	"strconv"

	"github.com/aquasecurity/trivy-operator/pkg/compliance"
	"github.com/aquasecurity/trivy-operator/pkg/config"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport/controller"
	"github.com/aquasecurity/trivy-operator/pkg/exposedsecretreport"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/metrics"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/jobs"
	"github.com/aquasecurity/trivy-operator/pkg/plugins"
	"github.com/aquasecurity/trivy-operator/pkg/rbacassessment"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	setupLog = log.Log.WithName("operator")
)

// Start starts all registered reconcilers and blocks until the context is cancelled.
// Returns an error if there is an error starting any reconciler.
func Start(ctx context.Context, buildInfo trivyoperator.BuildInfo, operatorConfig etc.Config) error {
	kubeConfig, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("getting kube client config: %w", err)
	}
	// The only reason we're using kubernetes.Clientset is that we need it to read Pod logs,
	// which is not supported by the client returned by the ctrl.Manager.
	kubeClientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("constructing kube client: %w", err)
	}

	// TODO: reconsidet operatorConfig.Namespace
	configManager := trivyoperator.NewConfigManager(kubeClientset, operatorConfig.Namespace)
	err = configManager.EnsureDefault(context.Background())
	if err != nil {
		return err
	}

	trivyOperatorConfig, err := configManager.Read(context.Background())
	if err != nil {
		return err
	}

	// sets keys before config.GetConfig()

	if operatorConfig.VulnerabilityScannerEnabled || operatorConfig.ExposedSecretScannerEnabled {
		trivyOperatorConfig.Set(
			trivyoperator.KeyVulnerabilityScannerEnabled,
			strconv.FormatBool(operatorConfig.VulnerabilityScannerEnabled))

		trivyOperatorConfig.Set(
			trivyoperator.KeyExposedSecretsScannerEnabled,
			strconv.FormatBool(operatorConfig.ExposedSecretScannerEnabled))
	}

	// encapsuluate both configurations options. This is a firt step towards refactoring to have
	// only one configuration source from a configmap
	cfg := config.GetConfig(operatorConfig, trivyOperatorConfig)

	installMode, operatorNamespace, targetNamespaces, err := cfg.ResolveInstallMode()
	if err != nil {
		return fmt.Errorf("resolving install mode: %w", err)
	}

	setupLog.Info("Resolved install mode", "install mode", installMode,
		"operator namespace", operatorNamespace,
		"target namespaces", targetNamespaces,
		"exclude namespaces", cfg.ExcludeNamespaces())

	// Set the default manager options.
	options := manager.Options{
		Scheme:                 trivyoperator.NewScheme(),
		MetricsBindAddress:     cfg.MetricsBindAddress(),
		HealthProbeBindAddress: cfg.HealthProbeBindAddress(),
		// Disable cache for resources used to look up image pull secrets to avoid
		// spinning up informers and to tighten operator RBAC permissions
		ClientDisableCacheFor: []client.Object{
			&corev1.Secret{},
			&corev1.ServiceAccount{},
		},
	}

	if cfg.LeaderElectionEnabled() {
		options.LeaderElection = cfg.LeaderElectionEnabled()
		options.LeaderElectionID = cfg.LeaderElectionID()
		options.LeaderElectionNamespace = operatorNamespace
	}

	switch installMode {
	case etc.OwnNamespace:
		// Add support for OwnNamespace set in OPERATOR_NAMESPACE (e.g. `trivy-operator`)
		// and OPERATOR_TARGET_NAMESPACES (e.g. `trivy-operator`).
		setupLog.Info("Constructing client cache", "namespace", targetNamespaces[0])
		options.Namespace = targetNamespaces[0]
	case etc.SingleNamespace:
		// Add support for SingleNamespace set in OPERATOR_NAMESPACE (e.g. `trivy-operator`)
		// and OPERATOR_TARGET_NAMESPACES (e.g. `default`).
		cachedNamespaces := append(targetNamespaces, operatorNamespace)
		setupLog.Info("Constructing client cache", "namespaces", cachedNamespaces)
		options.NewCache = cache.MultiNamespacedCacheBuilder(cachedNamespaces)
	case etc.MultiNamespace:
		// Add support for MultiNamespace set in OPERATOR_NAMESPACE (e.g. `trivy-operator`)
		// and OPERATOR_TARGET_NAMESPACES (e.g. `default,kube-system`).
		// Note that you may face performance issues when using this mode with a high number of namespaces.
		// More: https://godoc.org/github.com/kubernetes-sigs/controller-runtime/pkg/cache#MultiNamespacedCacheBuilder
		cachedNamespaces := append(targetNamespaces, operatorNamespace)
		setupLog.Info("Constructing client cache", "namespaces", cachedNamespaces)
		options.NewCache = cache.MultiNamespacedCacheBuilder(cachedNamespaces)
	case etc.AllNamespaces:
		// Add support for AllNamespaces set in OPERATOR_NAMESPACE (e.g. `operators`)
		// and OPERATOR_TARGET_NAMESPACES left blank.
		setupLog.Info("Watching all namespaces")
	default:
		return fmt.Errorf("unrecognized install mode: %v", installMode)
	}

	mgr, err := ctrl.NewManager(kubeConfig, options)
	if err != nil {
		return fmt.Errorf("constructing controllers manager: %w", err)
	}

	err = mgr.AddReadyzCheck("ping", healthz.Ping)
	if err != nil {
		return err
	}

	err = mgr.AddHealthzCheck("ping", healthz.Ping)
	if err != nil {
		return err
	}

	compatibleObjectMapper, err := kube.InitCompatibleMgr(mgr.GetClient().RESTMapper())
	if err != nil {
		return err
	}
	objectResolver := kube.NewObjectResolver(mgr.GetClient(), compatibleObjectMapper)
	if err != nil {
		return err
	}

	limitChecker := jobs.NewLimitChecker(cfg, mgr.GetClient())
	logsReader := kube.NewLogsReader(kubeClientset)
	secretsReader := kube.NewSecretsReader(mgr.GetClient())

	if cfg.VulnerabilityScannerEnabled() || cfg.ExposedSecretsScannerEnabled() {

		plugin, pluginContext, err := plugins.NewResolver().
			WithBuildInfo(buildInfo).
			// TODO: do I need it? considering I'm injecting config
			WithNamespace(operatorNamespace).
			// TODO: do I need it? considering I'm injecting config
			WithServiceAccountName(cfg.ServiceAccount()).
			WithConfig(cfg).
			WithClient(mgr.GetClient()).
			WithObjectResolver(&objectResolver).
			GetVulnerabilityPlugin()
		if err != nil {
			return err
		}

		err = plugin.Init(pluginContext)
		if err != nil {
			return fmt.Errorf("initializing %s plugin: %w", pluginContext.GetName(), err)
		}

		if err = (&vulnerabilityreport.WorkloadController{
			Logger:                  ctrl.Log.WithName("reconciler").WithName("vulnerabilityreport"),
			Config:                  cfg,
			Client:                  mgr.GetClient(),
			ObjectResolver:          objectResolver,
			LimitChecker:            limitChecker,
			LogsReader:              logsReader,
			SecretsReader:           secretsReader,
			Plugin:                  plugin,
			PluginContext:           pluginContext,
			VulnerabilityReadWriter: vulnerabilityreport.NewReadWriter(&objectResolver),
			ExposedSecretReadWriter: exposedsecretreport.NewReadWriter(&objectResolver),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup vulnerabilityreport reconciler: %w", err)
		}

		if cfg.VulnerabilityScannerReportTTL() != nil {
			if err = (&vulnerabilityreport.TTLReportReconciler{
				Logger: ctrl.Log.WithName("reconciler").WithName("ttlreport"),
				Config: cfg,
				Client: mgr.GetClient(),
				Clock:  ext.NewSystemClock(),
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("unable to setup TTLreport reconciler: %w", err)
			}
		}
	}

	if cfg.ConfigAuditScannerEnabled() {
		plugin, pluginContext, err := plugins.NewResolver().WithBuildInfo(buildInfo).
			WithNamespace(operatorNamespace).
			WithServiceAccountName(cfg.ServiceAccount()).
			WithConfig(cfg).
			WithClient(mgr.GetClient()).
			WithObjectResolver(&objectResolver).
			GetConfigAuditPlugin()
		if err != nil {
			return fmt.Errorf("initializing %s plugin: %w", pluginContext.GetName(), err)
		}
		err = plugin.Init(pluginContext)
		if err != nil {
			return fmt.Errorf("initializing %s plugin: %w", pluginContext.GetName(), err)
		}
		setupLog.Info("Enabling built-in configuration audit scanner")
		if err = (&controller.ResourceController{
			Logger:         ctrl.Log.WithName("resourcecontroller"),
			Config:         cfg,
			Client:         mgr.GetClient(),
			ObjectResolver: objectResolver,
			PluginContext:  pluginContext,
			PluginInMemory: plugin,
			ReadWriter:     configauditreport.NewReadWriter(&objectResolver),
			RbacReadWriter: rbacassessment.NewReadWriter(&objectResolver),
			BuildInfo:      buildInfo,
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup resource controller: %w", err)
		}

	}

	if cfg.ClusterComplianceEnabled() {
		logger := ctrl.Log.WithName("reconciler").WithName("clustercompliancereport")
		cc := &compliance.ClusterComplianceReportReconciler{
			Logger: logger,
			Client: mgr.GetClient(),
			Mgr:    compliance.NewMgr(mgr.GetClient(), logger, cfg),
			Clock:  ext.NewSystemClock(),
		}
		if err := cc.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup clustercompliancereport reconciler: %w", err)
		}
	}

	if cfg.MetricsFindingsEnabled() {
		logger := ctrl.Log.WithName("metrics")
		rmc := &metrics.ResourcesMetricsCollector{
			Logger: logger,
			Config: cfg,
			Client: mgr.GetClient(),
		}
		if err := rmc.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup resources metrics collector: %w", err)
		}
	}

	setupLog.Info("Starting controllers manager")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("starting controllers manager: %w", err)
	}

	return nil
}
