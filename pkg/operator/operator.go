package operator

import (
	"context"
	"fmt"

	"github.com/aquasecurity/trivy-operator/pkg/compliance"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/kubebench"
	"github.com/aquasecurity/trivy-operator/pkg/operator/controller"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/plugin"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
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
	installMode, operatorNamespace, targetNamespaces, err := operatorConfig.ResolveInstallMode()
	if err != nil {
		return fmt.Errorf("resolving install mode: %w", err)
	}
	setupLog.Info("Resolved install mode", "install mode", installMode,
		"operator namespace", operatorNamespace,
		"target namespaces", targetNamespaces,
		"exclude namespaces", operatorConfig.ExcludeNamespaces)

	// Set the default manager options.
	options := manager.Options{
		Scheme:                 trivyoperator.NewScheme(),
		MetricsBindAddress:     operatorConfig.MetricsBindAddress,
		HealthProbeBindAddress: operatorConfig.HealthProbeBindAddress,
	}

	if operatorConfig.LeaderElectionEnabled {
		options.LeaderElection = operatorConfig.LeaderElectionEnabled
		options.LeaderElectionID = operatorConfig.LeaderElectionID
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
		if operatorConfig.CISKubernetesBenchmarkEnabled {
			// Cache cluster-scoped resources such as Nodes
			cachedNamespaces = append(cachedNamespaces, "")
		}
		setupLog.Info("Constructing client cache", "namespaces", cachedNamespaces)
		options.NewCache = cache.MultiNamespacedCacheBuilder(cachedNamespaces)
	case etc.MultiNamespace:
		// Add support for MultiNamespace set in OPERATOR_NAMESPACE (e.g. `trivy-operator`)
		// and OPERATOR_TARGET_NAMESPACES (e.g. `default,kube-system`).
		// Note that you may face performance issues when using this mode with a high number of namespaces.
		// More: https://godoc.org/github.com/kubernetes-sigs/controller-runtime/pkg/cache#MultiNamespacedCacheBuilder
		cachedNamespaces := append(targetNamespaces, operatorNamespace)
		if operatorConfig.CISKubernetesBenchmarkEnabled {
			// Cache cluster-scoped resources such as Nodes
			cachedNamespaces = append(cachedNamespaces, "")
		}
		setupLog.Info("Constructing client cache", "namespaces", cachedNamespaces)
		options.NewCache = cache.MultiNamespacedCacheBuilder(cachedNamespaces)
	case etc.AllNamespaces:
		// Add support for AllNamespaces set in OPERATOR_NAMESPACE (e.g. `operators`)
		// and OPERATOR_TARGET_NAMESPACES left blank.
		setupLog.Info("Watching all namespaces")
	default:
		return fmt.Errorf("unrecognized install mode: %v", installMode)
	}

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

	configManager := trivyoperator.NewConfigManager(kubeClientset, operatorNamespace)
	err = configManager.EnsureDefault(context.Background())
	if err != nil {
		return err
	}

	trivyOperatorConfig, err := configManager.Read(context.Background())
	if err != nil {
		return err
	}

	objectResolver := kube.ObjectResolver{Client: mgr.GetClient()}
	limitChecker := controller.NewLimitChecker(operatorConfig, mgr.GetClient(), trivyOperatorConfig)
	logsReader := kube.NewLogsReader(kubeClientset)
	secretsReader := kube.NewSecretsReader(mgr.GetClient())

	if operatorConfig.VulnerabilityScannerEnabled {
		plugin, pluginContext, err := plugin.NewResolver().
			WithBuildInfo(buildInfo).
			WithNamespace(operatorNamespace).
			WithServiceAccountName(operatorConfig.ServiceAccount).
			WithConfig(trivyOperatorConfig).
			WithClient(mgr.GetClient()).
			GetVulnerabilityPlugin()
		if err != nil {
			return err
		}

		err = plugin.Init(pluginContext)
		if err != nil {
			return fmt.Errorf("initializing %s plugin: %w", pluginContext.GetName(), err)
		}

		if err = (&vulnerabilityreport.WorkloadController{
			Logger:         ctrl.Log.WithName("reconciler").WithName("vulnerabilityreport"),
			Config:         operatorConfig,
			ConfigData:     trivyOperatorConfig,
			Client:         mgr.GetClient(),
			ObjectResolver: objectResolver,
			LimitChecker:   limitChecker,
			LogsReader:     logsReader,
			SecretsReader:  secretsReader,
			Plugin:         plugin,
			PluginContext:  pluginContext,
			ReadWriter:     vulnerabilityreport.NewReadWriter(mgr.GetClient()),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup vulnerabilityreport reconciler: %w", err)
		}

		if operatorConfig.VulnerabilityScannerReportTTL != nil {
			if err = (&controller.TTLReportReconciler{
				Logger: ctrl.Log.WithName("reconciler").WithName("ttlreport"),
				Config: operatorConfig,
				Client: mgr.GetClient(),
				Clock:  ext.NewSystemClock(),
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("unable to setup TTLreport reconciler: %w", err)
			}
		}
	}

	if operatorConfig.ConfigAuditScannerEnabled {
		plugin, pluginContext, err := plugin.NewResolver().
			WithBuildInfo(buildInfo).
			WithNamespace(operatorNamespace).
			WithServiceAccountName(operatorConfig.ServiceAccount).
			WithConfig(trivyOperatorConfig).
			WithClient(mgr.GetClient()).
			GetConfigAuditPlugin()
		if err != nil {
			return err
		}

		err = plugin.Init(pluginContext)
		if err != nil {
			return fmt.Errorf("initializing %s plugin: %w", pluginContext.GetName(), err)
		}

		if err = (&controller.ConfigAuditReportReconciler{
			Logger:         ctrl.Log.WithName("reconciler").WithName("configauditreport"),
			Config:         operatorConfig,
			ConfigData:     trivyOperatorConfig,
			Client:         mgr.GetClient(),
			ObjectResolver: objectResolver,
			LimitChecker:   limitChecker,
			LogsReader:     logsReader,
			Plugin:         plugin,
			PluginContext:  pluginContext,
			ReadWriter:     configauditreport.NewReadWriter(mgr.GetClient()),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup configauditreport reconciler: %w", err)
		}

		if err = (&controller.PluginsConfigReconciler{
			Logger:        ctrl.Log.WithName("reconciler").WithName("pluginsconfig"),
			Config:        operatorConfig,
			Client:        mgr.GetClient(),
			Plugin:        plugin,
			PluginContext: pluginContext,
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup %T: %w", controller.PluginsConfigReconciler{}, err)
		}
	}

	if operatorConfig.CISKubernetesBenchmarkEnabled {
		if err = (&controller.CISKubeBenchReportReconciler{
			Logger:       ctrl.Log.WithName("reconciler").WithName("ciskubebenchreport"),
			Config:       operatorConfig,
			ConfigData:   trivyOperatorConfig,
			Client:       mgr.GetClient(),
			LogsReader:   logsReader,
			LimitChecker: limitChecker,
			ReadWriter:   kubebench.NewReadWriter(mgr.GetClient()),
			Plugin:       kubebench.NewKubeBenchPlugin(ext.NewSystemClock(), trivyOperatorConfig),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup ciskubebenchreport reconciler: %w", err)
		}
	}

	if operatorConfig.ConfigAuditScannerBuiltIn {
		setupLog.Info("Enabling built-in configuration audit scanner")
		if err = (&configauditreport.ResourceController{
			Logger:         ctrl.Log.WithName("resourcecontroller"),
			Config:         operatorConfig,
			ConfigData:     trivyOperatorConfig,
			Client:         mgr.GetClient(),
			ObjectResolver: objectResolver,
			ReadWriter:     configauditreport.NewReadWriter(mgr.GetClient()),
			BuildInfo:      buildInfo,
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup resource controller: %w", err)
		}
	}

	if operatorConfig.ClusterComplianceEnabled {
		logger := ctrl.Log.WithName("reconciler").WithName("clustercompliancereport")
		cc := &compliance.ClusterComplianceReportReconciler{
			Logger: logger,
			Client: mgr.GetClient(),
			Mgr:    compliance.NewMgr(mgr.GetClient(), logger, trivyOperatorConfig),
			Clock:  ext.NewSystemClock(),
		}
		if err := cc.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup clustercompliancereport reconciler: %w", err)
		}
	}
	setupLog.Info("Starting controllers manager")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("starting controllers manager: %w", err)
	}

	return nil
}
