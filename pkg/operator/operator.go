package operator

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/compliance"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport/controller"
	"github.com/aquasecurity/trivy-operator/pkg/exposedsecretreport"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/infraassessment"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/metrics"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/jobs"
	"github.com/aquasecurity/trivy-operator/pkg/plugins"
	"github.com/aquasecurity/trivy-operator/pkg/rbacassessment"
	"github.com/aquasecurity/trivy-operator/pkg/sbomreport"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
	vcontroller "github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport/controller"
	"github.com/aquasecurity/trivy-operator/pkg/webhook"
	"github.com/bluele/gcache"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
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
	installMode, operatorNamespace, targetNamespaces, err := operatorConfig.ResolveInstallMode()
	if err != nil {
		return fmt.Errorf("resolving install mode: %w", err)
	}
	setupLog.Info("Resolved install mode", "install mode", installMode,
		"operator namespace", operatorNamespace,
		"target namespaces", targetNamespaces,
		"exclude namespaces", operatorConfig.ExcludeNamespaces,
		"target workloads", operatorConfig.GetTargetWorkloads())

	// Set the default manager options.
	options := manager.Options{
		Scheme:                 trivyoperator.NewScheme(),
		MetricsBindAddress:     operatorConfig.MetricsBindAddress,
		HealthProbeBindAddress: operatorConfig.HealthProbeBindAddress,
		// Disable cache for resources used to look up image pull secrets to avoid
		// spinning up informers and to tighten operator RBAC permissions
		ClientDisableCacheFor: []client.Object{
			&corev1.Secret{},
			&corev1.ServiceAccount{},
		},
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
		options.Cache.Namespaces = []string{targetNamespaces[0]}
	case etc.SingleNamespace:
		// Add support for SingleNamespace set in OPERATOR_NAMESPACE (e.g. `trivy-operator`)
		// and OPERATOR_TARGET_NAMESPACES (e.g. `default`).
		cachedNamespaces := append(targetNamespaces, operatorNamespace)
		setupLog.Info("Constructing client cache", "namespaces", cachedNamespaces)
		options.Cache.Namespaces = cachedNamespaces
	case etc.MultiNamespace:
		// Add support for MultiNamespace set in OPERATOR_NAMESPACE (e.g. `trivy-operator`)
		// and OPERATOR_TARGET_NAMESPACES (e.g. `default,kube-system`).
		// Note that you may face performance issues when using this mode with a high number of namespaces.
		// More: https://godoc.org/github.com/kubernetes-sigs/controller-runtime/pkg/cache#MultiNamespacedCacheBuilder
		cachedNamespaces := append(targetNamespaces, operatorNamespace)
		setupLog.Info("Constructing client cache", "namespaces", cachedNamespaces)
		options.Cache.Namespaces = cachedNamespaces
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
	clientSet, err := kubernetes.NewForConfig(kubeConfig)
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

	configManager := trivyoperator.NewConfigManager(clientSet, operatorNamespace)
	err = configManager.EnsureDefault(context.Background())
	if err != nil {
		return err
	}
	compatibleObjectMapper, err := kube.InitCompatibleMgr()
	if err != nil {
		return err
	}
	trivyOperatorConfig, err := configManager.Read(context.Background())
	if err != nil {
		return err
	}
	objectResolver := kube.NewObjectResolver(mgr.GetClient(), compatibleObjectMapper)
	if err != nil {
		return err
	}
	limitChecker := jobs.NewLimitChecker(operatorConfig, mgr.GetClient(), trivyOperatorConfig)
	logsReader := kube.NewLogsReader(clientSet)
	secretsReader := kube.NewSecretsReader(mgr.GetClient())

	if operatorConfig.VulnerabilityScannerEnabled || operatorConfig.ExposedSecretScannerEnabled || operatorConfig.SbomGenerationEnable {

		trivyOperatorConfig.Set(trivyoperator.KeyVulnerabilityScannerEnabled, strconv.FormatBool(operatorConfig.VulnerabilityScannerEnabled))
		trivyOperatorConfig.Set(trivyoperator.KeyExposedSecretsScannerEnabled, strconv.FormatBool(operatorConfig.ExposedSecretScannerEnabled))
		trivyOperatorConfig.Set(trivyoperator.KeyGenerateSbom, strconv.FormatBool(operatorConfig.SbomGenerationEnable))

		plugin, pluginContext, err := plugins.NewResolver().
			WithBuildInfo(buildInfo).
			WithNamespace(operatorNamespace).
			WithServiceAccountName(operatorConfig.ServiceAccount).
			WithConfig(trivyOperatorConfig).
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

		if err = (&vcontroller.WorkloadController{
			Logger:         ctrl.Log.WithName("reconciler").WithName("vulnerabilityreport"),
			Config:         operatorConfig,
			ConfigData:     trivyOperatorConfig,
			Client:         mgr.GetClient(),
			ObjectResolver: objectResolver,
			LimitChecker:   limitChecker,
			SecretsReader:  secretsReader,
			Plugin:         plugin,
			PluginContext:  pluginContext,
			ServerHealthChecker: vcontroller.NewTrivyServerChecker(
				operatorConfig.TrivyServerHealthCheckCacheExpiration,
				gcache.New(1).LRU().Build(),
				vcontroller.NewHttpChecker()),
			VulnerabilityReadWriter: vulnerabilityreport.NewReadWriter(&objectResolver),
			ExposedSecretReadWriter: exposedsecretreport.NewReadWriter(&objectResolver),
			SbomReadWriter:          sbomreport.NewReadWriter(&objectResolver),
			SubmitScanJobChan:       make(chan vcontroller.ScanJobRequest, operatorConfig.ConcurrentScanJobsLimit),
			ResultScanJobChan:       make(chan vcontroller.ScanJobResult, operatorConfig.ConcurrentScanJobsLimit),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup vulnerabilityreport reconciler: %w", err)
		}

		if err = (&vcontroller.ScanJobController{
			Logger:                  ctrl.Log.WithName("reconciler").WithName("scan job"),
			Config:                  operatorConfig,
			ConfigData:              trivyOperatorConfig,
			ObjectResolver:          objectResolver,
			LogsReader:              logsReader,
			Plugin:                  plugin,
			PluginContext:           pluginContext,
			SbomReadWriter:          sbomreport.NewReadWriter(&objectResolver),
			VulnerabilityReadWriter: vulnerabilityreport.NewReadWriter(&objectResolver),
			ExposedSecretReadWriter: exposedsecretreport.NewReadWriter(&objectResolver),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup scan job  reconciler: %w", err)
		}
	}

	if operatorConfig.ScannerReportTTL != nil {
		_, pluginContext, err := plugins.NewResolver().
			WithBuildInfo(buildInfo).
			WithNamespace(operatorNamespace).
			WithServiceAccountName(operatorConfig.ServiceAccount).
			WithConfig(trivyOperatorConfig).
			WithClient(mgr.GetClient()).
			WithObjectResolver(&objectResolver).
			GetVulnerabilityPlugin()
		if err != nil {
			return err
		}
		ttlReconciler := &TTLReportReconciler{
			Logger: ctrl.Log.WithName("reconciler").WithName("ttlreport"),
			Config: operatorConfig,
			Client: mgr.GetClient(),
			Clock:  ext.NewSystemClock(),
		}
		if operatorConfig.ConfigAuditScannerEnabled {
			plugin, pluginContextCofig, err := plugins.NewResolver().WithBuildInfo(buildInfo).
				WithNamespace(operatorNamespace).
				WithServiceAccountName(operatorConfig.ServiceAccount).
				WithConfig(trivyOperatorConfig).
				WithClient(mgr.GetClient()).
				WithObjectResolver(&objectResolver).
				GetConfigAuditPlugin()
			if err != nil {
				return fmt.Errorf("initializing %s plugin: %w", pluginContext.GetName(), err)
			}
			ttlReconciler.PluginContext = pluginContextCofig
			ttlReconciler.PluginInMemory = plugin
		}
		if err = ttlReconciler.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup TTLreport reconciler: %w", err)
		}
	}

	if operatorConfig.WebhookBroadcastURL != "" {
		if err = (&webhook.WebhookReconciler{
			Logger: ctrl.Log.WithName("reconciler").WithName("webhookreporter"),
			Config: operatorConfig,
			Client: mgr.GetClient(),
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup webhookreporter: %w", err)
		}
	}

	if operatorConfig.ConfigAuditScannerEnabled {
		plugin, pluginContext, err := plugins.NewResolver().WithBuildInfo(buildInfo).
			WithNamespace(operatorNamespace).
			WithServiceAccountName(operatorConfig.ServiceAccount).
			WithConfig(trivyOperatorConfig).
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
		var gitVersion string
		if version, err := clientSet.ServerVersion(); err == nil {
			gitVersion = strings.TrimPrefix(version.GitVersion, "v")
		}
		setupLog.Info("Enabling built-in configuration audit scanner")
		if err = (&controller.ResourceController{
			Logger:          ctrl.Log.WithName("resourcecontroller"),
			Config:          operatorConfig,
			ConfigData:      trivyOperatorConfig,
			ObjectResolver:  objectResolver,
			PluginContext:   pluginContext,
			PluginInMemory:  plugin,
			ReadWriter:      configauditreport.NewReadWriter(&objectResolver),
			RbacReadWriter:  rbacassessment.NewReadWriter(&objectResolver),
			InfraReadWriter: infraassessment.NewReadWriter(&objectResolver),
			BuildInfo:       buildInfo,
			ClusterVersion:  gitVersion,
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup resource controller: %w", err)
		}
		if err = (&controller.PolicyConfigController{
			Logger:         ctrl.Log.WithName("resourcecontroller"),
			Config:         operatorConfig,
			ObjectResolver: objectResolver,
			PluginContext:  pluginContext,
			PluginInMemory: plugin,
			ClusterVersion: gitVersion,
		}).SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup resource controller: %w", err)
		}
		if operatorConfig.InfraAssessmentScannerEnabled {
			limitChecker := jobs.NewLimitChecker(operatorConfig, mgr.GetClient(), trivyOperatorConfig)
			if err = (&controller.NodeReconciler{
				Logger:          ctrl.Log.WithName("node-reconciler"),
				Config:          operatorConfig,
				ConfigData:      trivyOperatorConfig,
				ObjectResolver:  objectResolver,
				PluginContext:   pluginContext,
				PluginInMemory:  plugin,
				LimitChecker:    limitChecker,
				InfraReadWriter: infraassessment.NewReadWriter(&objectResolver),
				BuildInfo:       buildInfo,
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("unable to setup node collector controller: %w", err)
			}
			if err = (&controller.NodeCollectorJobController{
				Logger:          ctrl.Log.WithName("node-collectorontroller"),
				Config:          operatorConfig,
				ConfigData:      trivyOperatorConfig,
				ObjectResolver:  objectResolver,
				LogsReader:      logsReader,
				PluginContext:   pluginContext,
				PluginInMemory:  plugin,
				InfraReadWriter: infraassessment.NewReadWriter(&objectResolver),
				BuildInfo:       buildInfo,
			}).SetupWithManager(mgr); err != nil {
				return fmt.Errorf("unable to setup node collector controller: %w", err)
			}
		}
	}

	if operatorConfig.ClusterComplianceEnabled {
		logger := ctrl.Log.WithName("reconciler").WithName("clustercompliancereport")
		cc := &compliance.ClusterComplianceReportReconciler{
			Logger: logger,
			Config: operatorConfig,
			Client: mgr.GetClient(),
			Mgr:    compliance.NewMgr(mgr.GetClient()),
			Clock:  ext.NewSystemClock(),
		}
		if err := cc.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("unable to setup clustercompliancereport reconciler: %w", err)
		}
	}

	if operatorConfig.MetricsFindingsEnabled {
		logger := ctrl.Log.WithName("metrics")
		rmc := metrics.NewResourcesMetricsCollector(logger, operatorConfig, trivyOperatorConfig, mgr.GetClient())
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
