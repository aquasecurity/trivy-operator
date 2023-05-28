package operator_test

import (
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"context"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/compliance"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	ca "github.com/aquasecurity/trivy-operator/pkg/configauditreport/controller"
	"github.com/aquasecurity/trivy-operator/pkg/exposedsecretreport"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/infraassessment"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/jobs"
	"github.com/aquasecurity/trivy-operator/pkg/plugins"
	"github.com/aquasecurity/trivy-operator/pkg/plugins/trivy"
	"github.com/aquasecurity/trivy-operator/pkg/rbacassessment"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport/controller"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/yaml"
)

var (
	cfg       *rest.Config
	k8sClient client.Client // You'll be using this client in your tests.
	testEnv   *envtest.Environment
	ctx       context.Context
	cancel    context.CancelFunc
)

func TestAPIs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping env tests")
	}
	RegisterFailHandler(Fail)
	RunSpecs(t, "VulnerabilityReport Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "deploy", "helm", "crds")},
		ErrorIfCRDPathMissing: true,
	}
	testEnv.ControlPlaneStartTimeout = 60 * time.Second
	var err error
	// cfg is defined in this file globally.
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = v1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
	})
	Expect(err).ToNot(HaveOccurred())
	managerClient := k8sManager.GetClient()
	compatibleObjectMapper := &kube.CompatibleObjectMapper{}
	objectResolver := kube.NewObjectResolver(managerClient, compatibleObjectMapper)
	Expect(err).ToNot(HaveOccurred())

	config := etc.Config{
		Namespace:                     "default",
		TargetNamespaces:              "default",
		ConcurrentScanJobsLimit:       10,
		RbacAssessmentScannerEnabled:  true,
		InfraAssessmentScannerEnabled: true,
		ClusterComplianceEnabled:      true,
		InvokeClusterComplianceOnce:   true,
	}

	trivyOperatorConfig := trivyoperator.GetDefaultConfig()

	trivyOperatorConfig.Set(trivyoperator.KeyVulnerabilityScannerEnabled, "true")
	trivyOperatorConfig.Set(trivyoperator.KeyExposedSecretsScannerEnabled, "true")

	plugin, pluginContext, err := plugins.NewResolver().
		WithNamespace(config.Namespace).
		WithServiceAccountName(config.ServiceAccount).
		WithConfig(trivyOperatorConfig).
		WithClient(managerClient).
		WithObjectResolver(&objectResolver).
		GetVulnerabilityPlugin()
	Expect(err).ToNot(HaveOccurred())
	err = pluginContext.EnsureConfig(trivyoperator.PluginConfig{
		Data: map[string]string{
			"trivy.repository":   trivy.DefaultImageRepository,
			"trivy.tag":          "0.35.0",
			"trivy.mode":         string(trivy.Standalone),
			"trivy.slow":         "true",
			"trivy.dbRepository": trivy.DefaultDBRepository,
		},
	})
	Expect(err).ToNot(HaveOccurred())

	err = (&controller.WorkloadController{
		Logger:                  ctrl.Log.WithName("reconciler").WithName("vulnerabilityreport"),
		Config:                  config,
		Client:                  managerClient,
		ObjectResolver:          objectResolver,
		LimitChecker:            jobs.NewLimitChecker(config, managerClient, trivyOperatorConfig),
		SecretsReader:           kube.NewSecretsReader(managerClient),
		Plugin:                  plugin,
		PluginContext:           pluginContext,
		VulnerabilityReadWriter: vulnerabilityreport.NewReadWriter(&objectResolver),
		ExposedSecretReadWriter: exposedsecretreport.NewReadWriter(&objectResolver),
		SubmitScanJobChan:       make(chan controller.ScanJobRequest, config.ConcurrentScanJobsLimit),
		ResultScanJobChan:       make(chan controller.ScanJobResult, config.ConcurrentScanJobsLimit),
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	buildInfo := trivyoperator.BuildInfo{
		Version: "version",
		Commit:  "commit",
		Date:    "12/12/2020",
	}
	pluginca, _, err := plugins.NewResolver().WithBuildInfo(buildInfo).
		WithNamespace(config.Namespace).
		WithServiceAccountName(config.ServiceAccount).
		WithConfig(trivyOperatorConfig).
		WithClient(managerClient).
		WithObjectResolver(&objectResolver).
		GetConfigAuditPlugin()

	Expect(err).ToNot(HaveOccurred())

	err = (&ca.ResourceController{
		Logger:          ctrl.Log.WithName("resourcecontroller"),
		Config:          config,
		ConfigData:      trivyOperatorConfig,
		ObjectResolver:  objectResolver,
		PluginContext:   pluginContext,
		PluginInMemory:  pluginca,
		ReadWriter:      configauditreport.NewReadWriter(&objectResolver),
		RbacReadWriter:  rbacassessment.NewReadWriter(&objectResolver),
		InfraReadWriter: infraassessment.NewReadWriter(&objectResolver),
		BuildInfo:       buildInfo,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&operator.TTLReportReconciler{
		Logger:         ctrl.Log.WithName("reconciler").WithName("ttlreport"),
		Config:         config,
		Client:         k8sClient,
		PluginContext:  pluginContext,
		PluginInMemory: pluginca,
		Clock:          ext.NewSystemClock(),
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&compliance.ClusterComplianceReportReconciler{
		Logger: ctrl.Log.WithName("reconciler").WithName("compliance report"),
		Client: k8sClient,
		Config: config,
		Mgr:    compliance.NewMgr(k8sClient),
		Clock:  ext.NewSystemClock(),
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	go func() {
		defer GinkgoRecover()
		err = k8sManager.Start(ctx)
		Expect(err).NotTo(HaveOccurred())
	}()
})

var _ = AfterSuite(func() {
	cancel()
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

func loadResource(obj runtime.Object, filename string) error {
	yamlFile, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	return yaml.UnmarshalStrict(yamlFile, obj)
}
