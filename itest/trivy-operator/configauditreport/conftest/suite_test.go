package conftest

import (
	_ "embed"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"context"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-operator/itest/helper"
	"github.com/aquasecurity/trivy-operator/itest/trivy-operator/behavior"
	"github.com/aquasecurity/trivy-operator/pkg/operator"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/plugin/conftest"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	buildInfo = trivyoperator.BuildInfo{
		Version: "dev",
		Commit:  "none",
		Date:    "unknown",
	}
)

var (
	scheme     *runtime.Scheme
	kubeClient client.Client
	startCtx   context.Context
	stopFunc   context.CancelFunc
)

var (
	inputs behavior.Inputs
)

var (
	starboardCM *corev1.ConfigMap
	conftestCM  *corev1.ConfigMap

	//go:embed testdata/run_as_root.rego
	runAsRootPolicy string
	//go:embed testdata/service_with_external_ip.rego
	serviceWithExternalIPPolicy string
)

func TestIntegrationOperatorWithConftest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}
	RegisterFailHandler(Fail)
	RunSpecs(t, "Conftest")
}

var _ = BeforeSuite(func() {
	ctx := context.Background()

	operatorConfig, err := etc.GetOperatorConfig()
	Expect(err).ToNot(HaveOccurred())

	operatorConfig.Namespace = "trivy-system"
	operatorConfig.TargetNamespaces = "default"

	// Disable vulnerability scanner and CIS Benchmarks
	operatorConfig.VulnerabilityScannerEnabled = false
	operatorConfig.CISKubernetesBenchmarkEnabled = false

	// Disable built-in configuration scanner
	operatorConfig.ConfigAuditScannerBuiltIn = false
	operatorConfig.ConfigAuditScannerEnabled = true

	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(operatorConfig.LogDevMode)))

	kubeConfig, err := ctrl.GetConfig()
	Expect(err).ToNot(HaveOccurred())

	scheme = trivyoperator.NewScheme()
	kubeClient, err = client.New(kubeConfig, client.Options{
		Scheme: scheme,
	})
	Expect(err).ToNot(HaveOccurred())

	inputs = behavior.Inputs{
		AssertTimeout:         3 * time.Minute,
		PrimaryNamespace:      corev1.NamespaceDefault,
		PrimaryWorkloadPrefix: "wordpress",

		ConfigAuditReportsPlugin: conftest.Plugin,

		Client: kubeClient,
		Helper: helper.NewHelper(kubeClient),
	}

	starboardCM, err = createOrUpdateConfigMap(ctx, client.ObjectKey{
		Namespace: operatorConfig.Namespace,
		Name:      trivyoperator.ConfigMapName,
	},
		map[string]string{
			"configAuditReports.scanner": "Conftest",
		})
	Expect(err).ToNot(HaveOccurred())

	conftestCM, err = createOrUpdateConfigMap(ctx, client.ObjectKey{
		Namespace: operatorConfig.Namespace,
		Name:      trivyoperator.GetPluginConfigMapName("Conftest"),
	}, map[string]string{
		"conftest.imageRef": "docker.io/openpolicyagent/conftest:v0.30.0",

		"conftest.policy.runs_as_root.rego":              runAsRootPolicy,
		"conftest.policy.service_with_external_ip.rego":  serviceWithExternalIPPolicy,
		"conftest.policy.runs_as_root.kinds":             "Workload",
		"conftest.policy.service_with_external_ip.kinds": "Service",
	})
	Expect(err).ToNot(HaveOccurred())

	startCtx, stopFunc = context.WithCancel(ctx)

	go func() {
		defer GinkgoRecover()
		By("Starting Starboard operator")
		err = operator.Start(startCtx, buildInfo, operatorConfig)
		Expect(err).ToNot(HaveOccurred())
	}()

})

var _ = AfterSuite(func() {
	By("Stopping Starboard operator")
	stopFunc()
	err := kubeClient.Delete(context.Background(), starboardCM)
	Expect(err).ToNot(HaveOccurred())
	err = kubeClient.Delete(context.Background(), conftestCM)
	Expect(err).ToNot(HaveOccurred())
})

func createOrUpdateConfigMap(ctx context.Context, ref client.ObjectKey, data map[string]string) (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{}
	err := kubeClient.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, cm)
	if err != nil {
		if errors.IsNotFound(err) {
			cm = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: ref.Namespace,
					Name:      ref.Name,
				},
				Data: data,
			}
			err = kubeClient.Create(ctx, cm)
			return cm, err
		} else {
			return nil, err
		}
	}
	cm = cm.DeepCopy()
	cm.Data = data
	err = kubeClient.Update(ctx, cm)
	return cm, err
}
