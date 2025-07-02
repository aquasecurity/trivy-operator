package trivy_operator

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/aquasecurity/trivy-operator/pkg/operator"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/tests/itest/helper"
	"github.com/aquasecurity/trivy-operator/tests/itest/trivy-operator/behavior"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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

func TestTrivyOperator(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}
	RegisterFailHandler(Fail)
	RunSpecs(t, "Trivy Operator")
}

var _ = BeforeSuite(func() {
	operatorConfig, err := etc.GetOperatorConfig()
	Expect(err).ToNot(HaveOccurred())

	ApplyTestConfiguration(&operatorConfig)

	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(operatorConfig.LogDevMode)))

	kubeConfig, err := ctrl.GetConfig()
	Expect(err).ToNot(HaveOccurred())

	scheme = trivyoperator.NewScheme()
	kubeClient, err = client.New(kubeConfig, client.Options{
		Scheme: scheme,
	})
	Expect(err).ToNot(HaveOccurred())

	inputs = behavior.Inputs{
		AssertTimeout:         5 * time.Minute,
		PollingInterval:       5 * time.Second,
		PrimaryNamespace:      corev1.NamespaceDefault,
		PrimaryWorkloadPrefix: "wordpress",
		Client:                kubeClient,
		Helper:                helper.NewHelper(kubeClient),
	}

	startCtx, stopFunc = context.WithCancel(context.Background())

	go func() {
		defer GinkgoRecover()
		By("Starting Trivy operator")
		err = operator.Start(startCtx, buildInfo, operatorConfig)
		Expect(err).ToNot(HaveOccurred())
	}()

})

func ApplyTestConfiguration(operatorConfig *etc.Config) {
	// Default is 0. Set to 30 seconds for testing scan job TTL behavior.
	scanJobTTL := 30 * time.Second
	operatorConfig.ScanJobTTL = &scanJobTTL
}

var _ = AfterSuite(func() {
	By("Stopping Trivy operator")
	stopFunc()
})
