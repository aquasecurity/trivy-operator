package trivy_operator

import (
	"context"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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

// ensureCRDsInstalled checks if the required trivy-operator CRDs are installed
func ensureCRDsInstalled(c client.Client) error {
	requiredCRDs := []string{
		"configauditreports.aquasecurity.github.io",
		"vulnerabilityreports.aquasecurity.github.io",
		"clusterconfigauditreports.aquasecurity.github.io",
	}

	ctx := context.Background()
	for _, crdName := range requiredCRDs {
		crd := &apiextensionsv1.CustomResourceDefinition{}
		err := c.Get(ctx, types.NamespacedName{Name: crdName}, crd)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return fmt.Errorf("required CRD %s not found in cluster", crdName)
			}
			return err
		}
	}
	return nil
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

	// Ensure CRDs are installed before running tests
	By("Checking if trivy-operator CRDs are installed")
	err = ensureCRDsInstalled(kubeClient)
	if err != nil {
		Fail(fmt.Sprintf("CRDs are not installed in the cluster. Please install them first:\n"+
			"kubectl apply -f deploy/helm/crds/\n"+
			"Error: %v", err))
	}

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
