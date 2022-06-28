package metrics

import (
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("ResourcesMetricsCollector", func() {
	var collector ResourcesMetricsCollector
	var client *fake.ClientBuilder

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(v1alpha1.AddToScheme(scheme)).To(Succeed())
		client = fake.NewClientBuilder().WithScheme(scheme)
	})

	JustBeforeEach(func() {
		collector = ResourcesMetricsCollector{
			Client: client.Build(),
		}
	})

	AssertNoLintIssues := func() {
		It("should not have lint issues", func() {
			problems, err := testutil.CollectAndLint(collector)
			Expect(err).To(Succeed())
			Expect(problems).To(BeEmpty())
		})
	}

	Context("VulnerabilityReport", func() {
		BeforeEach(func() {
			vr1 := &v1alpha1.VulnerabilityReport{}
			vr1.Namespace = "default"
			vr1.Name = "replicaset-nginx-6d4cf56db6-nginx"
			vr1.Report.Registry.Server = "index.docker.io"
			vr1.Report.Artifact.Repository = "library/nginx"
			vr1.Report.Artifact.Tag = "1.16"
			vr1.Report.Summary.CriticalCount = 2

			vr2 := &v1alpha1.VulnerabilityReport{}
			vr2.Namespace = "some-ns"
			vr2.Name = "replicaset-app-d327abe3c4-proxy"
			vr2.Report.Registry.Server = "quay.io"
			vr2.Report.Artifact.Repository = "oauth2-proxy/oauth2-proxy"
			vr2.Report.Artifact.Tag = "v7.2.1"
			vr2.Report.Summary.CriticalCount = 4
			vr2.Report.Summary.HighCount = 7

			vr3 := &v1alpha1.VulnerabilityReport{}
			vr3.Namespace = "ingress-nginx"
			vr3.Name = "daemonset-ingress-nginx-controller-controller"
			vr3.Report.Registry.Server = "k8s.gcr.io"
			vr3.Report.Artifact.Repository = "ingress-nginx/controller"
			vr3.Report.Artifact.Digest = "sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8"

			client.WithRuntimeObjects(vr1, vr2, vr3)
		})

		AssertNoLintIssues()

		It("should produce correct metrics with cluster scope", func() {
			const expected = `
        # HELP trivy_image_vulnerabilities Number of container image vulnerabilities
        # TYPE trivy_image_vulnerabilities gauge
        trivy_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Critical"} 2
        trivy_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="High"} 0
        trivy_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Low"} 0
        trivy_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Medium"} 0
        trivy_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Unknown"} 0
        trivy_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Critical"} 4
        trivy_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="High"} 7
        trivy_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Low"} 0
        trivy_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Medium"} 0
        trivy_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Unknown"} 0
        trivy_image_vulnerabilities{image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",severity="Critical"} 0
        trivy_image_vulnerabilities{image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",severity="High"} 0
        trivy_image_vulnerabilities{image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",severity="Low"} 0
        trivy_image_vulnerabilities{image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",severity="Medium"} 0
        trivy_image_vulnerabilities{image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",severity="Unknown"} 0
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_image_vulnerabilities")).
				To(Succeed())
		})

		It("should produce correct metrics from target namespaces", func() {
			collector.TargetNamespaces = "default,some-ns"
			const expected = `
        # HELP trivy_image_vulnerabilities Number of container image vulnerabilities
        # TYPE trivy_image_vulnerabilities gauge
        trivy_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Critical"} 2
        trivy_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="High"} 0
        trivy_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Low"} 0
        trivy_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Medium"} 0
        trivy_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Unknown"} 0
        trivy_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Critical"} 4
        trivy_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="High"} 7
        trivy_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Low"} 0
        trivy_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Medium"} 0
        trivy_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Unknown"} 0
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_image_vulnerabilities")).
				To(Succeed())
		})
	})

	Context("ExposedSecretReport", func() {
		BeforeEach(func() {
			vr1 := &v1alpha1.ExposedSecretReport{}
			vr1.Namespace = "default"
			vr1.Name = "replicaset-nginx-6d4cf56db6-nginx"
			vr1.Report.Registry.Server = "index.docker.io"
			vr1.Report.Artifact.Repository = "library/nginx"
			vr1.Report.Artifact.Tag = "1.16"
			vr1.Report.Summary.CriticalCount = 2

			vr2 := &v1alpha1.ExposedSecretReport{}
			vr2.Namespace = "some-ns"
			vr2.Name = "replicaset-app-d327abe3c4-proxy"
			vr2.Report.Registry.Server = "quay.io"
			vr2.Report.Artifact.Repository = "oauth2-proxy/oauth2-proxy"
			vr2.Report.Artifact.Tag = "v7.2.1"
			vr2.Report.Summary.CriticalCount = 4
			vr2.Report.Summary.HighCount = 7

			vr3 := &v1alpha1.ExposedSecretReport{}
			vr3.Namespace = "ingress-nginx"
			vr3.Name = "daemonset-ingress-nginx-controller-controller"
			vr3.Report.Registry.Server = "k8s.gcr.io"
			vr3.Report.Artifact.Repository = "ingress-nginx/controller"
			vr3.Report.Artifact.Digest = "sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8"

			client.WithRuntimeObjects(vr1, vr2, vr3)
		})

		AssertNoLintIssues()

		It("should produce correct metrics with cluster scope", func() {
			const expected = `
        # HELP trivy_image_exposedsecrets Number of image exposed secrets
        # TYPE trivy_image_exposedsecrets gauge
        trivy_image_exposedsecrets{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Critical"} 2
        trivy_image_exposedsecrets{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="High"} 0
        trivy_image_exposedsecrets{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Low"} 0
        trivy_image_exposedsecrets{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Medium"} 0
        trivy_image_exposedsecrets{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Critical"} 4
        trivy_image_exposedsecrets{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="High"} 7
        trivy_image_exposedsecrets{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Low"} 0
        trivy_image_exposedsecrets{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Medium"} 0
        trivy_image_exposedsecrets{image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",severity="Critical"} 0
        trivy_image_exposedsecrets{image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",severity="High"} 0
        trivy_image_exposedsecrets{image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",severity="Low"} 0
        trivy_image_exposedsecrets{image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",severity="Medium"} 0
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_image_exposedsecrets")).
				To(Succeed())
		})

		It("should produce correct metrics from target namespaces", func() {
			collector.TargetNamespaces = "default,some-ns"
			const expected = `
        # HELP trivy_image_exposedsecrets Number of image exposed secrets
        # TYPE trivy_image_exposedsecrets gauge
        trivy_image_exposedsecrets{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Critical"} 2
        trivy_image_exposedsecrets{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="High"} 0
        trivy_image_exposedsecrets{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Low"} 0
        trivy_image_exposedsecrets{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Medium"} 0
        trivy_image_exposedsecrets{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Critical"} 4
        trivy_image_exposedsecrets{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="High"} 7
        trivy_image_exposedsecrets{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Low"} 0
        trivy_image_exposedsecrets{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Medium"} 0
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_image_exposedsecrets")).
				To(Succeed())
		})
	})

	Context("ConfigAuditReport", func() {
		BeforeEach(func() {
			car1 := &v1alpha1.ConfigAuditReport{}
			car1.Namespace = "default"
			car1.Name = "replicaset-nginx-6d4cf56db6"
			car1.Report.Summary.CriticalCount = 2
			car1.Report.Summary.LowCount = 9

			car2 := &v1alpha1.ConfigAuditReport{}
			car2.Namespace = "some-ns"
			car2.Name = "configmap-test"
			car2.Report.Summary.LowCount = 1

			car3 := &v1alpha1.ConfigAuditReport{}
			car3.Namespace = "vault-system"
			car3.Name = "replicaset-vault-agent-injector-65fd65bfb8"
			car3.Report.Summary.MediumCount = 4
			car3.Report.Summary.LowCount = 7

			client.WithRuntimeObjects(car1, car2, car3)
		})

		AssertNoLintIssues()

		It("should produce correct metrics with cluster scope", func() {
			const expected = `
        # HELP trivy_resource_configaudits Number of failing resource configuration auditing checks
        # TYPE trivy_resource_configaudits gauge
        trivy_resource_configaudits{name="configmap-test",namespace="some-ns",severity="Critical"} 0
        trivy_resource_configaudits{name="configmap-test",namespace="some-ns",severity="High"} 0
        trivy_resource_configaudits{name="configmap-test",namespace="some-ns",severity="Low"} 1
        trivy_resource_configaudits{name="configmap-test",namespace="some-ns",severity="Medium"} 0
        trivy_resource_configaudits{name="replicaset-nginx-6d4cf56db6",namespace="default",severity="Critical"} 2
        trivy_resource_configaudits{name="replicaset-nginx-6d4cf56db6",namespace="default",severity="High"} 0
        trivy_resource_configaudits{name="replicaset-nginx-6d4cf56db6",namespace="default",severity="Low"} 9
        trivy_resource_configaudits{name="replicaset-nginx-6d4cf56db6",namespace="default",severity="Medium"} 0
        trivy_resource_configaudits{name="replicaset-vault-agent-injector-65fd65bfb8",namespace="vault-system",severity="Critical"} 0
        trivy_resource_configaudits{name="replicaset-vault-agent-injector-65fd65bfb8",namespace="vault-system",severity="High"} 0
        trivy_resource_configaudits{name="replicaset-vault-agent-injector-65fd65bfb8",namespace="vault-system",severity="Low"} 7
        trivy_resource_configaudits{name="replicaset-vault-agent-injector-65fd65bfb8",namespace="vault-system",severity="Medium"} 4
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_resource_configaudits")).
				To(Succeed())
		})

		It("should produce correct metrics from target namespaces", func() {
			collector.TargetNamespaces = "default,some-ns"
			const expected = `
        # HELP trivy_resource_configaudits Number of failing resource configuration auditing checks
        # TYPE trivy_resource_configaudits gauge
        trivy_resource_configaudits{name="configmap-test",namespace="some-ns",severity="Critical"} 0
        trivy_resource_configaudits{name="configmap-test",namespace="some-ns",severity="High"} 0
        trivy_resource_configaudits{name="configmap-test",namespace="some-ns",severity="Low"} 1
        trivy_resource_configaudits{name="configmap-test",namespace="some-ns",severity="Medium"} 0
        trivy_resource_configaudits{name="replicaset-nginx-6d4cf56db6",namespace="default",severity="Critical"} 2
        trivy_resource_configaudits{name="replicaset-nginx-6d4cf56db6",namespace="default",severity="High"} 0
        trivy_resource_configaudits{name="replicaset-nginx-6d4cf56db6",namespace="default",severity="Low"} 9
        trivy_resource_configaudits{name="replicaset-nginx-6d4cf56db6",namespace="default",severity="Medium"} 0
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_resource_configaudits")).
				To(Succeed())
		})
	})
})
