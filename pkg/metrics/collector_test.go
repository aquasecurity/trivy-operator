package metrics

import (
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("ResourcesMetricsCollector", func() {
	var collector ResourcesMetricsCollector

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

		scheme := runtime.NewScheme()
		Expect(v1alpha1.AddToScheme(scheme)).To(Succeed())
		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithRuntimeObjects(vr1, vr2, vr3).
			Build()
		collector = ResourcesMetricsCollector{
			Client: client,
		}
	})

	It("should not have lint issues", func() {
		problems, err := testutil.CollectAndLint(collector)
		Expect(err).To(Succeed())
		Expect(problems).To(BeEmpty())
	})

	It("should produce correct metrics with cluster scope", func() {
		const expected = `
		  # HELP trivy_vulnerabilityreport_image_vulnerabilities Number of container image vulnerabilities
		  # TYPE trivy_vulnerabilityreport_image_vulnerabilities gauge
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Critical"} 2
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="High"} 0
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Low"} 0
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Medium"} 0
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Unknown"} 0
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Critical"} 4
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="High"} 7
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Low"} 0
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Medium"} 0
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Unknown"} 0
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",severity="Critical"} 0
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",severity="High"} 0
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",severity="Low"} 0
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",severity="Medium"} 0
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",severity="Unknown"} 0
		`
		Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_vulnerabilityreport_image_vulnerabilities")).
			To(Succeed())
	})

	It("should produce correct metrics from target namespaces", func() {
		collector.TargetNamespaces = "default,some-ns"
		const expected = `
		  # HELP trivy_vulnerabilityreport_image_vulnerabilities Number of container image vulnerabilities
		  # TYPE trivy_vulnerabilityreport_image_vulnerabilities gauge
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Critical"} 2
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="High"} 0
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Low"} 0
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Medium"} 0
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",severity="Unknown"} 0
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Critical"} 4
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="High"} 7
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Low"} 0
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Medium"} 0
		  trivy_vulnerabilityreport_image_vulnerabilities{image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",severity="Unknown"} 0
		`
		Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_vulnerabilityreport_image_vulnerabilities")).
			To(Succeed())
	})
})
