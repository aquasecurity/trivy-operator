package metrics

import (
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/labels"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"k8s.io/apimachinery/pkg/runtime"
	pointer "k8s.io/utils/pointer"
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
		var logger logr.Logger
		var config etc.Config
		var trvConfig = trivyoperator.GetDefaultConfig()
		collector = *NewResourcesMetricsCollector(logger, config, trvConfig, client.Build())
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
			vr1.Labels = labels.Set{
				trivyoperator.LabelResourceKind:  "ReplicaSet",
				trivyoperator.LabelResourceName:  "nginx-6d4cf56db6",
				trivyoperator.LabelContainerName: "nginx",
				"tier":                           "tier-1",
				"owner":                          "team-a",
				"app.kubernetes.io/name":         "my_name"}
			vr1.Report.Registry.Server = "index.docker.io"
			vr1.Report.Artifact.Repository = "library/nginx"
			vr1.Report.Artifact.Tag = "1.16"
			vr1.Report.Summary.CriticalCount = 2
			vr1.Report.Vulnerabilities = []v1alpha1.Vulnerability{
				{InstalledVersion: "2.28-10", FixedVersion: "2.28-11", Class: "os-pkgs", PackageType: "debian", PkgPath: "ab", Resource: "libc-bin", Severity: v1alpha1.SeverityCritical, VulnerabilityID: "CVE-VR1-CRITICAL-1", Title: "VR1 Critical vulnerability 1", Score: pointer.Float64(8.5)},
				{InstalledVersion: "1.19.7", Class: "os-pkgs", PackageType: "debian", PkgPath: "ab", Resource: "dppkg", Severity: v1alpha1.SeverityCritical, VulnerabilityID: "CVE-VR1-CRITICAL-2", Title: "VR1 Critical vulnerability 2", Score: pointer.Float64(8.3)},
			}

			vr2 := &v1alpha1.VulnerabilityReport{}
			vr2.Namespace = "some-ns"
			vr2.Name = "replicaset-app-d327abe3c4-proxy"
			vr2.Labels = labels.Set{
				trivyoperator.LabelResourceKind:  "ReplicaSet",
				trivyoperator.LabelResourceName:  "app-d327abe3c4",
				trivyoperator.LabelContainerName: "proxy"}
			vr2.Report.Registry.Server = "quay.io"
			vr2.Report.Artifact.Repository = "oauth2-proxy/oauth2-proxy"
			vr2.Report.Artifact.Tag = "v7.2.1"
			vr2.Report.Summary.CriticalCount = 4
			vr2.Report.Summary.HighCount = 7
			vr2.Report.Vulnerabilities = []v1alpha1.Vulnerability{
				{InstalledVersion: "1.2.11-r3", Class: "os-pkgs", PackageType: "debian", PkgPath: "ab", Resource: "zlib", Severity: v1alpha1.SeverityCritical, VulnerabilityID: "CVE-VR2-CRITICAL-1", Title: "VR2 Critical vulnerability 1", Score: pointer.Float64(7.5)},
				{InstalledVersion: "1.34.1-r3", Class: "os-pkgs", PackageType: "debian", PkgPath: "ab", Resource: "ssl_client", Severity: v1alpha1.SeverityCritical, VulnerabilityID: "CVE-VR2-CRITICAL-2", Title: "VR2 Critical vulnerability 2", Score: pointer.Float64(8.7)},
				{InstalledVersion: "1.2.11-r3", Class: "os-pkgs", PackageType: "debian", PkgPath: "ab", Resource: "zlib", Severity: v1alpha1.SeverityCritical, VulnerabilityID: "CVE-VR2-CRITICAL-3", Title: "VR2 Critical vulnerability 3", Score: pointer.Float64(8.5)},
				{InstalledVersion: "1.1.1l-r7", Class: "os-pkgs", PackageType: "debian", PkgPath: "ab", Resource: "libssl1.1", Severity: v1alpha1.SeverityCritical, VulnerabilityID: "CVE-VR2-CRITICAL-4", Title: "VR2 Critical vulnerability 4", Score: pointer.Float64(9.5)},
				{InstalledVersion: "v1.9.0", Class: "os-pkgs", PackageType: "debian", PkgPath: "ab", Resource: "golang.org/prometheus/client_golang", Severity: v1alpha1.SeverityHigh, VulnerabilityID: "CVE-VR2-HIGH-1", Title: "VR2 High vulnerability 1", Score: pointer.Float64(7)},
				{InstalledVersion: "v0.0.0-20210711020723-a769d52b0f97", Class: "os-pkgs", PackageType: "debian", PkgPath: "ab", Resource: "golang.org/x/crypto", Severity: v1alpha1.SeverityHigh, VulnerabilityID: "CVE-VR2-HIGH-2", Title: "VR2 High vulnerability 2", Score: pointer.Float64(6.7)},
				{InstalledVersion: "v0.0.0-20210226172049-e18ecbb05110", Class: "os-pkgs", PackageType: "debian", PkgPath: "ab", Resource: "golang.org/x/net", Severity: v1alpha1.SeverityHigh, VulnerabilityID: "CVE-VR2-HIGH-3", Title: "VR2 High vulnerability 3", Score: pointer.Float64(7.1)},
				{InstalledVersion: "v0.3.3", Class: "os-pkgs", PackageType: "debian", PkgPath: "ab", Resource: "golang.org/x/text", Severity: v1alpha1.SeverityHigh, VulnerabilityID: "CVE-VR2-HIGH-4", Title: "VR2 High vulnerability 4", Score: pointer.Float64(7)},
				{InstalledVersion: "1.2.11-r3", Class: "os-pkgs", PackageType: "debian", PkgPath: "ab", Resource: "zlib", Severity: v1alpha1.SeverityHigh, VulnerabilityID: "CVE-VR2-HIGH-5", Title: "VR2 High vulnerability 5", Score: pointer.Float64(7)},
				{InstalledVersion: "1.34.1-r3", Class: "os-pkgs", PackageType: "debian", PkgPath: "ab", Resource: "busybox", Severity: v1alpha1.SeverityHigh, VulnerabilityID: "CVE-VR2-HIGH-6", Title: "VR2 High vulnerability 6", Score: pointer.Float64(6)},
				{InstalledVersion: "1.1.1l-r7", Class: "os-pkgs", PackageType: "debian", PkgPath: "ab", Resource: "libssl1.1", Severity: v1alpha1.SeverityHigh, VulnerabilityID: "CVE-VR2-HIGH-7", Title: "VR2 High vulnerability 7", Score: pointer.Float64(6.4)},
			}

			vr3 := &v1alpha1.VulnerabilityReport{}
			vr3.Namespace = "ingress-nginx"
			vr3.Name = "daemonset-ingress-nginx-controller-controller"
			vr3.Labels = labels.Set{
				trivyoperator.LabelResourceKind:  "DaemonSet",
				trivyoperator.LabelResourceName:  "ingress-nginx-controller",
				trivyoperator.LabelContainerName: "controller"}
			vr3.Report.Registry.Server = "k8s.gcr.io"
			vr3.Report.Artifact.Repository = "ingress-nginx/controller"
			vr3.Report.Artifact.Digest = "sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8"
			vr3.Report.Summary.CriticalCount = 1
			vr3.Report.Vulnerabilities = []v1alpha1.Vulnerability{
				{InstalledVersion: "1.19.7", Class: "os-pkgs", PackageType: "debian", PkgPath: "ab", Resource: "dppkg", Severity: v1alpha1.SeverityCritical, VulnerabilityID: "CVE-VR3-CRITICAL-1", Title: "VR3 Critical vulnerability 1", Score: pointer.Float64(8.4)},
			}

			client.WithRuntimeObjects(vr1, vr2, vr3)
		})

		AssertNoLintIssues()

		It("should produce correct metrics with cluster scope", func() {
			const expected = `
		# HELP trivy_image_vulnerabilities Number of container image vulnerabilities
		# TYPE trivy_image_vulnerabilities gauge
		trivy_image_vulnerabilities{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Critical"} 2
		trivy_image_vulnerabilities{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="High"} 0
		trivy_image_vulnerabilities{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Low"} 0
		trivy_image_vulnerabilities{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Medium"} 0
		trivy_image_vulnerabilities{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Unknown"} 0
		trivy_image_vulnerabilities{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical"} 4
		trivy_image_vulnerabilities{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High"} 7
		trivy_image_vulnerabilities{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Low"} 0
		trivy_image_vulnerabilities{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Medium"} 0
		trivy_image_vulnerabilities{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Unknown"} 0
		trivy_image_vulnerabilities{container_name="controller",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="Critical"} 1
		trivy_image_vulnerabilities{container_name="controller",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="High"} 0
		trivy_image_vulnerabilities{container_name="controller",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="Low"} 0
		trivy_image_vulnerabilities{container_name="controller",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="Medium"} 0
		trivy_image_vulnerabilities{container_name="controller",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="Unknown"} 0
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_image_vulnerabilities")).
				To(Succeed())
		})

		It("should produce correct metrics from target namespaces", func() {
			collector.TargetNamespaces = "default,some-ns"
			const expected = `
		# HELP trivy_image_vulnerabilities Number of container image vulnerabilities
		# TYPE trivy_image_vulnerabilities gauge
		trivy_image_vulnerabilities{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Critical"} 2
		trivy_image_vulnerabilities{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="High"} 0
		trivy_image_vulnerabilities{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Low"} 0
		trivy_image_vulnerabilities{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Medium"} 0
		trivy_image_vulnerabilities{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Unknown"} 0
		trivy_image_vulnerabilities{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical"} 4
		trivy_image_vulnerabilities{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High"} 7
		trivy_image_vulnerabilities{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Low"} 0
		trivy_image_vulnerabilities{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Medium"} 0
		trivy_image_vulnerabilities{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Unknown"} 0
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_image_vulnerabilities")).
				To(Succeed())
		})
		It("should produce correct metrics with cluster scope with MetricsVulnerabilityId option enabled", func() {
			collector.Config.MetricsVulnerabilityId = true
			const expected = `
		# HELP trivy_vulnerability_id Number of container image vulnerabilities group by vulnerability id
		# TYPE trivy_vulnerability_id gauge
		trivy_vulnerability_id{class="os-pkgs",container_name="nginx",fixed_version="2.28-11",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",installed_version="2.28-10",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",package_type="debian",pkg_path="ab",resource="libc-bin",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Critical",vuln_id="CVE-VR1-CRITICAL-1",vuln_score="8.5",vuln_title="VR1 Critical vulnerability 1"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="nginx",fixed_version="",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",installed_version="1.19.7",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",package_type="debian",pkg_path="ab",resource="dppkg",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Critical",vuln_id="CVE-VR1-CRITICAL-2",vuln_score="8.3",vuln_title="VR1 Critical vulnerability 2"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.2.11-r3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="zlib",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical",vuln_id="CVE-VR2-CRITICAL-1",vuln_score="7.5",vuln_title="VR2 Critical vulnerability 1"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.34.1-r3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="ssl_client",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical",vuln_id="CVE-VR2-CRITICAL-2",vuln_score="8.7",vuln_title="VR2 Critical vulnerability 2"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.2.11-r3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="zlib",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical",vuln_id="CVE-VR2-CRITICAL-3",vuln_score="8.5",vuln_title="VR2 Critical vulnerability 3"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.1.1l-r7",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="libssl1.1",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical",vuln_id="CVE-VR2-CRITICAL-4",vuln_score="9.5",vuln_title="VR2 Critical vulnerability 4"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="v1.9.0",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="golang.org/prometheus/client_golang",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-1",vuln_score="7",vuln_title="VR2 High vulnerability 1"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="v0.0.0-20210711020723-a769d52b0f97",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="golang.org/x/crypto",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-2",vuln_score="6.7",vuln_title="VR2 High vulnerability 2"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="v0.0.0-20210226172049-e18ecbb05110",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="golang.org/x/net",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-3",vuln_score="7.1",vuln_title="VR2 High vulnerability 3"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="v0.3.3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="golang.org/x/text",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-4",vuln_score="7",vuln_title="VR2 High vulnerability 4"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.2.11-r3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="zlib",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-5",vuln_score="7",vuln_title="VR2 High vulnerability 5"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.34.1-r3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="busybox",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-6",vuln_score="6",vuln_title="VR2 High vulnerability 6"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.1.1l-r7",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="libssl1.1",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-7",vuln_score="6.4",vuln_title="VR2 High vulnerability 7"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="controller",fixed_version="",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",installed_version="1.19.7",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",package_type="debian",pkg_path="ab",resource="dppkg",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="Critical",vuln_id="CVE-VR3-CRITICAL-1",vuln_score="8.4",vuln_title="VR3 Critical vulnerability 1"} 1
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_vulnerability_id")).
				To(Succeed())
		})
		It("should produce correct metrics from target namespaces with MetricsVulnerabilityId option enabled", func() {
			collector.Config.MetricsVulnerabilityId = true
			collector.TargetNamespaces = "default,some-ns"
			const expected = `
		# HELP trivy_vulnerability_id Number of container image vulnerabilities group by vulnerability id
		# TYPE trivy_vulnerability_id gauge
		trivy_vulnerability_id{class="os-pkgs",container_name="nginx",fixed_version="2.28-11",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",installed_version="2.28-10",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",package_type="debian",pkg_path="ab",resource="libc-bin",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Critical",vuln_id="CVE-VR1-CRITICAL-1",vuln_score="8.5",vuln_title="VR1 Critical vulnerability 1"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="nginx",fixed_version="",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",installed_version="1.19.7",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",package_type="debian",pkg_path="ab",resource="dppkg",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Critical",vuln_id="CVE-VR1-CRITICAL-2",vuln_score="8.3",vuln_title="VR1 Critical vulnerability 2"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.2.11-r3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="zlib",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical",vuln_id="CVE-VR2-CRITICAL-1",vuln_score="7.5",vuln_title="VR2 Critical vulnerability 1"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.34.1-r3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="ssl_client",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical",vuln_id="CVE-VR2-CRITICAL-2",vuln_score="8.7",vuln_title="VR2 Critical vulnerability 2"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.2.11-r3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="zlib",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical",vuln_id="CVE-VR2-CRITICAL-3",vuln_score="8.5",vuln_title="VR2 Critical vulnerability 3"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.1.1l-r7",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="libssl1.1",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical",vuln_id="CVE-VR2-CRITICAL-4",vuln_score="9.5",vuln_title="VR2 Critical vulnerability 4"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="v1.9.0",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="golang.org/prometheus/client_golang",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-1",vuln_score="7",vuln_title="VR2 High vulnerability 1"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="v0.0.0-20210711020723-a769d52b0f97",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="golang.org/x/crypto",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-2",vuln_score="6.7",vuln_title="VR2 High vulnerability 2"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="v0.0.0-20210226172049-e18ecbb05110",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="golang.org/x/net",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-3",vuln_score="7.1",vuln_title="VR2 High vulnerability 3"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="v0.3.3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="golang.org/x/text",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-4",vuln_score="7",vuln_title="VR2 High vulnerability 4"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.2.11-r3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="zlib",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-5",vuln_score="7",vuln_title="VR2 High vulnerability 5"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.34.1-r3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="busybox",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-6",vuln_score="6",vuln_title="VR2 High vulnerability 6"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.1.1l-r7",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="libssl1.1",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-7",vuln_score="6.4",vuln_title="VR2 High vulnerability 7"} 1
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_vulnerability_id")).
				To(Succeed())
		})
		It("should produce correct metrics with MetricsVulnerabilityId option enabled and configured labels included using the correct prefix", func() {
			collector.Config.MetricsVulnerabilityId = true
			collector.Set(trivyoperator.KeyReportResourceLabels, "tier,ssot")
			collector.Set(trivyoperator.KeyMetricsResourceLabelsPrefix, "custom_prefix_")
			collector.metricDescriptors = buildMetricDescriptors(collector.ConfigData) // Force rebuild metricDescriptors again
			const expected = `
		# HELP trivy_vulnerability_id Number of container image vulnerabilities group by vulnerability id
		# TYPE trivy_vulnerability_id gauge
		trivy_vulnerability_id{class="os-pkgs",container_name="nginx",custom_prefix_ssot="",custom_prefix_tier="tier-1",fixed_version="2.28-11",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",installed_version="2.28-10",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",package_type="debian",pkg_path="ab",resource="libc-bin",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Critical",vuln_id="CVE-VR1-CRITICAL-1",vuln_score="8.5",vuln_title="VR1 Critical vulnerability 1"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="nginx",custom_prefix_ssot="",custom_prefix_tier="tier-1",fixed_version="",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",installed_version="1.19.7",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",package_type="debian",pkg_path="ab",resource="dppkg",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Critical",vuln_id="CVE-VR1-CRITICAL-2",vuln_score="8.3",vuln_title="VR1 Critical vulnerability 2"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",custom_prefix_ssot="",custom_prefix_tier="",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.2.11-r3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="zlib",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical",vuln_id="CVE-VR2-CRITICAL-1",vuln_score="7.5",vuln_title="VR2 Critical vulnerability 1"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",custom_prefix_ssot="",custom_prefix_tier="",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.34.1-r3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="ssl_client",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical",vuln_id="CVE-VR2-CRITICAL-2",vuln_score="8.7",vuln_title="VR2 Critical vulnerability 2"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",custom_prefix_ssot="",custom_prefix_tier="",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.2.11-r3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="zlib",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical",vuln_id="CVE-VR2-CRITICAL-3",vuln_score="8.5",vuln_title="VR2 Critical vulnerability 3"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",custom_prefix_ssot="",custom_prefix_tier="",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.1.1l-r7",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="libssl1.1",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical",vuln_id="CVE-VR2-CRITICAL-4",vuln_score="9.5",vuln_title="VR2 Critical vulnerability 4"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",custom_prefix_ssot="",custom_prefix_tier="",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="v1.9.0",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="golang.org/prometheus/client_golang",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-1",vuln_score="7",vuln_title="VR2 High vulnerability 1"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",custom_prefix_ssot="",custom_prefix_tier="",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="v0.0.0-20210711020723-a769d52b0f97",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="golang.org/x/crypto",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-2",vuln_score="6.7",vuln_title="VR2 High vulnerability 2"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",custom_prefix_ssot="",custom_prefix_tier="",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="v0.0.0-20210226172049-e18ecbb05110",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="golang.org/x/net",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-3",vuln_score="7.1",vuln_title="VR2 High vulnerability 3"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",custom_prefix_ssot="",custom_prefix_tier="",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="v0.3.3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="golang.org/x/text",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-4",vuln_score="7",vuln_title="VR2 High vulnerability 4"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",custom_prefix_ssot="",custom_prefix_tier="",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.2.11-r3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="zlib",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-5",vuln_score="7",vuln_title="VR2 High vulnerability 5"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",custom_prefix_ssot="",custom_prefix_tier="",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.34.1-r3",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="busybox",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-6",vuln_score="6",vuln_title="VR2 High vulnerability 6"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="proxy",custom_prefix_ssot="",custom_prefix_tier="",fixed_version="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",installed_version="1.1.1l-r7",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",package_type="debian",pkg_path="ab",resource="libssl1.1",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High",vuln_id="CVE-VR2-HIGH-7",vuln_score="6.4",vuln_title="VR2 High vulnerability 7"} 1
		trivy_vulnerability_id{class="os-pkgs",container_name="controller",custom_prefix_ssot="",custom_prefix_tier="",fixed_version="",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",installed_version="1.19.7",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",package_type="debian",pkg_path="ab",resource="dppkg",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="Critical",vuln_id="CVE-VR3-CRITICAL-1",vuln_score="8.4",vuln_title="VR3 Critical vulnerability 1"} 1
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_vulnerability_id")).
				To(Succeed())
		})
		It("should produce correct metrics with configured labels included using the correct prefix", func() {
			collector.Set(trivyoperator.KeyReportResourceLabels, "tier,ssot")
			collector.Set(trivyoperator.KeyMetricsResourceLabelsPrefix, "custom_prefix_")
			collector.metricDescriptors = buildMetricDescriptors(collector.ConfigData) // Force rebuild metricDescriptors again
			const expected = `
		# HELP trivy_image_vulnerabilities Number of container image vulnerabilities
		# TYPE trivy_image_vulnerabilities gauge
		trivy_image_vulnerabilities{container_name="nginx",custom_prefix_ssot="",custom_prefix_tier="tier-1",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Critical"} 2
		trivy_image_vulnerabilities{container_name="nginx",custom_prefix_ssot="",custom_prefix_tier="tier-1",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="High"} 0
		trivy_image_vulnerabilities{container_name="nginx",custom_prefix_ssot="",custom_prefix_tier="tier-1",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Low"} 0
		trivy_image_vulnerabilities{container_name="nginx",custom_prefix_ssot="",custom_prefix_tier="tier-1",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Medium"} 0
		trivy_image_vulnerabilities{container_name="nginx",custom_prefix_ssot="",custom_prefix_tier="tier-1",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Unknown"} 0
		trivy_image_vulnerabilities{container_name="proxy",custom_prefix_ssot="",custom_prefix_tier="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical"} 4
		trivy_image_vulnerabilities{container_name="proxy",custom_prefix_ssot="",custom_prefix_tier="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High"} 7
		trivy_image_vulnerabilities{container_name="proxy",custom_prefix_ssot="",custom_prefix_tier="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Low"} 0
		trivy_image_vulnerabilities{container_name="proxy",custom_prefix_ssot="",custom_prefix_tier="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Medium"} 0
		trivy_image_vulnerabilities{container_name="proxy",custom_prefix_ssot="",custom_prefix_tier="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Unknown"} 0
		trivy_image_vulnerabilities{container_name="controller",custom_prefix_ssot="",custom_prefix_tier="",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="Critical"} 1
		trivy_image_vulnerabilities{container_name="controller",custom_prefix_ssot="",custom_prefix_tier="",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="High"} 0
		trivy_image_vulnerabilities{container_name="controller",custom_prefix_ssot="",custom_prefix_tier="",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="Low"} 0
		trivy_image_vulnerabilities{container_name="controller",custom_prefix_ssot="",custom_prefix_tier="",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="Medium"} 0
		trivy_image_vulnerabilities{container_name="controller",custom_prefix_ssot="",custom_prefix_tier="",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="Unknown"} 0
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_image_vulnerabilities")).
				To(Succeed())
		})
		It("should produce correct metrics with configured labels included using the correct prefix and sanitized the invalid metric label", func() {
			collector.Set(trivyoperator.KeyReportResourceLabels, "app.kubernetes.io/name")
			collector.Set(trivyoperator.KeyMetricsResourceLabelsPrefix, "custom_prefix_")
			collector.metricDescriptors = buildMetricDescriptors(collector.ConfigData) // Force rebuild metricDescriptors again
			const expected = `
		# HELP trivy_image_vulnerabilities Number of container image vulnerabilities
		# TYPE trivy_image_vulnerabilities gauge
		trivy_image_vulnerabilities{container_name="nginx",custom_prefix_app_kubernetes_io_name="my_name",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Critical"} 2
		trivy_image_vulnerabilities{container_name="nginx",custom_prefix_app_kubernetes_io_name="my_name",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="High"} 0
		trivy_image_vulnerabilities{container_name="nginx",custom_prefix_app_kubernetes_io_name="my_name",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Low"} 0
		trivy_image_vulnerabilities{container_name="nginx",custom_prefix_app_kubernetes_io_name="my_name",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Medium"} 0
		trivy_image_vulnerabilities{container_name="nginx",custom_prefix_app_kubernetes_io_name="my_name",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Unknown"} 0
		trivy_image_vulnerabilities{container_name="proxy",custom_prefix_app_kubernetes_io_name="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical"} 4
		trivy_image_vulnerabilities{container_name="proxy",custom_prefix_app_kubernetes_io_name="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High"} 7
		trivy_image_vulnerabilities{container_name="proxy",custom_prefix_app_kubernetes_io_name="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Low"} 0
		trivy_image_vulnerabilities{container_name="proxy",custom_prefix_app_kubernetes_io_name="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Medium"} 0
		trivy_image_vulnerabilities{container_name="proxy",custom_prefix_app_kubernetes_io_name="",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Unknown"} 0
		trivy_image_vulnerabilities{container_name="controller",custom_prefix_app_kubernetes_io_name="",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="Critical"} 1
		trivy_image_vulnerabilities{container_name="controller",custom_prefix_app_kubernetes_io_name="",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="High"} 0
		trivy_image_vulnerabilities{container_name="controller",custom_prefix_app_kubernetes_io_name="",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="Low"} 0
		trivy_image_vulnerabilities{container_name="controller",custom_prefix_app_kubernetes_io_name="",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="Medium"} 0
		trivy_image_vulnerabilities{container_name="controller",custom_prefix_app_kubernetes_io_name="",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="Unknown"} 0
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_image_vulnerabilities")).
				To(Succeed())
		})
	})

	Context("ExposedSecretReport", func() {
		BeforeEach(func() {
			sr1 := &v1alpha1.ExposedSecretReport{}
			sr1.Namespace = "default"
			sr1.Name = "replicaset-nginx-6d4cf56db6-nginx"
			sr1.Labels = labels.Set{
				trivyoperator.LabelResourceKind:  "ReplicaSet",
				trivyoperator.LabelResourceName:  "nginx-6d4cf56db6",
				trivyoperator.LabelContainerName: "nginx"}
			sr1.Report.Registry.Server = "index.docker.io"
			sr1.Report.Artifact.Repository = "library/nginx"
			sr1.Report.Artifact.Tag = "1.16"
			sr1.Report.Summary.CriticalCount = 2
			sr1.Report.Secrets = []v1alpha1.ExposedSecret{
				{Target: "/etc/apt/s3auth.conf", Category: "AWS", RuleID: "aws-access-key-id", Title: "AWS Access Key ID", Severity: v1alpha1.SeverityCritical},
				{Target: "/app/config/secret.yaml", Category: "Stripe", RuleID: "stripe-secret-token", Title: "Stripe", Severity: v1alpha1.SeverityCritical},
			}

			sr2 := &v1alpha1.ExposedSecretReport{}
			sr2.Namespace = "some-ns"
			sr2.Name = "replicaset-app-d327abe3c4-proxy"
			sr2.Labels = labels.Set{
				trivyoperator.LabelResourceKind:  "ReplicaSet",
				trivyoperator.LabelResourceName:  "app-d327abe3c4",
				trivyoperator.LabelContainerName: "proxy"}
			sr2.Report.Registry.Server = "quay.io"
			sr2.Report.Artifact.Repository = "oauth2-proxy/oauth2-proxy"
			sr2.Report.Artifact.Tag = "v7.2.1"
			sr2.Report.Summary.CriticalCount = 4
			sr2.Report.Summary.HighCount = 3
			sr2.Report.Secrets = []v1alpha1.ExposedSecret{
				{Target: "/etc/apt/s3auth.conf", Category: "AWS", RuleID: "aws-access-key-id", Title: "AWS Access Key ID", Severity: v1alpha1.SeverityCritical},
				{Target: "/etc/apt/s3auth.conf", Category: "AWS", RuleID: "aws-access-key-id", Title: "AWS Access Key ID", Severity: v1alpha1.SeverityCritical},
				{Target: "/etc/apt/s3auth.conf", Category: "AWS", RuleID: "aws-secret-access-key", Title: "AWS Secret Access Key", Severity: v1alpha1.SeverityCritical},
				{Target: "/app/config/secret.yaml", Category: "Stripe", RuleID: "stripe-secret-token", Title: "Stripe", Severity: v1alpha1.SeverityCritical},
				{Target: "/app/config/secret.yaml", Category: "GitHub", RuleID: "github-pat", Title: "GitHub Personal Access Token", Severity: v1alpha1.SeverityCritical},
				{Target: "/app2/config/secret.yaml", Category: "Shopify", RuleID: "shopify-token", Title: "Shopify token", Severity: v1alpha1.SeverityHigh},
				{Target: "/app3/config/secret.yaml", Category: "PyPI", RuleID: "pypi-upload-token", Title: "PyPI upload token", Severity: v1alpha1.SeverityHigh},
				{Target: "/app4/config/secret.yaml", Category: "Alibaba", RuleID: "alibaba-access-key-id", Title: "Alibaba AccessKey ID", Severity: v1alpha1.SeverityHigh},
			}

			sr3 := &v1alpha1.ExposedSecretReport{}
			sr3.Namespace = "ingress-nginx"
			sr3.Name = "daemonset-ingress-nginx-controller-controller"
			sr3.Labels = labels.Set{
				trivyoperator.LabelResourceKind:  "DaemonSet",
				trivyoperator.LabelResourceName:  "ingress-nginx-controller",
				trivyoperator.LabelContainerName: "controller"}
			sr3.Report.Registry.Server = "k8s.gcr.io"
			sr3.Report.Artifact.Repository = "ingress-nginx/controller"
			sr3.Report.Artifact.Digest = "sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8"
			sr3.Report.Secrets = []v1alpha1.ExposedSecret{}

			client.WithRuntimeObjects(sr1, sr2, sr3)
		})

		AssertNoLintIssues()

		It("should produce correct metrics with cluster scope", func() {
			const expected = `
        # HELP trivy_image_exposedsecrets Number of image exposed secrets
        # TYPE trivy_image_exposedsecrets gauge
        trivy_image_exposedsecrets{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Critical"} 2
        trivy_image_exposedsecrets{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="High"} 0
        trivy_image_exposedsecrets{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Low"} 0
        trivy_image_exposedsecrets{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Medium"} 0
        trivy_image_exposedsecrets{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical"} 4
        trivy_image_exposedsecrets{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High"} 3
        trivy_image_exposedsecrets{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Low"} 0
        trivy_image_exposedsecrets{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Medium"} 0
        trivy_image_exposedsecrets{container_name="controller",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="Critical"} 0
        trivy_image_exposedsecrets{container_name="controller",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="High"} 0
        trivy_image_exposedsecrets{container_name="controller",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="Low"} 0
        trivy_image_exposedsecrets{container_name="controller",image_digest="sha256:5516d103a9c2ecc4f026efbd4b40662ce22dc1f824fb129ed121460aaa5c47f8",image_registry="k8s.gcr.io",image_repository="ingress-nginx/controller",image_tag="",name="daemonset-ingress-nginx-controller-controller",namespace="ingress-nginx",resource_kind="DaemonSet",resource_name="ingress-nginx-controller",severity="Medium"} 0
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_image_exposedsecrets")).
				To(Succeed())
		})

		It("should produce correct metrics from target namespaces", func() {
			collector.TargetNamespaces = "default,some-ns"
			const expected = `
        # HELP trivy_image_exposedsecrets Number of image exposed secrets
        # TYPE trivy_image_exposedsecrets gauge
        trivy_image_exposedsecrets{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Critical"} 2
        trivy_image_exposedsecrets{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="High"} 0
        trivy_image_exposedsecrets{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Low"} 0
        trivy_image_exposedsecrets{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Medium"} 0
        trivy_image_exposedsecrets{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Critical"} 4
        trivy_image_exposedsecrets{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="High"} 3
        trivy_image_exposedsecrets{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Low"} 0
        trivy_image_exposedsecrets{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",severity="Medium"} 0
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_image_exposedsecrets")).
				To(Succeed())
		})

		It("should produce correct metrics with cluster scope and with MetricsExposedSecretInfo option enabled", func() {
			collector.Config.MetricsExposedSecretInfo = true
			const expected = `
		# HELP trivy_exposedsecrets_info Number of container image exposed secrets group by secret rule id
		# TYPE trivy_exposedsecrets_info gauge
		trivy_exposedsecrets_info{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",secret_category="AWS",secret_rule_id="aws-access-key-id",secret_target="/etc/apt/s3auth.conf",secret_title="AWS Access Key ID",severity="Critical"} 1
		trivy_exposedsecrets_info{container_name="nginx",image_digest="",image_registry="index.docker.io",image_repository="library/nginx",image_tag="1.16",name="replicaset-nginx-6d4cf56db6-nginx",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",secret_category="Stripe",secret_rule_id="stripe-secret-token",secret_target="/app/config/secret.yaml",secret_title="Stripe",severity="Critical"} 1
		trivy_exposedsecrets_info{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",secret_category="AWS",secret_rule_id="aws-access-key-id",secret_target="/etc/apt/s3auth.conf",secret_title="AWS Access Key ID",severity="Critical"} 1
		trivy_exposedsecrets_info{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",secret_category="AWS",secret_rule_id="aws-secret-access-key",secret_target="/etc/apt/s3auth.conf",secret_title="AWS Secret Access Key",severity="Critical"} 1
		trivy_exposedsecrets_info{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",secret_category="Alibaba",secret_rule_id="alibaba-access-key-id",secret_target="/app4/config/secret.yaml",secret_title="Alibaba AccessKey ID",severity="High"} 1
		trivy_exposedsecrets_info{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",secret_category="GitHub",secret_rule_id="github-pat",secret_target="/app/config/secret.yaml",secret_title="GitHub Personal Access Token",severity="Critical"} 1
		trivy_exposedsecrets_info{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",secret_category="PyPI",secret_rule_id="pypi-upload-token",secret_target="/app3/config/secret.yaml",secret_title="PyPI upload token",severity="High"} 1
		trivy_exposedsecrets_info{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",secret_category="Shopify",secret_rule_id="shopify-token",secret_target="/app2/config/secret.yaml",secret_title="Shopify token",severity="High"} 1
		trivy_exposedsecrets_info{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",secret_category="Stripe",secret_rule_id="stripe-secret-token",secret_target="/app/config/secret.yaml",secret_title="Stripe",severity="Critical"} 1
			`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_exposedsecrets_info")).
				To(Succeed())
		})

		It("should produce correct metrics from target namespaces with MetricsExposedSecretInfo option enabled", func() {
			collector.Config.MetricsExposedSecretInfo = true
			collector.TargetNamespaces = "some-ns"
			const expected = `
		# HELP trivy_exposedsecrets_info Number of container image exposed secrets group by secret rule id
		# TYPE trivy_exposedsecrets_info gauge
		trivy_exposedsecrets_info{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",secret_category="AWS",secret_rule_id="aws-access-key-id",secret_target="/etc/apt/s3auth.conf",secret_title="AWS Access Key ID",severity="Critical"} 1
		trivy_exposedsecrets_info{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",secret_category="AWS",secret_rule_id="aws-secret-access-key",secret_target="/etc/apt/s3auth.conf",secret_title="AWS Secret Access Key",severity="Critical"} 1
		trivy_exposedsecrets_info{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",secret_category="Alibaba",secret_rule_id="alibaba-access-key-id",secret_target="/app4/config/secret.yaml",secret_title="Alibaba AccessKey ID",severity="High"} 1
		trivy_exposedsecrets_info{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",secret_category="GitHub",secret_rule_id="github-pat",secret_target="/app/config/secret.yaml",secret_title="GitHub Personal Access Token",severity="Critical"} 1
		trivy_exposedsecrets_info{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",secret_category="PyPI",secret_rule_id="pypi-upload-token",secret_target="/app3/config/secret.yaml",secret_title="PyPI upload token",severity="High"} 1
		trivy_exposedsecrets_info{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",secret_category="Shopify",secret_rule_id="shopify-token",secret_target="/app2/config/secret.yaml",secret_title="Shopify token",severity="High"} 1
		trivy_exposedsecrets_info{container_name="proxy",image_digest="",image_registry="quay.io",image_repository="oauth2-proxy/oauth2-proxy",image_tag="v7.2.1",name="replicaset-app-d327abe3c4-proxy",namespace="some-ns",resource_kind="ReplicaSet",resource_name="app-d327abe3c4",secret_category="Stripe",secret_rule_id="stripe-secret-token",secret_target="/app/config/secret.yaml",secret_title="Stripe",severity="Critical"} 1
			`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_exposedsecrets_info")).
				To(Succeed())
		})
	})

	Context("ConfigAuditReport", func() {
		BeforeEach(func() {
			car1 := &v1alpha1.ConfigAuditReport{}
			car1.Namespace = "default"
			car1.Name = "replicaset-nginx-6d4cf56db6"
			car1.Labels = labels.Set{
				trivyoperator.LabelResourceKind: "ReplicaSet",
				trivyoperator.LabelResourceName: "nginx-6d4cf56db6"}
			car1.Report.Checks = append(car1.Report.Checks,
				[]v1alpha1.Check{
					{
						ID:          "car1 Id",
						Title:       "car1 config audit title",
						Description: "car1 description for config audit",
						Category:    "car1 category for config audit",
						Severity:    "Critical",
						Success:     true,
					},
					{
						ID:          "car1 Id",
						Title:       "car1 config audit title",
						Description: "car1 description for config audit",
						Category:    "car1 category for config audit",
						Severity:    "Critical",
						Success:     false,
					},
				}...)

			car1.Report.Summary.CriticalCount = 2
			car1.Report.Summary.LowCount = 9

			car2 := &v1alpha1.ConfigAuditReport{}
			car2.Namespace = "some-ns"
			car2.Name = "configmap-test"
			car2.Labels = labels.Set{
				trivyoperator.LabelResourceKind: "ConfigMap",
				trivyoperator.LabelResourceName: "test"}
			car2.Report.Checks = append(car2.Report.Checks,
				[]v1alpha1.Check{
					{
						ID:          "car2 Id",
						Title:       "car2 config audit title",
						Description: "car2 description for config audit",
						Category:    "car2 category for config audit",
						Severity:    "Critical",
						Success:     true,
					},
					{
						ID:          "car2 Id",
						Title:       "car2 config audit title",
						Description: "car2 description for config audit",
						Category:    "car2 category for config audit",
						Severity:    "Critical",
						Success:     false,
					},
				}...)
			car2.Report.Summary.LowCount = 1

			car3 := &v1alpha1.ConfigAuditReport{}
			car3.Namespace = "vault-system"
			car3.Name = "replicaset-vault-agent-injector-65fd65bfb8"
			car3.Labels = labels.Set{
				trivyoperator.LabelResourceKind: "ReplicaSet",
				trivyoperator.LabelResourceName: "vault-agent-injector-65fd65bfb8"}
			car3.Report.Checks = append(car3.Report.Checks,
				[]v1alpha1.Check{
					{
						ID:          "car3 Id",
						Title:       "car3 config audit title",
						Description: "car3 description for config audit",
						Category:    "car3 category for config audit",
						Severity:    "Critical",
						Success:     true,
					},
					{
						ID:          "car3 Id",
						Title:       "car3 config audit title",
						Description: "car3 description for config audit",
						Category:    "car3 category for config audit",
						Severity:    "Critical",
						Success:     false,
					},
				}...)
			car3.Report.Summary.MediumCount = 4
			car3.Report.Summary.LowCount = 7

			client.WithRuntimeObjects(car1, car2, car3)
		})

		AssertNoLintIssues()

		It("should produce correct metrics with cluster scope - Summary", func() {
			const expected = `
        # HELP trivy_resource_configaudits Number of failing resource configuration auditing checks
        # TYPE trivy_resource_configaudits gauge
        trivy_resource_configaudits{name="configmap-test",namespace="some-ns",resource_kind="ConfigMap",resource_name="test",severity="Critical"} 0
        trivy_resource_configaudits{name="configmap-test",namespace="some-ns",resource_kind="ConfigMap",resource_name="test",severity="High"} 0
        trivy_resource_configaudits{name="configmap-test",namespace="some-ns",resource_kind="ConfigMap",resource_name="test",severity="Low"} 1
        trivy_resource_configaudits{name="configmap-test",namespace="some-ns",resource_kind="ConfigMap",resource_name="test",severity="Medium"} 0
        trivy_resource_configaudits{name="replicaset-nginx-6d4cf56db6",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Critical"} 2
        trivy_resource_configaudits{name="replicaset-nginx-6d4cf56db6",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="High"} 0
        trivy_resource_configaudits{name="replicaset-nginx-6d4cf56db6",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Low"} 9
        trivy_resource_configaudits{name="replicaset-nginx-6d4cf56db6",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Medium"} 0
        trivy_resource_configaudits{name="replicaset-vault-agent-injector-65fd65bfb8",namespace="vault-system",resource_kind="ReplicaSet",resource_name="vault-agent-injector-65fd65bfb8",severity="Critical"} 0
        trivy_resource_configaudits{name="replicaset-vault-agent-injector-65fd65bfb8",namespace="vault-system",resource_kind="ReplicaSet",resource_name="vault-agent-injector-65fd65bfb8",severity="High"} 0
        trivy_resource_configaudits{name="replicaset-vault-agent-injector-65fd65bfb8",namespace="vault-system",resource_kind="ReplicaSet",resource_name="vault-agent-injector-65fd65bfb8",severity="Low"} 7
        trivy_resource_configaudits{name="replicaset-vault-agent-injector-65fd65bfb8",namespace="vault-system",resource_kind="ReplicaSet",resource_name="vault-agent-injector-65fd65bfb8",severity="Medium"} 4
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_resource_configaudits")).
				To(Succeed())
		})

		It("should produce correct metrics with cluster scope - Info", func() {
			collector.Config.MetricsConfigAuditInfo = true
			const expected = `
        # HELP trivy_configaudits_info Number of failing resource configuration auditing checks Info
		# TYPE trivy_configaudits_info gauge
		trivy_configaudits_info{config_audit_category="car1 category for config audit",config_audit_description="car1 description for config audit",config_audit_id="car1 Id",config_audit_success="false",config_audit_title="car1 config audit title",name="replicaset-nginx-6d4cf56db6",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Critical"} 1
		trivy_configaudits_info{config_audit_category="car1 category for config audit",config_audit_description="car1 description for config audit",config_audit_id="car1 Id",config_audit_success="true",config_audit_title="car1 config audit title",name="replicaset-nginx-6d4cf56db6",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Critical"} 1
		trivy_configaudits_info{config_audit_category="car2 category for config audit",config_audit_description="car2 description for config audit",config_audit_id="car2 Id",config_audit_success="false",config_audit_title="car2 config audit title",name="configmap-test",namespace="some-ns",resource_kind="ConfigMap",resource_name="test",severity="Critical"} 1
		trivy_configaudits_info{config_audit_category="car2 category for config audit",config_audit_description="car2 description for config audit",config_audit_id="car2 Id",config_audit_success="true",config_audit_title="car2 config audit title",name="configmap-test",namespace="some-ns",resource_kind="ConfigMap",resource_name="test",severity="Critical"} 1
		trivy_configaudits_info{config_audit_category="car3 category for config audit",config_audit_description="car3 description for config audit",config_audit_id="car3 Id",config_audit_success="false",config_audit_title="car3 config audit title",name="replicaset-vault-agent-injector-65fd65bfb8",namespace="vault-system",resource_kind="ReplicaSet",resource_name="vault-agent-injector-65fd65bfb8",severity="Critical"} 1
		trivy_configaudits_info{config_audit_category="car3 category for config audit",config_audit_description="car3 description for config audit",config_audit_id="car3 Id",config_audit_success="true",config_audit_title="car3 config audit title",name="replicaset-vault-agent-injector-65fd65bfb8",namespace="vault-system",resource_kind="ReplicaSet",resource_name="vault-agent-injector-65fd65bfb8",severity="Critical"} 1
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_configaudits_info")).
				To(Succeed())
		})

		It("should produce correct metrics from target namespaces - Summary", func() {
			collector.TargetNamespaces = "default,some-ns"
			const expected = `
        # HELP trivy_resource_configaudits Number of failing resource configuration auditing checks
        # TYPE trivy_resource_configaudits gauge
        trivy_resource_configaudits{name="configmap-test",namespace="some-ns",resource_kind="ConfigMap",resource_name="test",severity="Critical"} 0
        trivy_resource_configaudits{name="configmap-test",namespace="some-ns",resource_kind="ConfigMap",resource_name="test",severity="High"} 0
        trivy_resource_configaudits{name="configmap-test",namespace="some-ns",resource_kind="ConfigMap",resource_name="test",severity="Low"} 1
        trivy_resource_configaudits{name="configmap-test",namespace="some-ns",resource_kind="ConfigMap",resource_name="test",severity="Medium"} 0
        trivy_resource_configaudits{name="replicaset-nginx-6d4cf56db6",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Critical"} 2
        trivy_resource_configaudits{name="replicaset-nginx-6d4cf56db6",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="High"} 0
        trivy_resource_configaudits{name="replicaset-nginx-6d4cf56db6",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Low"} 9
        trivy_resource_configaudits{name="replicaset-nginx-6d4cf56db6",namespace="default",resource_kind="ReplicaSet",resource_name="nginx-6d4cf56db6",severity="Medium"} 0
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_resource_configaudits")).
				To(Succeed())
		})
	})

	Context("InfraAssessmentReport", func() {
		BeforeEach(func() {
			car1 := &v1alpha1.InfraAssessmentReport{}
			car1.Namespace = "kube-system"
			car1.Name = "pod-kube-apiserver-minikube-6d4cf56db6"
			car1.Labels = labels.Set{
				trivyoperator.LabelResourceKind: "Pod",
				trivyoperator.LabelResourceName: "kube-apiserver-minikube-6d4cf56db6"}
			car1.Report.Checks = append(car1.Report.Checks,
				[]v1alpha1.Check{
					{
						ID:          "car1 Id",
						Title:       "car1 infra assessment title",
						Description: "car1 description for infra assessment",
						Category:    "car1 category for infra assessment",
						Severity:    "Critical",
						Success:     true,
					},
					{
						ID:          "car1 Id",
						Title:       "car1 infra assessment title",
						Description: "car1 description for infra assessment",
						Category:    "car1 category for infra assessment",
						Severity:    "Critical",
						Success:     false,
					},
				}...)

			car1.Report.Summary.CriticalCount = 2
			car1.Report.Summary.LowCount = 9

			client.WithRuntimeObjects(car1)
		})

		AssertNoLintIssues()

		It("should produce infra assessment metrics on kube-system namespace", func() {
			const expected = `
		# HELP trivy_resource_infraassessments Number of failing k8s infra assessment checks
		# TYPE trivy_resource_infraassessments gauge
		trivy_resource_infraassessments{name="pod-kube-apiserver-minikube-6d4cf56db6",namespace="kube-system",resource_kind="Pod",resource_name="kube-apiserver-minikube-6d4cf56db6",severity="Critical"} 2
		trivy_resource_infraassessments{name="pod-kube-apiserver-minikube-6d4cf56db6",namespace="kube-system",resource_kind="Pod",resource_name="kube-apiserver-minikube-6d4cf56db6",severity="High"} 0
		trivy_resource_infraassessments{name="pod-kube-apiserver-minikube-6d4cf56db6",namespace="kube-system",resource_kind="Pod",resource_name="kube-apiserver-minikube-6d4cf56db6",severity="Low"} 9
		trivy_resource_infraassessments{name="pod-kube-apiserver-minikube-6d4cf56db6",namespace="kube-system",resource_kind="Pod",resource_name="kube-apiserver-minikube-6d4cf56db6",severity="Medium"} 0
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_resource_infraassessments")).
				To(Succeed())
		})

		It("should produce correct infra assessment metrics with cluster scope - Info", func() {
			collector.Config.MetricsInfraAssessmentInfo = true
			const expected = `
		# HELP trivy_infraassessments_info Number of failing k8s infra assessment checks Info
		# TYPE trivy_infraassessments_info gauge
		trivy_infraassessments_info{name="pod-kube-apiserver-minikube-6d4cf56db6",namespace="kube-system",infra_assessment_category="car1 category for infra assessment",infra_assessment_description="car1 description for infra assessment",infra_assessment_id="car1 Id",infra_assessment_success="true",infra_assessment_title="car1 infra assessment title",resource_kind="Pod",resource_name="kube-apiserver-minikube-6d4cf56db6",severity="Critical"} 1
		trivy_infraassessments_info{name="pod-kube-apiserver-minikube-6d4cf56db6",namespace="kube-system",infra_assessment_category="car1 category for infra assessment",infra_assessment_description="car1 description for infra assessment",infra_assessment_id="car1 Id",infra_assessment_success="false",infra_assessment_title="car1 infra assessment title",resource_kind="Pod",resource_name="kube-apiserver-minikube-6d4cf56db6",severity="Critical"} 1
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_rbacassessments_info")).
				To(Succeed())
		})
	})

	Context("RbacAssessment", func() {
		BeforeEach(func() {
			car1 := &v1alpha1.RbacAssessmentReport{}
			car1.Namespace = "default"
			car1.Name = "role-admin-6d4cf56db6"
			car1.Labels = labels.Set{
				trivyoperator.LabelResourceKind: "Role",
				trivyoperator.LabelResourceName: "admin-6d4cf56db6"}
			car1.Report.Checks = append(car1.Report.Checks,
				[]v1alpha1.Check{
					{
						ID:          "car1 Id",
						Title:       "car1 rbac assessment title",
						Description: "car1 description for rbac assessment",
						Category:    "car1 category for rbac assessment",
						Severity:    "Critical",
						Success:     true,
					},
					{
						ID:          "car1 Id",
						Title:       "car1 rbac assessment title",
						Description: "car1 description for rbac assessment",
						Category:    "car1 category for rbac assessment",
						Severity:    "Critical",
						Success:     false,
					},
				}...)

			car1.Report.Summary.CriticalCount = 2
			car1.Report.Summary.LowCount = 9

			car2 := &v1alpha1.RbacAssessmentReport{}
			car2.Namespace = "some-ns"
			car2.Name = "role-write-test"
			car2.Labels = labels.Set{
				trivyoperator.LabelResourceKind: "Role",
				trivyoperator.LabelResourceName: "write-test"}
			car2.Report.Checks = append(car2.Report.Checks,
				[]v1alpha1.Check{
					{
						ID:          "car2 Id",
						Title:       "car2 rbac assessment title",
						Description: "car2 description for rbac assessment",
						Category:    "car2 category for rbac assessment",
						Severity:    "Critical",
						Success:     true,
					},
					{
						ID:          "car2 Id",
						Title:       "car2 rbac assessment title",
						Description: "car2 description for rbac assessment",
						Category:    "car2 category for rbac assessment",
						Severity:    "Critical",
						Success:     false,
					},
				}...)
			car2.Report.Summary.LowCount = 1

			car3 := &v1alpha1.RbacAssessmentReport{}
			car3.Namespace = "vault-system"
			car3.Name = "role-read-65fd65bfb8"
			car3.Labels = labels.Set{
				trivyoperator.LabelResourceKind: "Role",
				trivyoperator.LabelResourceName: "read-65fd65bfb8"}
			car3.Report.Checks = append(car3.Report.Checks,
				[]v1alpha1.Check{
					{
						ID:          "car3 Id",
						Title:       "car3 rbac assessment title",
						Description: "car3 description for rbac assessment",
						Category:    "car3 category for rbac assessment",
						Severity:    "Critical",
						Success:     true,
					},
					{
						ID:          "car3 Id",
						Title:       "car3 rbac assessment title",
						Description: "car3 description for rbac assessment",
						Category:    "car3 category for rbac assessment",
						Severity:    "Critical",
						Success:     false,
					},
				}...)
			car3.Report.Summary.MediumCount = 4
			car3.Report.Summary.LowCount = 7

			client.WithRuntimeObjects(car1, car2, car3)
		})

		AssertNoLintIssues()

		It("should produce correct rbac assessment metrics with cluster scope", func() {
			const expected = `
		# HELP trivy_role_rbacassessments Number of rbac risky role assessment checks
		# TYPE trivy_role_rbacassessments gauge
		trivy_role_rbacassessments{name="role-admin-6d4cf56db6",namespace="default",resource_kind="Role",resource_name="admin-6d4cf56db6",severity="Critical"} 2
		trivy_role_rbacassessments{name="role-admin-6d4cf56db6",namespace="default",resource_kind="Role",resource_name="admin-6d4cf56db6",severity="High"} 0
		trivy_role_rbacassessments{name="role-admin-6d4cf56db6",namespace="default",resource_kind="Role",resource_name="admin-6d4cf56db6",severity="Low"} 9
		trivy_role_rbacassessments{name="role-admin-6d4cf56db6",namespace="default",resource_kind="Role",resource_name="admin-6d4cf56db6",severity="Medium"} 0
		trivy_role_rbacassessments{name="role-read-65fd65bfb8",namespace="vault-system",resource_kind="Role",resource_name="read-65fd65bfb8",severity="Critical"} 0
		trivy_role_rbacassessments{name="role-read-65fd65bfb8",namespace="vault-system",resource_kind="Role",resource_name="read-65fd65bfb8",severity="High"} 0
		trivy_role_rbacassessments{name="role-read-65fd65bfb8",namespace="vault-system",resource_kind="Role",resource_name="read-65fd65bfb8",severity="Low"} 7
		trivy_role_rbacassessments{name="role-read-65fd65bfb8",namespace="vault-system",resource_kind="Role",resource_name="read-65fd65bfb8",severity="Medium"} 4
		trivy_role_rbacassessments{name="role-write-test",namespace="some-ns",resource_kind="Role",resource_name="write-test",severity="Critical"} 0
		trivy_role_rbacassessments{name="role-write-test",namespace="some-ns",resource_kind="Role",resource_name="write-test",severity="High"} 0
		trivy_role_rbacassessments{name="role-write-test",namespace="some-ns",resource_kind="Role",resource_name="write-test",severity="Low"} 1
		trivy_role_rbacassessments{name="role-write-test",namespace="some-ns",resource_kind="Role",resource_name="write-test",severity="Medium"} 0
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_role_rbacassessments")).
				To(Succeed())
		})

		It("should produce correct rbac assessment metrics with cluster scope - Info", func() {
			collector.Config.MetricsRbacAssessmentInfo = true
			const expected = `
		# HELP trivy_rbacassessments_info Number of rbac risky role assessment checks Info
		# TYPE trivy_rbacassessments_info gauge
		trivy_rbacassessments_info{name="role-admin-6d4cf56db6",namespace="default",rbac_assessment_category="car1 category for rbac assessment",rbac_assessment_description="car1 description for rbac assessment",rbac_assessment_id="car1 Id",rbac_assessment_success="true",rbac_assessment_title="car1 rbac assessment title",resource_kind="Role",resource_name="admin-6d4cf56db6",severity="Critical"} 1
		trivy_rbacassessments_info{name="role-admin-6d4cf56db6",namespace="default",rbac_assessment_category="car1 category for rbac assessment",rbac_assessment_description="car1 description for rbac assessment",rbac_assessment_id="car1 Id",rbac_assessment_success="false",rbac_assessment_title="car1 rbac assessment title",resource_kind="Role",resource_name="admin-6d4cf56db6",severity="Critical"} 1
		trivy_rbacassessments_info{name="role-write-test",namespace="some-ns",rbac_assessment_category="car2 category for rbac assessment",rbac_assessment_description="car2 description for rbac assessment",rbac_assessment_id="car2 Id",rbac_assessment_success="true",rbac_assessment_title="car2 rbac assessment title",resource_kind="Role",resource_name="write-test",severity="Critical"} 1
		trivy_rbacassessments_info{name="role-write-test",namespace="some-ns",rbac_assessment_category="car2 category for rbac assessment",rbac_assessment_description="car2 description for rbac assessment",rbac_assessment_id="car2 Id",rbac_assessment_success="false",rbac_assessment_title="car2 rbac assessment title",resource_kind="Role",resource_name="write-test",severity="Critical"} 1
		trivy_rbacassessments_info{name="role-read-65fd65bfb8",namespace="vault-system",rbac_assessment_category="car3 category for rbac assessment",rbac_assessment_description="car3 description for rbac assessment",rbac_assessment_id="car3 Id",rbac_assessment_success="true",rbac_assessment_title="car3 rbac assessment title",resource_kind="Role",resource_name="read-65fd65bfb8",severity="Critical"} 1
		trivy_rbacassessments_info{name="role-read-65fd65bfb8",namespace="vault-system",rbac_assessment_category="car3 category for rbac assessment",rbac_assessment_description="car3 description for rbac assessment",rbac_assessment_id="car3 Id",rbac_assessment_success="false",rbac_assessment_title="car3 rbac assessment title",resource_kind="Role",resource_name="read-65fd65bfb8",severity="Critical"} 1
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_rbacassessments_info")).
				To(Succeed())
		})

		It("should produce correct rbac assessment metrics from target namespaces", func() {
			collector.TargetNamespaces = "default,some-ns"
			const expected = `
		# HELP trivy_role_rbacassessments Number of rbac risky role assessment checks
		# TYPE trivy_role_rbacassessments gauge
		trivy_role_rbacassessments{name="role-admin-6d4cf56db6",namespace="default",resource_kind="Role",resource_name="admin-6d4cf56db6",severity="Critical"} 2
		trivy_role_rbacassessments{name="role-admin-6d4cf56db6",namespace="default",resource_kind="Role",resource_name="admin-6d4cf56db6",severity="High"} 0
		trivy_role_rbacassessments{name="role-admin-6d4cf56db6",namespace="default",resource_kind="Role",resource_name="admin-6d4cf56db6",severity="Low"} 9
		trivy_role_rbacassessments{name="role-admin-6d4cf56db6",namespace="default",resource_kind="Role",resource_name="admin-6d4cf56db6",severity="Medium"} 0
		trivy_role_rbacassessments{name="role-write-test",namespace="some-ns",resource_kind="Role",resource_name="write-test",severity="Critical"} 0
		trivy_role_rbacassessments{name="role-write-test",namespace="some-ns",resource_kind="Role",resource_name="write-test",severity="High"} 0
		trivy_role_rbacassessments{name="role-write-test",namespace="some-ns",resource_kind="Role",resource_name="write-test",severity="Low"} 1
		trivy_role_rbacassessments{name="role-write-test",namespace="some-ns",resource_kind="Role",resource_name="write-test",severity="Medium"} 0
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_role_rbacassessments")).
				To(Succeed())
		})
	})
	Context("RbacAssessment", func() {
		BeforeEach(func() {
			car1 := &v1alpha1.ClusterRbacAssessmentReport{}
			car1.Name = "cluster_role-admin-6d4cf56db6"
			car1.Labels = labels.Set{
				trivyoperator.LabelResourceKind: "ClusterRole",
				trivyoperator.LabelResourceName: "admin-6d4cf56db6"}
			car1.Report.Summary.CriticalCount = 2
			car1.Report.Summary.LowCount = 9

			car2 := &v1alpha1.ClusterRbacAssessmentReport{}
			car2.Name = "cluster_role-write-test"
			car2.Labels = labels.Set{
				trivyoperator.LabelResourceKind: "ClusterRole",
				trivyoperator.LabelResourceName: "write-test"}
			car2.Report.Summary.LowCount = 1

			car3 := &v1alpha1.ClusterRbacAssessmentReport{}
			car3.Name = "cluster_role-read-65fd65bfb8"
			car3.Labels = labels.Set{
				trivyoperator.LabelResourceKind: "ClusterRole",
				trivyoperator.LabelResourceName: "read-65fd65bfb8"}
			car3.Report.Summary.MediumCount = 4
			car3.Report.Summary.LowCount = 7

			client.WithRuntimeObjects(car1, car2, car3)
		})

		AssertNoLintIssues()

		It("should produce correct cluster rbac assessment metrics", func() {
			const expected = `
		# HELP trivy_clusterrole_clusterrbacassessments Number of rbac risky cluster role assessment checks
		# TYPE trivy_clusterrole_clusterrbacassessments gauge
		trivy_clusterrole_clusterrbacassessments{name="cluster_role-admin-6d4cf56db6",resource_kind="ClusterRole",resource_name="admin-6d4cf56db6",severity="Critical"} 2
		trivy_clusterrole_clusterrbacassessments{name="cluster_role-admin-6d4cf56db6",resource_kind="ClusterRole",resource_name="admin-6d4cf56db6",severity="High"} 0
		trivy_clusterrole_clusterrbacassessments{name="cluster_role-admin-6d4cf56db6",resource_kind="ClusterRole",resource_name="admin-6d4cf56db6",severity="Low"} 9
		trivy_clusterrole_clusterrbacassessments{name="cluster_role-admin-6d4cf56db6",resource_kind="ClusterRole",resource_name="admin-6d4cf56db6",severity="Medium"} 0
		trivy_clusterrole_clusterrbacassessments{name="cluster_role-read-65fd65bfb8",resource_kind="ClusterRole",resource_name="read-65fd65bfb8",severity="Critical"} 0
		trivy_clusterrole_clusterrbacassessments{name="cluster_role-read-65fd65bfb8",resource_kind="ClusterRole",resource_name="read-65fd65bfb8",severity="High"} 0
		trivy_clusterrole_clusterrbacassessments{name="cluster_role-read-65fd65bfb8",resource_kind="ClusterRole",resource_name="read-65fd65bfb8",severity="Low"} 7
		trivy_clusterrole_clusterrbacassessments{name="cluster_role-read-65fd65bfb8",resource_kind="ClusterRole",resource_name="read-65fd65bfb8",severity="Medium"} 4
		trivy_clusterrole_clusterrbacassessments{name="cluster_role-write-test",resource_kind="ClusterRole",resource_name="write-test",severity="Critical"} 0
		trivy_clusterrole_clusterrbacassessments{name="cluster_role-write-test",resource_kind="ClusterRole",resource_name="write-test",severity="High"} 0
		trivy_clusterrole_clusterrbacassessments{name="cluster_role-write-test",resource_kind="ClusterRole",resource_name="write-test",severity="Low"} 1
		trivy_clusterrole_clusterrbacassessments{name="cluster_role-write-test",resource_kind="ClusterRole",resource_name="write-test",severity="Medium"} 0
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_clusterrole_clusterrbacassessments")).
				To(Succeed())
		})
	})

	Context("clusterComplianceReport", func() {
		BeforeEach(func() {
			car1 := &v1alpha1.ClusterComplianceReport{}
			car1.Spec.Complaince.Title = "nsa"
			car1.Spec.Complaince.Description = "National Security Agency - Kubernetes Hardening Guidance"
			car1.Status.Summary.FailCount = 12
			car1.Status.Summary.PassCount = 15

			client.WithRuntimeObjects(car1)
		})

		AssertNoLintIssues()

		It("should produce correct cluster rbac assessment metrics", func() {
			const expected = `
		# HELP trivy_cluster_compliance cluster compliance report
		# TYPE trivy_cluster_compliance gauge
		trivy_cluster_compliance{description="National Security Agency - Kubernetes Hardening Guidance",status="Fail",title="nsa"} 12
		trivy_cluster_compliance{description="National Security Agency - Kubernetes Hardening Guidance",status="Pass",title="nsa"} 15
		`
			Expect(testutil.CollectAndCompare(collector, strings.NewReader(expected), "trivy_cluster_compliance")).
				To(Succeed())
		})
	})
})
