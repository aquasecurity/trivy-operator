package cmd

import (
	"fmt"
	"io"

	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/report"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewReportCmd(info trivyoperator.BuildInfo, cf *genericclioptions.ConfigFlags, out io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "report (NAME | TYPE/NAME)",
		Short: "Generate an HTML security report for a specified Kubernetes object",
		Long: fmt.Sprintf(`Generate an HTML security report for a specified Kubernetes object.

If the specified object is a Kubernetes workload, for example Pod or Deployment,
the report will contain vulnerabilities found in its container images as well as
results of its configuration audit.

If the specified object is a Kubernetes namespace, the report will contain the
summary of security risks, including vulnerabilities and results of configuration
audits for most critical workloads within that namespace.

HTML reports are generated from data already stored as VulnerabilityReport and
ConfigAuditReport resources. Therefore, before generating a report make sure
that you scanned Kubernetes workloads for vulnerabilities and configuration
pitfalls. You can run "%[1]s scan vulnerabilityreports -h" and
"%[1]s scan configauditreports -h" commands for more details on how to do that.

If the specified object is a Kubernetes node, the report will contain configuration
checks based on CIS Kubernetes Benchmark guides.

TYPE is a Kubernetes workload. Shortcuts and API groups will be resolved, e.g. 'po' or 'deployments.apps'.
NAME is the name of a particular Kubernetes workload.
`, info.Executable),
		Example: fmt.Sprintf(`  # Generate an HTML report for a deployment with the specified name and save it to a file.
  %[1]s report deployment/nginx > nginx.deploy.html

  # Generate an HTML report for a namespace with the specified name and save it to a file.
  %[1]s report namespace/kube-system > kube-system.ns.html

  # Generate an HTML report for a node with the specified name and save it to a file.
  %[1]s report node/kind-control-plane > kind-control-plane.node.html
`, info.Executable),
		RunE: func(cmd *cobra.Command, args []string) error {
			kubeConfig, err := cf.ToRESTConfig()
			if err != nil {
				return err
			}
			kubeClient, err := client.New(kubeConfig, client.Options{Scheme: trivyoperator.NewScheme()})
			ns, _, err := cf.ToRawKubeConfigLoader().Namespace()
			if err != nil {
				return err
			}
			mapper, err := cf.ToRESTMapper()
			if err != nil {
				return err
			}
			workload, _, err := WorkloadFromArgs(mapper, ns, args)
			if err != nil {
				return err
			}
			clock := ext.NewSystemClock()
			switch workload.Kind {
			case kube.KindDeployment,
				kube.KindReplicaSet,
				kube.KindReplicationController,
				kube.KindStatefulSet,
				kube.KindDaemonSet,
				kube.KindCronJob,
				kube.KindJob,
				kube.KindPod:
				reporter := report.NewWorkloadReporter(clock, kubeClient)
				return reporter.Generate(workload, out)
			case kube.KindNamespace:
				reporter := report.NewNamespaceReporter(clock, kubeClient)
				return reporter.Generate(workload, out)
			case kube.KindNode:
				reporter := report.NewNodeReporter(clock, kubeClient)
				return reporter.Generate(workload, out)
			default:
				return fmt.Errorf("HTML report is not supported for %q", workload.Kind)
			}
		},
	}
}
