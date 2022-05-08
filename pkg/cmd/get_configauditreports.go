package cmd

import (
	"context"
	"fmt"
	"io"

	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewGetConfigAuditReportsCmd(executable string, cf *genericclioptions.ConfigFlags, out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "configauditreports (NAME | TYPE/NAME)",
		Aliases: []string{"configaudit"},
		Short:   "Get configuration audit reports",
		Long: `Get configuration audit reports for the specified resource

TYPE is a Kubernetes resource. Shortcuts and API groups will be resolved, e.g. 'po' or 'deployments.apps'.
NAME is the name of a particular Kubernetes resource.
`,
		Example: fmt.Sprintf(`  # Get configuration audit report for a Deployment with the specified name
  %[1]s get configauditreports deploy/nginx

  # Get configuration audit report for a Deployment with the specified name in the specified namespace
  %[1]s get configauditreports deploy/nginx -n staging

  # Get configuration audit report for a ReplicaSet with the specified name
  %[1]s get configaudit replicaset/nginx

  # Get configuration audit report for a CronJob with the specified name in JSON output format
  %[1]s get configaudit cj/my-job -o json`, executable),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			kubeConfig, err := cf.ToRESTConfig()
			if err != nil {
				return err
			}
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
			scheme := trivyoperator.NewScheme()
			kubeClient, err := client.New(kubeConfig, client.Options{Scheme: scheme})
			if err != nil {
				return err
			}
			reader := configauditreport.NewReadWriter(kubeClient)
			report, err := reader.FindReportByOwnerInHierarchy(ctx, workload)
			if err != nil {
				return nil
			}

			if report == nil {
				fmt.Fprintf(out, "No reports found in %s namespace.\n", workload.Namespace)
				return nil
			}

			format := cmd.Flag("output").Value.String()
			printer, err := genericclioptions.NewPrintFlags("").
				WithTypeSetter(scheme).
				WithDefaultOutput(format).
				ToPrinter()
			if err != nil {
				return fmt.Errorf("create printer: %w", err)
			}

			if err := printer.PrintObj(report, out); err != nil {
				return fmt.Errorf("print vulnerability reports: %w", err)
			}

			return nil
		},
	}

	return cmd
}
