package cmd

import (
	"context"
	"fmt"
	"io"

	"k8s.io/client-go/kubernetes"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/compliance"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewGetClusterComplianceReportsCmd(executable string, cf *genericclioptions.ConfigFlags, out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "clustercompliancereports (NAME)",
		Aliases: []string{"clustercompliance"},
		Short:   "Get cluster compliance reports",
		Long:    `Get cluster compliance report for pre-defined spec`,
		Example: fmt.Sprintf(`  # Get cluster compliance report for specifc spec in JSON output format
  %[1]s get clustercompliancereports nsa -o json

  # Get compliance detail report for control checks failure in JSON output format
  %[1]s get clustercompliancereports nsa -o json --detail`, executable),
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := ctrl.Log.WithName("reconciler").WithName("clustercompliancereport")
			ctx := context.Background()
			scheme := trivyoperator.NewScheme()
			kubeConfig, err := cf.ToRESTConfig()
			if err != nil {
				return fmt.Errorf("failed to create kubeConfig: %w", err)
			}

			kubeClient, err := client.New(kubeConfig, client.Options{Scheme: scheme})
			if err != nil {
				return fmt.Errorf("failed to create kubernetes client: %w", err)
			}
			namespaceName, err := ComplianceNameFromArgs(args)
			if err != nil {
				return err
			}

			var report v1alpha1.ClusterComplianceReport
			err = GetComplianceReport(ctx, kubeClient, namespaceName, out, &report)
			if err != nil {
				return err
			}
			kubeClientset, err := kubernetes.NewForConfig(kubeConfig)
			if err != nil {
				return err
			}
			starboardConfig, err := trivyoperator.NewConfigManager(kubeClientset, trivyoperator.NamespaceName).Read(ctx)
			if err != nil {
				return err
			}
			complianceMgr := compliance.NewMgr(kubeClient, logger, starboardConfig)
			err = complianceMgr.GenerateComplianceReport(ctx, report.Spec)
			if err != nil {
				return fmt.Errorf("failed to generate report: %w", err)
			}

			format := cmd.Flag("output").Value.String()
			printer, err := genericclioptions.NewPrintFlags("").
				WithTypeSetter(scheme).
				WithDefaultOutput(format).
				ToPrinter()
			if err != nil {
				return fmt.Errorf("faild to create printer: %w", err)
			}

			detail, err := cmd.Flags().GetBool("detail")
			if err != nil {
				return fmt.Errorf("detail flag is not set correctly, check flag usage: %w", err)
			}
			if !detail {
				var complianceReport v1alpha1.ClusterComplianceReport
				err := GetComplianceReport(ctx, kubeClient, namespaceName, out, &complianceReport)
				if err != nil {
					return err
				}
				if err := printer.PrintObj(&complianceReport, out); err != nil {
					return fmt.Errorf("print compliance reports: %w", err)
				}
				return nil
			}

			detailNamespaceName, err := ComplianceNameFromArgs(args, "details")
			if err != nil {
				return err
			}
			var complianceDetailReport v1alpha1.ClusterComplianceDetailReport
			err = GetComplianceReport(ctx, kubeClient, detailNamespaceName, out, &complianceDetailReport)
			if err != nil {
				return err
			}
			if err := printer.PrintObj(&complianceDetailReport, out); err != nil {
				return fmt.Errorf("print compliance reports: %w", err)
			}
			return nil
		},
	}
	cmd.PersistentFlags().BoolP("detail", "d", false, "Get compliance detail report for control checks failure")
	return cmd
}

func GetComplianceReport(ctx context.Context, client client.Client, namespaceName types.NamespacedName, out io.Writer, report client.Object) error {
	err := client.Get(ctx, namespaceName, report)
	if err != nil {
		if errors.IsNotFound(err) {
			fmt.Fprintf(out, "No complaince reports found with name: %s .\n", namespaceName.Name)
			return err
		}
		return fmt.Errorf("failed getting report: %w", err)
	}
	return nil
}
