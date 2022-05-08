package cmd

import (
	"context"

	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/spf13/cobra"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewCleanupCmd(buildInfo trivyoperator.BuildInfo, cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "uninstall",
		Aliases: []string{"cleanup"},
		Short:   "Delete Kubernetes resources created by Starboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			kubeConfig, err := cf.ToRESTConfig()
			if err != nil {
				return err
			}
			kubeClientset, err := kubernetes.NewForConfig(kubeConfig)
			if err != nil {
				return err
			}
			apiExtensionsClientset, err := apiextensionsv1.NewForConfig(kubeConfig)
			if err != nil {
				return err
			}
			scheme := trivyoperator.NewScheme()
			kubeClient, err := client.New(kubeConfig, client.Options{Scheme: scheme})
			if err != nil {
				return err
			}
			configManager := trivyoperator.NewConfigManager(kubeClientset, trivyoperator.NamespaceName)
			installer := NewInstaller(buildInfo, kubeClientset, apiExtensionsClientset, kubeClient, configManager)
			return installer.Uninstall(context.Background())
		},
	}
	return cmd
}
