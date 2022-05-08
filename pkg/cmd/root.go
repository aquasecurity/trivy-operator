package cmd

import (
	"flag"
	"fmt"
	"io"

	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

const (
	shortMessage = "Kubernetes-native security toolkit"
	longMessage  = `Kubernetes-native security toolkit

Starboard CLI can be used to find risks, such as vulnerabilities or insecure
pod descriptors, in Kubernetes workloads. By default, the risk assessment
reports are stored as custom resources.

To get started execute the following one-time init command:

$ %[1]s init

As an example let's run in the current namespace an old version of nginx that
we know has vulnerabilities:

$ kubectl create deployment nginx --image nginx:1.16

Run the vulnerability scanner to generate vulnerability reports:

$ %[1]s scan vulnerabilityreports deployment/nginx

Once this has been done, you can retrieve the vulnerability report:

$ %[1]s get vulnerabilityreports deployment/nginx -o yaml
`
)

func NewRootCmd(buildInfo trivyoperator.BuildInfo, args []string, outWriter io.Writer, errWriter io.Writer) *cobra.Command {
	var cf *genericclioptions.ConfigFlags

	rootCmd := &cobra.Command{
		Use:           "trivyoperator",
		Short:         shortMessage,
		Long:          fmt.Sprintf(longMessage, buildInfo.Executable),
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cf = genericclioptions.NewConfigFlags(true)

	rootCmd.AddCommand(NewVersionCmd(buildInfo, outWriter))
	rootCmd.AddCommand(NewInitCmd(buildInfo, cf))
	rootCmd.AddCommand(NewScanCmd(buildInfo, cf))
	rootCmd.AddCommand(NewGetCmd(buildInfo, cf, outWriter))
	rootCmd.AddCommand(NewReportCmd(buildInfo, cf, outWriter))
	rootCmd.AddCommand(NewCleanupCmd(buildInfo, cf))
	rootCmd.AddCommand(NewConfigCmd(cf, outWriter))

	SetGlobalFlags(cf, rootCmd)

	rootCmd.SetArgs(args[1:])
	rootCmd.SetOut(outWriter)
	rootCmd.SetErr(errWriter)

	return rootCmd
}

// Run is the entry point of the Starboard CLI. It runs the specified
// command based on the specified args.
func Run(version trivyoperator.BuildInfo, args []string, outWriter io.Writer, errWriter io.Writer) error {

	initFlags()

	return NewRootCmd(version, args, outWriter, errWriter).Execute()
}

func initFlags() {
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	// Hide all klog flags except for -v
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if f.Name != "v" {
			pflag.Lookup(f.Name).Hidden = true
		}
	})
}
