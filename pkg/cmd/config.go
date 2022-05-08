package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

type LocalFlags struct {
	get      string
	nameOnly bool
}

func NewConfigCmd(cf *genericclioptions.ConfigFlags, outWriter io.Writer) *cobra.Command {
	var localFlags LocalFlags
	cmd := &cobra.Command{
		Use:   "config",
		Short: "View the configuration parameters used by Starboard scanners",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			kubernetesConfig, err := cf.ToRESTConfig()
			if err != nil {
				return err
			}
			clientset, err := kubernetes.NewForConfig(kubernetesConfig)
			if err != nil {
				return err
			}
			config, err := trivyoperator.NewConfigManager(clientset, trivyoperator.NamespaceName).Read(ctx)
			if err != nil {
				return err
			}
			filteredValues, err := getFilteredValues(config, &localFlags)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(outWriter, "%s\n", filteredValues)
			return nil
		},
	}
	setLocalFlags(cmd, &localFlags)
	return cmd
}

func getFilteredValues(data trivyoperator.ConfigData, localFlags *LocalFlags) (string, error) {
	if localFlags.get != "" {
		value := data[localFlags.get]
		if value != "" {
			return data[localFlags.get], nil
		} else {
			return "", fmt.Errorf("no such key exists: %s", localFlags.get)
		}
	}
	if localFlags.nameOnly {
		return convertMapToString(data, true), nil
	}
	return convertMapToString(data, false), nil
}

func convertMapToString(mapToConvert map[string]string, nameOnly bool) string {
	asString := make([]string, 0, len(mapToConvert))
	for key, val := range mapToConvert {
		asString = append(asString, key)
		if !nameOnly {
			asString = append(asString, val)
		}
	}
	return strings.Join(asString, "\n")
}

func setLocalFlags(cmd *cobra.Command, localFlags *LocalFlags) {
	cmd.Flags().BoolVar(&localFlags.nameOnly, "name-only", false, "List parameters by name only")
	cmd.Flags().StringVar(&localFlags.get, "get", "", "Get configuration parameters for a specified key")
}
