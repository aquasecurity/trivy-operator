package cmd

import (
	"context"
	"fmt"
	"sync"

	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kubebench"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	kubeBenchCmdShort = "Run the CIS Kubernetes Benchmark for each node of your cluster"
)

func NewScanKubeBenchReportsCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ciskubebenchreports",
		Short: kubeBenchCmdShort,
		RunE:  ScanKubeBenchReports(cf),
	}

	registerScannerOpts(cmd)

	return cmd
}

func ScanKubeBenchReports(cf *genericclioptions.ConfigFlags) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		kubeConfig, err := cf.ToRESTConfig()
		if err != nil {
			return err
		}
		kubeClientset, err := kubernetes.NewForConfig(kubeConfig)
		if err != nil {
			return err
		}
		opts, err := getScannerOpts(cmd)
		if err != nil {
			return err
		}
		config, err := trivyoperator.NewConfigManager(kubeClientset, trivyoperator.NamespaceName).Read(ctx)
		if err != nil {
			return err
		}
		scheme := trivyoperator.NewScheme()
		kubeClient, err := client.New(kubeConfig, client.Options{
			Scheme: scheme,
		})
		if err != nil {
			return err
		}

		plugin := kubebench.NewKubeBenchPlugin(ext.NewSystemClock(), config)
		scanner := kubebench.NewScanner(scheme, kubeClientset, plugin, config, opts)
		writer := kubebench.NewReadWriter(kubeClient)

		nodes, err := GetNodes(ctx, kubeClientset, args...)
		if err != nil {
			return fmt.Errorf("getting nodes: %w", err)
		}

		// TODO Move this logic to scanner.ScanAll() method. We should not mix discovery / scanning logic with the CLI.
		var wg sync.WaitGroup

		for _, node := range nodes {
			nodeValueLabel, exist := node.GetObjectMeta().GetLabels()[corev1.LabelOSStable]
			if exist && nodeValueLabel != "linux" {
				klog.V(3).Infof("Skipping non linux node: %v %v", node.Name, node.Labels)
				continue
			}

			wg.Add(1)
			go func(node corev1.Node) {
				defer wg.Done()
				report, err := scanner.Scan(ctx, node)
				if err != nil {
					klog.Errorf("Error while running kube-bench on node: %s: %v", node.Name, err)
					return
				}
				err = writer.Write(ctx, report)
				if err != nil {
					klog.Errorf("Error while writing kube-bench report for node: %s: %v", node.Name, err)
					return
				}
			}(node)
		}

		wg.Wait()
		return nil
	}
}

// GetNodes returns nodes by names. If the list of names is empty it returns all nodes.
func GetNodes(ctx context.Context, clientset kubernetes.Interface, names ...string) ([]corev1.Node, error) {
	if len(names) > 0 {
		var nodes []corev1.Node
		for _, name := range names {
			node, err := clientset.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, *node)
		}
		return nodes, nil
	}

	nodeList, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return nodeList.Items, nil
}
