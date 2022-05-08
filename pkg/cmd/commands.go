package cmd

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func SetGlobalFlags(cf *genericclioptions.ConfigFlags, cmd *cobra.Command) {
	cf.AddFlags(cmd.Flags())
	for _, c := range cmd.Commands() {
		SetGlobalFlags(cf, c)
	}
}

func WorkloadFromArgs(mapper meta.RESTMapper, namespace string, args []string) (workload kube.ObjectRef, gvk schema.GroupVersionKind, err error) {
	if len(args) < 1 {
		err = errors.New("required workload kind and name not specified")
		return
	}

	var resource, resourceName string
	parts := strings.SplitN(args[0], "/", 2)
	if len(parts) == 1 {
		resource = "pods"
		resourceName = parts[0]
	} else {
		resource = parts[0]
		resourceName = parts[1]
	}

	_, gvk, err = kube.GVRForResource(mapper, resource)
	if err != nil {
		return
	}
	if "" == resourceName {
		err = errors.New("required workload name is blank")
		return
	}
	workload = kube.ObjectRef{
		Namespace: namespace,
		Kind:      kube.Kind(gvk.Kind),
		Name:      resourceName,
	}
	return
}

func ComplianceNameFromArgs(args []string, suffix ...string) (types.NamespacedName, error) {
	if len(args) < 1 {
		return types.NamespacedName{}, fmt.Errorf("required compliance name not specified")
	}
	reportName := args[0]
	if len(suffix) > 0 {
		reportName = fmt.Sprintf("%s-%s", reportName, suffix[0])
	}
	return types.NamespacedName{Name: reportName}, nil
}

const (
	scanJobTimeoutFlagName = "scan-job-timeout"
	deleteScanJobFlagName  = "delete-scan-job"
)

func registerScannerOpts(cmd *cobra.Command) {
	cmd.Flags().Duration(scanJobTimeoutFlagName, time.Duration(0),
		"The length of time to wait before giving up on a scan job. Non-zero values should contain a"+
			" corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout the scan job.")
	cmd.Flags().Bool(deleteScanJobFlagName, true, "If true, delete a scan job either complete or failed")
}

func getScannerOpts(cmd *cobra.Command) (opts kube.ScannerOpts, err error) {
	opts.ScanJobTimeout, err = cmd.Flags().GetDuration(scanJobTimeoutFlagName)
	if err != nil {
		return
	}
	opts.DeleteScanJob, err = cmd.Flags().GetBool(deleteScanJobFlagName)
	if err != nil {
		return
	}
	return
}
