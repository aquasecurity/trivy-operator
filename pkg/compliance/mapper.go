package compliance

import (
	"context"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func mapComplianceScannerToResource(cli client.Client, ctx context.Context) ([]types.Results, error) {
	results := make([]types.Results, 0)
	caObjList := &v1alpha1.ConfigAuditReportList{}
	err := cli.List(ctx, caObjList)
	if err != nil {
		return nil, err
	}
	for _, ca := range caObjList.Items {
		results:= types.Results{}
		for _,check:=range ca.Report.Checks {
			types.DetectedMisconfiguration{}
			result.types.Result{
				Misconfigurations: 
			}
		}
	}

	iaObjList := &v1alpha1.InfraAssessmentReportList{}
	err = cli.List(ctx, iaObjList)
	if err != nil {
		return nil, err
	}
	return results, nil
}
