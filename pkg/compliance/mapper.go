package compliance

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// MisconfigReportToTrivyResults convert misconfig and infra assessment report Data to trivy results
func MisconfigReportToTrivyResults(cli client.Client, ctx context.Context) ([]types.Results, error) {
	resultsArray := make([]types.Results, 0)
	caObjList := &v1alpha1.ConfigAuditReportList{}
	err := cli.List(ctx, caObjList)
	if err != nil {
		return nil, err
	}
	for _, ca := range caObjList.Items {
		results := reportstoResults(ca.Report.Checks)
		resultsArray = append(resultsArray, results)
	}
	iaObjList := &v1alpha1.InfraAssessmentReportList{}
	err = cli.List(ctx, iaObjList)
	if err != nil {
		return nil, err
	}
	for _, ia := range iaObjList.Items {
		results := reportstoResults(ia.Report.Checks)
		resultsArray = append(resultsArray, results)
	}
	return resultsArray, nil
}

func reportstoResults(checks []v1alpha1.Check) types.Results {
	results := types.Results{}
	for _, check := range checks {
		status := types.StatusFailure
		if check.Success {
			status = types.StatusPassed
		}
		var id string
		if !strings.HasPrefix(check.ID, "AVD-") {
			if strings.HasPrefix(check.ID, "KSV") {
				id = fmt.Sprintf("%s-%s-%s", "AVD", "KSV", strings.Replace(check.ID, "KSV", "0", -1))
			}
			if strings.HasPrefix(check.ID, "KCV") {
				id = fmt.Sprintf("%s-%s-%s", "AVD", "KCV", strings.Replace(check.ID, "KCV", "", -1))
			}
		}
		misconfigResult := types.Result{
			Misconfigurations: []types.DetectedMisconfiguration{{
				AVDID:       id,
				Title:       check.Title,
				Description: check.Description,
				Message:     check.Description,
				Severity:    string(check.Severity),
				Status:      status,
			},
			},
		}
		results = append(results, misconfigResult)
	}
	return results
}
