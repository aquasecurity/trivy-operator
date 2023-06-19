package compliance

import (
	"github.com/aquasecurity/trivy/pkg/compliance/report"
	ttypes "github.com/aquasecurity/trivy/pkg/types"

	"context"
	"fmt"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"strings"
)

type Mgr interface {
	GenerateComplianceReport(ctx context.Context, spec v1alpha1.ReportSpec) error
}

func NewMgr(c client.Client) Mgr {
	return &cm{
		client: c,
	}
}

type cm struct {
	client client.Client
}

// GenerateComplianceReport generate and public compliance report by spec
func (w *cm) GenerateComplianceReport(ctx context.Context, spec v1alpha1.ReportSpec) error {
	trivyResults, err := misconfigReportToTrivyResults(w.client, ctx)
	if err != nil {
		return err
	}

	status, err := w.buildComplianceReport(spec, trivyResults)
	if err != nil {
		return err
	}
	// generate cluster compliance report
	updatedReport, err := w.createComplianceReport(ctx, spec, status)
	if err != nil {
		return err
	}
	// update compliance report status
	return w.client.Status().Update(ctx, updatedReport)

}

// createComplianceReport create compliance report
func (w *cm) createComplianceReport(ctx context.Context, reportSpec v1alpha1.ReportSpec, reportStatus v1alpha1.ReportStatus) (*v1alpha1.ClusterComplianceReport, error) {
	reportStatus.UpdateTimestamp = metav1.NewTime(ext.NewSystemClock().Now())
	r := v1alpha1.ClusterComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: strings.ToLower(reportSpec.Complaince.ID),
		},
		Status: reportStatus,
	}
	var existing v1alpha1.ClusterComplianceReport
	err := w.client.Get(ctx, types.NamespacedName{
		Name: strings.ToLower(reportSpec.Complaince.ID),
	}, &existing)
	if err != nil {
		return nil, fmt.Errorf("compliance crd with name %s is missing", reportSpec.Complaince.ID)
	}
	copied := existing.DeepCopy()
	copied.Labels = r.Labels
	copied.Status = r.Status
	copied.Spec = reportSpec
	copied.Status.UpdateTimestamp = metav1.NewTime(ext.NewSystemClock().Now())
	return copied, nil
}

// BuildComplianceReport build compliance based on report type {summary | detail}
func (w *cm) buildComplianceReport(spec v1alpha1.ReportSpec, complianceResults []ttypes.Results) (v1alpha1.ReportStatus, error) {
	trivyCompSpec := v1alpha1.ToComplainceSpec(spec.Complaince)
	cr, err := report.BuildComplianceReport(complianceResults, trivyCompSpec)
	if err != nil {
		return v1alpha1.ReportStatus{}, err
	}
	summary := v1alpha1.TotalsCheckCount(cr)
	switch spec.ReportFormat {
	case v1alpha1.ReportSummary:
		rs := report.BuildSummary(cr)
		return v1alpha1.ReportStatus{SummaryReport: v1alpha1.FromSummaryReport(rs), Summary: summary}, nil
	case v1alpha1.ReportDetail:
		return v1alpha1.ReportStatus{DetailReport: v1alpha1.FromDetailReport(cr), Summary: summary}, nil
	default:
		return v1alpha1.ReportStatus{}, fmt.Errorf("report type is invalid")
	}
}

// MisconfigReportToTrivyResults convert misconfig and infra assessment report Data to trivy results
func misconfigReportToTrivyResults(cli client.Client, ctx context.Context) ([]ttypes.Results, error) {
	resultsArray := make([]ttypes.Results, 0)
	// collect configaudit report data
	caObjList := &v1alpha1.ConfigAuditReportList{}
	err := cli.List(ctx, caObjList)
	if err != nil {
		return nil, err
	}
	for _, ca := range caObjList.Items {
		results := reportsToResults(ca.Report.Checks, ca.Name, ca.Namespace)
		resultsArray = append(resultsArray, results)
	}
	// collect rbac assessment report data
	raObjList := &v1alpha1.RbacAssessmentReportList{}
	err = cli.List(ctx, raObjList)
	if err != nil {
		return nil, err
	}
	for _, ra := range raObjList.Items {
		results := reportsToResults(ra.Report.Checks, ra.Name, ra.Namespace)
		resultsArray = append(resultsArray, results)
	}
	// collect cluster rbac assessment report data
	craObjList := &v1alpha1.ClusterRbacAssessmentReportList{}
	err = cli.List(ctx, craObjList)
	if err != nil {
		return nil, err
	}
	for _, cra := range craObjList.Items {
		results := reportsToResults(cra.Report.Checks, cra.Name, cra.Namespace)
		resultsArray = append(resultsArray, results)
	}
	// collect infra assessment report data
	iaObjList := &v1alpha1.InfraAssessmentReportList{}
	err = cli.List(ctx, iaObjList)
	if err != nil {
		return nil, err
	}
	for _, ia := range iaObjList.Items {
		results := reportsToResults(ia.Report.Checks, ia.Name, ia.Namespace)
		resultsArray = append(resultsArray, results)
	}
	// collect cluster infra assessment report data
	ciaObjList := &v1alpha1.ClusterInfraAssessmentReportList{}
	err = cli.List(ctx, ciaObjList)
	if err != nil {
		return nil, err
	}
	for _, cia := range ciaObjList.Items {
		results := reportsToResults(cia.Report.Checks, cia.Name, cia.Namespace)
		resultsArray = append(resultsArray, results)
	}
	return resultsArray, nil
}

func reportsToResults(checks []v1alpha1.Check, name string, namespace string) ttypes.Results {
	results := ttypes.Results{}
	for _, check := range checks {
		status := ttypes.StatusFailure
		if check.Success {
			status = ttypes.StatusPassed
		}
		id := check.ID
		if !strings.HasPrefix(check.ID, "AVD-") {
			if strings.HasPrefix(check.ID, "KSV") {
				id = fmt.Sprintf("%s-%s-%s", "AVD", "KSV", strings.Replace(check.ID, "KSV", "0", -1))
			}
			if strings.HasPrefix(check.ID, "KCV") {
				id = fmt.Sprintf("%s-%s-%s", "AVD", "KCV", strings.Replace(check.ID, "KCV", "", -1))
			}
		}
		misconfigResult := ttypes.Result{Target: fmt.Sprintf("%s/%s", namespace, name),
			Misconfigurations: []ttypes.DetectedMisconfiguration{{
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
