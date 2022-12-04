package compliance

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy/pkg/compliance/report"
	ttypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	ResourceDoNotExistInCluster = "Resource do not exist in cluster"
)

type Mgr interface {
	GenerateComplianceReport(ctx context.Context, spec v1alpha1.ReportSpec) error
}

func NewMgr(c client.Client, log logr.Logger, config trivyoperator.ConfigData) Mgr {
	return &cm{
		client: c,
		log:    log,
		config: config,
	}
}

type cm struct {
	client client.Client
	log    logr.Logger
	config trivyoperator.ConfigData
}

// GenerateComplianceReport generate and public compliance report by spec
func (w *cm) GenerateComplianceReport(ctx context.Context, spec v1alpha1.ReportSpec) error {
	// map specs to key/value map for easy processing
	trivyResults, err := MisconfigReportToTrivyResults(w.client, ctx)
	if err != nil {
		return err
	}

	status, err := w.buildComplianceReport(spec, trivyResults)
	if err != nil {
		return err
	}
	//generate cluster compliance report
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
			Name: strings.ToLower(reportSpec.Complaince.Title),
		},
		Status: reportStatus,
	}
	var existing v1alpha1.ClusterComplianceReport
	err := w.client.Get(ctx, types.NamespacedName{
		Name: strings.ToLower(reportSpec.Complaince.Title),
	}, &existing)
	if err != nil {
		return nil, fmt.Errorf("compliance crd with name %s is missing", reportSpec.Complaince.Title)
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
	switch spec.ReportFormat {
	case v1alpha1.ReportSummary:
		rs := report.BuildSummary(cr)
		return v1alpha1.ReportStatus{SummaryReport: v1alpha1.FromSummaryReport(rs), TotalCounts: v1alpha1.TotalsCheckCount(cr)}, nil
	case v1alpha1.ReportDetail:
		return v1alpha1.ReportStatus{DetailReport: v1alpha1.FromDetailReport(cr), TotalCounts: v1alpha1.TotalsCheckCount(cr)}, nil
	default:
		return v1alpha1.ReportStatus{}, fmt.Errorf("report type is invalid")
	}
}
