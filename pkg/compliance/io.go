package compliance

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy/pkg/compliance/report"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/emirpasic/gods/sets/hashset"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

type summaryTotal struct {
	pass int
	fail int
}

type specDataMapping struct {
	scannerResourceListNames map[string]*hashset.Set
	controlIDControlObject   map[string]v1alpha1.Control
	controlCheckIds          map[string][]string
	controlIdResources       map[string][]string
}

func (w *cm) GenerateComplianceReport(ctx context.Context, spec v1alpha1.ReportSpec) error {
	// map specs to key/value map for easy processing
	smd := w.populateSpecDataToMaps(spec)
	// map compliance scanner to resource data
	scannerResourceMap := mapComplianceScannerToResource(w.client, ctx, smd.scannerResourceListNames)
	// organized data by check id and it aggregated results
	checkIdsToResults, err := w.checkIdsToResults(scannerResourceMap)
	if err != nil {
		return err
	}
	// map scanner checks results to control check results
	controlChecks := w.controlChecksByScannerChecks(smd, checkIdsToResults)
	// find summary totals
	st := w.getTotals(controlChecks)
	//create cluster compliance details report
	err = w.createComplianceDetailReport(ctx, spec, smd, checkIdsToResults, st)
	if err != nil {
		return fmt.Errorf("failed to create compliance detail report name: %s with error %w", strings.ToLower(fmt.Sprintf("%s-%s", spec.Name, "details")), err)
	}
	//generate cluster compliance report
	updatedReport, err := w.createComplianceReport(ctx, spec, st, controlChecks)
	if err != nil {
		return err
	}
	// update compliance report status
	return w.client.Status().Update(ctx, updatedReport)

}

// createComplianceReport create compliance report
func (w *cm) createComplianceReport(ctx context.Context, spec v1alpha1.ReportSpec, st summaryTotal, controlChecks []v1alpha1.ControlCheck) (*v1alpha1.ClusterComplianceReport, error) {
	statusControlChecks := make([]v1alpha1.ControlCheck, 0)
	//check if status data should be updated
	if st.fail > 0 || st.pass > 0 {
		statusControlChecks = append(statusControlChecks, controlChecks...)
	}
	summary := v1alpha1.ClusterComplianceSummary{PassCount: st.pass, FailCount: st.fail}
	report := v1alpha1.ClusterComplianceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: strings.ToLower(spec.Name),
		},
		Status: v1alpha1.ReportStatus{UpdateTimestamp: metav1.NewTime(ext.NewSystemClock().Now()), Summary: summary, ControlChecks: statusControlChecks},
	}
	var existing v1alpha1.ClusterComplianceReport
	err := w.client.Get(ctx, types.NamespacedName{
		Name: strings.ToLower(spec.Name),
	}, &existing)
	if err != nil {
		return nil, fmt.Errorf("compliance crd with name %s is missing", spec.Name)
	}
	copied := existing.DeepCopy()
	copied.Labels = report.Labels
	copied.Status = report.Status
	copied.Spec = spec
	copied.Status.UpdateTimestamp = metav1.NewTime(ext.NewSystemClock().Now())
	return copied, nil
}

// getTotals return control check totals
func (w *cm) getTotals(controlChecks []v1alpha1.ControlCheck) summaryTotal {
	var totalFail, totalPass int
	if len(controlChecks) > 0 {
		for _, controlCheck := range controlChecks {
			totalFail = totalFail + controlCheck.FailTotal
			totalPass = totalPass + controlCheck.PassTotal
		}
	}
	return summaryTotal{fail: totalFail, pass: totalPass}
}

// controlChecksByScannerChecks build control checks list by parsing test results and mapping it to relevant scanner
func (w *cm) controlChecksByScannerChecks(smd *specDataMapping, checkIdsToResults map[string][]*ScannerCheckResult) []v1alpha1.ControlCheck {
	controlChecks := make([]v1alpha1.ControlCheck, 0)
	if len(checkIdsToResults) == 0 {
		return controlChecks
	}
	for controlID, checkIds := range smd.controlCheckIds {
		var passTotal, failTotal, total int
		for _, checkId := range checkIds {
			results, ok := checkIdsToResults[checkId]
			if ok {
				for _, checkResult := range results {
					for _, crd := range checkResult.Details {
						switch crd.Status {
						case v1alpha1.PassStatus, v1alpha1.WarnStatus:
							passTotal++
						case v1alpha1.FailStatus:
							failTotal++
						}
						total++
					}
				}
			}
		}
		control, ok := smd.controlIDControlObject[controlID]
		if ok {
			if passTotal == 0 && failTotal == 0 {
				if control.DefaultStatus == v1alpha1.FailStatus {
					failTotal = 1
				}
				if control.DefaultStatus == v1alpha1.PassStatus {
					passTotal = 1
				}
			}
			controlChecks = append(controlChecks, v1alpha1.ControlCheck{ID: controlID,
				Name:        control.Name,
				Description: control.Description,
				Severity:    control.Severity,
				PassTotal:   passTotal,
				FailTotal:   failTotal})
		}
	}
	return controlChecks
}

// controlChecksDetailsByScannerChecks build control checks with details list by parsing test results and mapping it to relevant tool
func (w *cm) controlChecksDetailsByScannerChecks(smd *specDataMapping, checkIdsToResults map[string][]*ScannerCheckResult) []v1alpha1.ControlCheckDetails {
	controlChecks := make([]v1alpha1.ControlCheckDetails, 0)
	if len(checkIdsToResults) == 0 {
		return controlChecks
	}
	for controlID, checkIds := range smd.controlCheckIds {
		control, ok := smd.controlIDControlObject[controlID]
		if ok {
			for _, checkId := range checkIds {
				results, ok := checkIdsToResults[checkId]
				ctta := make([]v1alpha1.ScannerCheckResult, 0)
				if ok {
					scr := w.createScanCheckResult(results)
					ctta = append(ctta, scr...)
				} else {
					w.createDefaultScanResult(smd, control, controlID, &ctta)
				}
				if len(ctta) > 0 {
					controlChecks = append(controlChecks, v1alpha1.ControlCheckDetails{ID: controlID,
						Name:               control.Name,
						Description:        control.Description,
						Severity:           control.Severity,
						ScannerCheckResult: ctta})
				}
			}
		}
	}
	return controlChecks
}

func (w *cm) createDefaultScanResult(smd *specDataMapping, control v1alpha1.Control, controlID string, ctta *[]v1alpha1.ScannerCheckResult) {
	if control.DefaultStatus == v1alpha1.FailStatus {
		resources := smd.controlIdResources[controlID]
		for _, resource := range resources {
			ctt := v1alpha1.ScannerCheckResult{ObjectType: resource, Details: []v1alpha1.ResultDetails{{Msg: ResourceDoNotExistInCluster, Status: v1alpha1.FailStatus}}}
			*ctta = append(*ctta, ctt)
		}
	}
}

func (w *cm) createScanCheckResult(results []*ScannerCheckResult) []v1alpha1.ScannerCheckResult {
	ctta := make([]v1alpha1.ScannerCheckResult, 0)
	for _, checkResult := range results {
		var ctt v1alpha1.ScannerCheckResult
		failedResultEntries := make([]v1alpha1.ResultDetails, 0)
		for _, crd := range checkResult.Details {
			if len(failedResultEntries) >= w.config.ComplianceFailEntriesLimit() {
				continue
			}
			//control check detail relevant to fail checks only
			if crd.Status == v1alpha1.PassStatus || crd.Status == v1alpha1.WarnStatus {
				continue
			}
			failedResultEntries = append(failedResultEntries, v1alpha1.ResultDetails{Name: crd.Name, Namespace: crd.Namespace, Msg: crd.Msg, Status: crd.Status})
		}
		if len(failedResultEntries) > 0 {
			ctt = v1alpha1.ScannerCheckResult{ID: checkResult.ID, ObjectType: checkResult.ObjectType, Remediation: checkResult.Remediation, Details: failedResultEntries}
			ctta = append(ctta, ctt)
		}
	}
	return ctta
}

func (w *cm) checkIdsToResults(scannerResourceMap map[string]map[string]client.ObjectList) (map[string][]*ScannerCheckResult, error) {
	checkIdsToResults := make(map[string][]*ScannerCheckResult)
	for scanner, resourceListMap := range scannerResourceMap {
		for resourceName, resourceList := range resourceListMap {
			mapper, err := byScanner(scanner)
			if err != nil {
				return nil, err
			}
			idCheckResultMap := mapper.mapReportData(resourceName, resourceList)
			if idCheckResultMap == nil {
				continue
			}
			for id, scannerCheckResult := range idCheckResultMap {
				if _, ok := checkIdsToResults[id]; !ok {
					checkIdsToResults[id] = make([]*ScannerCheckResult, 0)
				}
				checkIdsToResults[id] = append(checkIdsToResults[id], scannerCheckResult)
			}
		}
	}
	return checkIdsToResults, nil
}

// BuildComplianceReport build compliance based on report type {summary | detail}
func (w *cm) BuildComplianceReport(spec v1alpha1.ReportSpec, complianceResults []types.Results) (v1alpha1.ReportStatus, error) {
	trivyCompSpec := v1alpha1.ToComplainceSpec(spec.Complaince)
	cr, err := report.BuildComplianceReport(complianceResults, trivyCompSpec)
	if err != nil {
		return v1alpha1.ReportStatus{}, err
	}
	switch spec.ReportFormat {
	case v1alpha1.ReportSummary:
		rs := report.BuildSummary(cr)
		return v1alpha1.ReportStatus{SummaryReport: v1alpha1.FromSummaryReport(rs)}, nil
	case v1alpha1.ReportDetail:
		return v1alpha1.ReportStatus{DetailReport: v1alpha1.FromDetailReport(cr)}, nil
	}
	return v1alpha1.ReportStatus{}, fmt.Errorf("report type is invalid")
}
