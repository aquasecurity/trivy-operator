package compliance

import (
	"context"
	"fmt"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/emirpasic/gods/sets/hashset"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	//KubeBench scanner name as appear in specs file
	KubeBench = "kube-bench"
	//ConfigAudit scanner name as appear in specs file
	ConfigAudit = "config-audit"
)

type Mapper interface {
	mapReportData(objType string, objList client.ObjectList) map[string]*ScannerCheckResult
}

type kubeBench struct {
}

type configAudit struct {
}

func byScanner(scanner string) (Mapper, error) {
	switch scanner {
	case KubeBench:
		return &kubeBench{}, nil
	case ConfigAudit:
		return &configAudit{}, nil
	}
	// scanner is not supported
	return nil, fmt.Errorf("mapper scanner: %s is not supported", scanner)
}

type CheckDetails struct {
	ID          string
	Status      string
	Remediation string
}

func (kb kubeBench) mapReportData(objType string, objList client.ObjectList) map[string]*ScannerCheckResult {
	scannerCheckResultMap := make(map[string]*ScannerCheckResult, 0)
	cb, ok := objList.(*v1alpha1.CISKubeBenchReportList)
	if !ok || len(cb.Items) == 0 {
		return scannerCheckResultMap
	}
	for _, item := range cb.Items {
		name := item.GetName()
		nameSpace := item.Namespace
		for _, section := range item.Report.Sections {
			for _, check := range section.Tests {
				for _, result := range check.Results {
					if _, ok := scannerCheckResultMap[result.TestNumber]; !ok {
						scannerCheckResultMap[result.TestNumber] = &ScannerCheckResult{ID: result.TestNumber, Remediation: result.Remediation, ObjectType: objType}
						scannerCheckResultMap[result.TestNumber].Details = make([]ResultDetails, 0)
					}
					scannerCheckResultMap[result.TestNumber].Details = append(scannerCheckResultMap[result.TestNumber].Details, ResultDetails{Name: name, Namespace: nameSpace, Status: v1alpha1.ControlStatus(result.Status)})
				}
			}
		}
	}
	return scannerCheckResultMap
}

func (ac configAudit) mapReportData(objType string, objList client.ObjectList) map[string]*ScannerCheckResult {
	scannerCheckResultMap := make(map[string]*ScannerCheckResult, 0)
	cb, ok := objList.(*v1alpha1.ConfigAuditReportList)
	if !ok || len(cb.Items) == 0 {
		return scannerCheckResultMap
	}
	for _, item := range cb.Items {
		for _, check := range item.Report.Checks {
			if _, ok := scannerCheckResultMap[check.ID]; !ok {
				scannerCheckResultMap[check.ID] = &ScannerCheckResult{ID: check.ID, Remediation: check.Remediation, ObjectType: objType}
				scannerCheckResultMap[check.ID].Details = make([]ResultDetails, 0)
			}
			var message string
			if len(check.Messages) > 0 {
				message = check.Messages[0]
			}
			var status = v1alpha1.FailStatus
			if check.Success {
				status = v1alpha1.PassStatus
			}
			scannerCheckResultMap[check.ID].Details = append(scannerCheckResultMap[check.ID].Details, ResultDetails{Name: item.GetName(), Namespace: item.Namespace, Msg: message, Status: status})

		}
	}
	return scannerCheckResultMap
}

func mapComplianceScannerToResource(cli client.Client, ctx context.Context, resourceListNames map[string]*hashset.Set) map[string]map[string]client.ObjectList {
	scannerResource := make(map[string]map[string]client.ObjectList)
	for scanner, objNames := range resourceListNames {
		for _, objName := range objNames.Values() {
			objNameString, ok := objName.(string)
			if !ok {
				continue
			}
			labels := map[string]string{
				trivyoperator.LabelResourceKind: objNameString,
			}
			matchingLabel := client.MatchingLabels(labels)
			objList := getObjListByName(scanner)
			err := cli.List(ctx, objList, matchingLabel)
			if err != nil {
				continue
			}
			if _, ok := scannerResource[scanner]; !ok {
				scannerResource[scanner] = make(map[string]client.ObjectList)
			}
			scannerResource[scanner][objNameString] = objList
		}
	}
	return scannerResource
}

func getObjListByName(scannerName string) client.ObjectList {
	switch scannerName {
	case KubeBench:
		return &v1alpha1.CISKubeBenchReportList{}
	case ConfigAudit:
		return &v1alpha1.ConfigAuditReportList{}
	default:
		return nil
	}
}

type ResultDetails struct {
	Name      string
	Namespace string
	Msg       string
	Status    v1alpha1.ControlStatus
}

type ScannerCheckResult struct {
	ObjectType  string
	ID          string
	Remediation string
	Details     []ResultDetails
}
