package report

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/kubebench"
	"github.com/aquasecurity/trivy-operator/pkg/report/templates"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type workloadReporter struct {
	clock                      ext.Clock
	vulnerabilityReportsReader vulnerabilityreport.ReadWriter
	configAuditReportsReader   configauditreport.ReadWriter
}

func NewWorkloadReporter(clock ext.Clock, client client.Client) WorkloadReporter {
	return &workloadReporter{
		clock:                      clock,
		vulnerabilityReportsReader: vulnerabilityreport.NewReadWriter(client),
		configAuditReportsReader:   configauditreport.NewReadWriter(client),
	}
}

func (h *workloadReporter) RetrieveData(workload kube.ObjectRef) (templates.WorkloadReport, error) {
	ctx := context.Background()
	configAuditReport, err := h.configAuditReportsReader.FindReportByOwnerInHierarchy(ctx, workload)
	if err != nil {
		return templates.WorkloadReport{}, err
	}
	vulnerabilityReports, err := h.vulnerabilityReportsReader.FindByOwnerInHierarchy(ctx, workload)
	if err != nil {
		return templates.WorkloadReport{}, err
	}

	vulnsReports := map[string]v1alpha1.VulnerabilityReportData{}
	for _, vulnerabilityReport := range vulnerabilityReports {
		containerName, ok := vulnerabilityReport.Labels[trivyoperator.LabelContainerName]
		if !ok {
			continue
		}

		sort.Stable(vulnerabilityreport.BySeverity{Vulnerabilities: vulnerabilityReport.Report.Vulnerabilities})

		vulnsReports[containerName] = vulnerabilityReport.Report
	}
	if configAuditReport == nil && len(vulnsReports) == 0 {
		return templates.WorkloadReport{}, fmt.Errorf("no configaudits or vulnerabilities found for workload %s/%s/%s",
			workload.Namespace, workload.Kind, workload.Name)
	}
	return templates.WorkloadReport{
		Workload:          workload,
		GeneratedAt:       h.clock.Now(),
		VulnsReports:      vulnsReports,
		ConfigAuditReport: configAuditReport,
	}, nil
}

func (h *workloadReporter) Generate(workload kube.ObjectRef, writer io.Writer) error {
	data, err := h.RetrieveData(workload)
	if err != nil {
		return err
	}

	templates.WritePageTemplate(writer, &data)
	return nil
}

type namespaceReporter struct {
	clock  ext.Clock
	client client.Client
}

func NewNamespaceReporter(clock ext.Clock, client client.Client) NamespaceReporter {
	return &namespaceReporter{
		clock:  clock,
		client: client,
	}
}

func (r *namespaceReporter) RetrieveData(namespace kube.ObjectRef) (templates.NamespaceReport, error) {
	var vulnerabilityReportList v1alpha1.VulnerabilityReportList
	err := r.client.List(context.Background(), &vulnerabilityReportList, client.InNamespace(namespace.Name))
	if err != nil {
		return templates.NamespaceReport{}, err
	}

	var configAuditReportList v1alpha1.ConfigAuditReportList
	err = r.client.List(context.Background(), &configAuditReportList, client.InNamespace(namespace.Name))
	if err != nil {
		return templates.NamespaceReport{}, err
	}

	return templates.NamespaceReport{
		Namespace:            namespace,
		GeneratedAt:          r.clock.Now(),
		Top5VulnerableImages: r.topNImagesBySeverityCount(vulnerabilityReportList.Items, 5),
		Top5FailedChecks:     r.topNFailedChecksByAffectedWorkloadsCount(configAuditReportList.Items, 5),
		Top5Vulnerability:    r.topNVulnerabilitiesByScore(vulnerabilityReportList.Items, 5),
	}, nil
}

func (r *namespaceReporter) topNImagesBySeverityCount(reports []v1alpha1.VulnerabilityReport, N int) []v1alpha1.VulnerabilityReport {
	b := append(reports[:0:0], reports...)

	vulnerabilityreport.OrderedBy(vulnerabilityreport.SummaryCount...).
		SortDesc(b)

	return b[:ext.MinInt(N, len(b))]
}

func (r *namespaceReporter) topNFailedChecksByAffectedWorkloadsCount(reports []v1alpha1.ConfigAuditReport, N int) []templates.CheckWithCount {
	checksMap := make(map[string]templates.CheckWithCount)

	for _, report := range reports {
		for _, podCheck := range report.Report.PodChecks {
			if podCheck.Success {
				continue
			}
			configId := podCheck.ID
			_, ok := checksMap[configId]
			if ok {
				config := checksMap[configId]
				config.AffectedWorkloads++
				checksMap[configId] = config
			} else {
				checksMap[configId] = templates.CheckWithCount{
					Check:             podCheck,
					AffectedWorkloads: 1,
				}
			}
		}

		alreadyCheckedForWorkload := make(map[string]bool)
		for _, container := range report.Report.ContainerChecks {
			for _, containerCheck := range container {
				if containerCheck.Success {
					continue
				}

				configId := containerCheck.ID
				if alreadyCheckedForWorkload[configId] {
					continue
				}

				alreadyCheckedForWorkload[configId] = true
				_, ok := checksMap[configId]
				if ok {
					config := checksMap[configId]
					config.AffectedWorkloads++
					checksMap[configId] = config
				} else {
					checksMap[configId] = templates.CheckWithCount{
						Check:             containerCheck,
						AffectedWorkloads: 1,
					}
				}
			}
		}
	}

	failedChecks := make([]templates.CheckWithCount, len(checksMap))
	i := 0
	for _, check := range checksMap {
		failedChecks[i] = check
		i++
	}

	OrderedBy(checkCompareFunc...).SortDesc(failedChecks)

	return failedChecks[:ext.MinInt(N, len(failedChecks))]
}

func (r *namespaceReporter) topNVulnerabilitiesByScore(reports []v1alpha1.VulnerabilityReport, N int) []templates.VulnerabilityWithCount {
	vulnerabilityMap := make(map[string]templates.VulnerabilityWithCount)

	for _, report := range reports {
		vulnMap := make(map[string]bool)
		for _, vulnerability := range report.Report.Vulnerabilities {
			vulnId := vulnerability.VulnerabilityID
			if vulnMap[vulnId] {
				continue
			}
			vulnMap[vulnId] = true

			if _, ok := vulnerabilityMap[vulnerability.VulnerabilityID]; ok {
				tempVuln := vulnerabilityMap[vulnId]
				tempVuln.AffectedWorkloads++
				vulnerabilityMap[vulnId] = tempVuln
			} else {
				if vulnerability.Score == nil {
					continue
				}

				vulnerabilityMap[vulnId] = templates.VulnerabilityWithCount{
					Vulnerability: v1alpha1.Vulnerability{
						VulnerabilityID: vulnerability.VulnerabilityID,
						PrimaryLink:     vulnerability.PrimaryLink,
						Severity:        vulnerability.Severity,
						Score:           vulnerability.Score,
					},
					AffectedWorkloads: 1,
				}
			}
		}
	}

	vulnerabilities := make([]templates.VulnerabilityWithCount, len(vulnerabilityMap))
	i := 0
	for _, vulnerability := range vulnerabilityMap {
		vulnerabilities[i] = vulnerability
		i++
	}

	sort.SliceStable(vulnerabilities, func(i, j int) bool {
		return *vulnerabilities[i].Score > *vulnerabilities[j].Score
	})

	return vulnerabilities[:ext.MinInt(N, len(vulnerabilities))]
}

func (r *namespaceReporter) Generate(namespace kube.ObjectRef, out io.Writer) error {
	data, err := r.RetrieveData(namespace)
	if err != nil {
		return err
	}
	templates.WritePageTemplate(out, &data)
	return nil
}

type nodeReporter struct {
	clock                  ext.Clock
	client                 client.Client
	kubebenchReportsReader kubebench.ReadWriter
}

// NewNodeReporter generate the html reporter
func NewNodeReporter(clock ext.Clock, client client.Client) NodeReporter {
	return &nodeReporter{
		clock:                  clock,
		client:                 client,
		kubebenchReportsReader: kubebench.NewReadWriter(client),
	}
}

func (r *nodeReporter) Generate(node kube.ObjectRef, out io.Writer) error {
	data, err := r.RetrieveData(node)
	if err != nil {
		return err
	}
	templates.WritePageTemplate(out, &data)
	return nil
}

func (r *nodeReporter) RetrieveData(node kube.ObjectRef) (templates.NodeReport, error) {
	found := &v1alpha1.CISKubeBenchReport{}
	err := r.client.Get(context.Background(), types.NamespacedName{Name: node.Name}, found)
	if err != nil {
		return templates.NodeReport{}, err
	}

	return templates.NodeReport{
		GeneratedAt:        r.clock.Now(),
		Node:               node,
		CisKubeBenchReport: found,
	}, nil
}
