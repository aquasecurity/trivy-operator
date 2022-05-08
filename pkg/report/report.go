package report

import (
	"io"

	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/report/templates"
)

type WorkloadReporter interface {
	RetrieveData(workload kube.ObjectRef) (templates.WorkloadReport, error)
	Generate(workload kube.ObjectRef, out io.Writer) error
}

type NamespaceReporter interface {
	RetrieveData(namespace kube.ObjectRef) (templates.NamespaceReport, error)
	Generate(namespace kube.ObjectRef, out io.Writer) error
}

type NodeReporter interface {
	RetrieveData(node kube.ObjectRef) (templates.NodeReport, error)
	Generate(node kube.ObjectRef, out io.Writer) error
}
