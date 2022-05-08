package kubebench

import (
	"context"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Writer interface {
	Write(ctx context.Context, report v1alpha1.CISKubeBenchReport) error
}

type Reader interface {
	FindByOwner(ctx context.Context, node kube.ObjectRef) (*v1alpha1.CISKubeBenchReport, error)
}

type ReadWriter interface {
	Writer
	Reader
}

type rw struct {
	client client.Client
}

func NewReadWriter(client client.Client) ReadWriter {
	return &rw{
		client: client,
	}
}

func (w *rw) Write(ctx context.Context, report v1alpha1.CISKubeBenchReport) error {
	// TODO Try CreateOrUpdate method
	var existing v1alpha1.CISKubeBenchReport
	err := w.client.Get(ctx, types.NamespacedName{
		Name: report.Name,
	}, &existing)

	if err == nil {
		copied := existing.DeepCopy()
		copied.Labels = report.Labels
		copied.Report = report.Report

		return w.client.Update(ctx, copied)
	}

	if errors.IsNotFound(err) {
		return w.client.Create(ctx, &report)
	}

	return err
}

func (w *rw) FindByOwner(ctx context.Context, node kube.ObjectRef) (*v1alpha1.CISKubeBenchReport, error) {
	report := &v1alpha1.CISKubeBenchReport{}
	err := w.client.Get(ctx, types.NamespacedName{
		Name: node.Name,
	}, report)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return report, nil
}
