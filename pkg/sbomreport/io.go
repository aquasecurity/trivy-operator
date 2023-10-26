package sbomreport

import (
	"context"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Writer is the interface that wraps the basic Write method.
//
// Write creates or updates the given slice of v1alpha1.SbomReport
// instances.
type Writer interface {
	Write(context.Context, []v1alpha1.SbomReport) error
}

// Reader is the interface that wraps methods for finding v1alpha1.SbomReport objects.
//
// FindByOwner returns the slice of v1alpha1.SbomReport instances
// owned by the given kube.ObjectRef or an empty slice if the reports are not found.
type Reader interface {
	FindByOwner(context.Context, kube.ObjectRef) ([]v1alpha1.SbomReport, error)
}

type ReadWriter interface {
	Reader
	Writer
}

type readWriter struct {
	*kube.ObjectResolver
}

// NewReadWriter constructs a new ReadWriter which is using the client package
// provided by the controller-runtime libraries for interacting with the
// Kubernetes API server.
func NewReadWriter(objectResolver *kube.ObjectResolver) ReadWriter {
	return &readWriter{
		ObjectResolver: objectResolver,
	}
}

func (r *readWriter) Write(ctx context.Context, reports []v1alpha1.SbomReport) error {
	for _, report := range reports {
		err := r.createOrUpdate(ctx, report)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *readWriter) createOrUpdate(ctx context.Context, report v1alpha1.SbomReport) error {
	var existing v1alpha1.SbomReport
	err := r.Get(ctx, types.NamespacedName{
		Name:      report.Name,
		Namespace: report.Namespace,
	}, &existing)

	if err == nil {
		copied := existing.DeepCopy()
		copied.Labels = report.Labels
		copied.Report = report.Report

		return r.Update(ctx, copied)
	}

	if errors.IsNotFound(err) {
		return r.Create(ctx, &report)
	}

	return err
}

func (r *readWriter) FindByOwner(ctx context.Context, owner kube.ObjectRef) ([]v1alpha1.SbomReport, error) {
	var list v1alpha1.SbomReportList

	labels := client.MatchingLabels(kube.ObjectRefToLabels(owner))

	err := r.List(ctx, &list, labels, client.InNamespace(owner.Namespace))
	if err != nil {
		return nil, err
	}

	return list.DeepCopy().Items, nil
}
