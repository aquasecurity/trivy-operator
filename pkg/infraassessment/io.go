package infraassessment

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
)

// Writer is the interface for saving v1alpha1.InfraAssessmentReport instances.
type Writer interface {

	// WriteReport creates or updates the given v1alpha1.InfraAssessmentReport instance.
	WriteReport(ctx context.Context, report v1alpha1.InfraAssessmentReport) error

	// WriteClusterReport creates or updates the given v1alpha1.ClusterConfigAuditReport instance.
	WriteClusterReport(ctx context.Context, report v1alpha1.ClusterInfraAssessmentReport) error
}

// Reader is the interface that wraps methods for finding v1alpha1.ConfigAuditReport
// and v1alpha1.ClusterConfigAuditReport objects.
// TODO(danielpacak): Consider returning trivyoperator.ResourceNotFound error instead of returning nil.
type Reader interface {

	// FindReportByOwner returns a v1alpha1.InfraAssessmentReport owned by the given
	// kube.ObjectRef or nil if the report is not found.
	FindReportByOwner(ctx context.Context, owner kube.ObjectRef) (any, error)

	// FindClusterReportByOwner returns a v1alpha1.ClusterConfigAuditReport owned by the given
	// kube.ObjectRef or nil if the report is not found.
	FindClusterReportByOwner(ctx context.Context, owner kube.ObjectRef) (any, error)
}

type ReadWriter interface {
	Writer
	Reader
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

func (r *readWriter) WriteReport(ctx context.Context, report v1alpha1.InfraAssessmentReport) error {
	var existing v1alpha1.InfraAssessmentReport
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

func (r *readWriter) WriteClusterReport(ctx context.Context, report v1alpha1.ClusterInfraAssessmentReport) error {
	var existing v1alpha1.ClusterInfraAssessmentReport
	err := r.Get(ctx, types.NamespacedName{
		Name: report.Name,
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

func (r *readWriter) FindReportByOwner(ctx context.Context, owner kube.ObjectRef) (any, error) {
	var list v1alpha1.InfraAssessmentReportList

	labels := client.MatchingLabels(kube.ObjectRefToLabels(owner))
	err := r.List(ctx, &list, labels, client.InNamespace(owner.Namespace))
	if err != nil {
		return nil, err
	}

	if len(list.Items) > 0 {
		return &list.DeepCopy().Items[0], nil
	}
	return nil, nil
}

func (r *readWriter) FindClusterReportByOwner(ctx context.Context, owner kube.ObjectRef) (any, error) {
	var list v1alpha1.ClusterInfraAssessmentReportList

	labels := client.MatchingLabels(kube.ObjectRefToLabels(owner))

	err := r.List(ctx, &list, labels)
	if err != nil {
		return nil, err
	}

	// Only one config audit per specific workload exists on the cluster
	if len(list.Items) > 0 {
		return &list.DeepCopy().Items[0], nil
	}
	return nil, nil
}
