package configauditreport

import (
	"context"
	"fmt"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Writer is the interface for saving v1alpha1.ClusterConfigAuditReport
// and v1alpha1.ConfigAuditReport instances.
type Writer interface {

	// WriteReport creates or updates the given v1alpha1.ConfigAuditReport instance.
	WriteReport(ctx context.Context, report v1alpha1.ConfigAuditReport) error

	// WriteClusterReport creates or updates the given v1alpha1.ClusterConfigAuditReport instance.
	WriteClusterReport(ctx context.Context, report v1alpha1.ClusterConfigAuditReport) error
}

// Reader is the interface that wraps methods for finding v1alpha1.ConfigAuditReport
// and v1alpha1.ClusterConfigAuditReport objects.
// TODO(danielpacak): Consider returning trivyoperator.ResourceNotFound error instead of returning nil.
type Reader interface {

	// FindReportByOwner returns a v1alpha1.ConfigAuditReport owned by the given
	// kube.ObjectRef or nil if the report is not found.
	FindReportByOwner(ctx context.Context, owner kube.ObjectRef) (*v1alpha1.ConfigAuditReport, error)

	// FindReportByOwnerInHierarchy is similar to FindReportByOwner except that it tries to find
	// a v1alpha1.ConfigAuditReport object owned by related Kubernetes objects.
	// For example, if the given owner is a Deployment, but a report is owned by the
	// active ReplicaSet (current revision) this method will return the report.
	FindReportByOwnerInHierarchy(ctx context.Context, owner kube.ObjectRef) (*v1alpha1.ConfigAuditReport, error)

	// FindClusterReportByOwner returns a v1alpha1.ClusterConfigAuditReport owned by the given
	// kube.ObjectRef or nil if the report is not found.
	FindClusterReportByOwner(ctx context.Context, owner kube.ObjectRef) (*v1alpha1.ClusterConfigAuditReport, error)
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
func NewReadWriter(client client.Client) ReadWriter {
	return &readWriter{
		ObjectResolver: &kube.ObjectResolver{Client: client},
	}
}

func (r *readWriter) WriteReport(ctx context.Context, report v1alpha1.ConfigAuditReport) error {
	var existing v1alpha1.ConfigAuditReport
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

func (r *readWriter) WriteClusterReport(ctx context.Context, report v1alpha1.ClusterConfigAuditReport) error {
	var existing v1alpha1.ClusterConfigAuditReport
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

func (r *readWriter) FindReportByOwner(ctx context.Context, owner kube.ObjectRef) (*v1alpha1.ConfigAuditReport, error) {
	var list v1alpha1.ConfigAuditReportList

	labels := client.MatchingLabels(kube.ObjectRefToLabels(owner))

	err := r.List(ctx, &list, labels, client.InNamespace(owner.Namespace))
	if err != nil {
		return nil, err
	}

	// Only one config audit per specific workload exists on the cluster
	if len(list.Items) > 0 {
		return &list.DeepCopy().Items[0], nil
	}
	return nil, nil
}

func (r *readWriter) FindReportByOwnerInHierarchy(ctx context.Context, owner kube.ObjectRef) (*v1alpha1.ConfigAuditReport, error) {
	report, err := r.FindReportByOwner(ctx, owner)
	if err != nil {
		return nil, err
	}

	// no reports found for provided owner, look for reports in related replicaset
	if report == nil && (owner.Kind == kube.KindDeployment || owner.Kind == kube.KindPod) {
		rsName, err := r.RelatedReplicaSetName(ctx, owner)
		if err != nil {
			return nil, fmt.Errorf("getting replicaset related to %s/%s: %w", owner.Kind, owner.Name, err)
		}
		report, err = r.FindReportByOwner(ctx, kube.ObjectRef{
			Kind:      kube.KindReplicaSet,
			Name:      rsName,
			Namespace: owner.Namespace,
		})

	}

	if report != nil {
		return report.DeepCopy(), nil
	}
	return nil, nil
}

func (r *readWriter) FindClusterReportByOwner(ctx context.Context, owner kube.ObjectRef) (*v1alpha1.ClusterConfigAuditReport, error) {
	var list v1alpha1.ClusterConfigAuditReportList

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
