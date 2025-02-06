package exposedsecretreport

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
)

// Writer is the interface that wraps the basic Write method.
//
// Write creates or updates the given slice of v1alpha1.VulnerabilityReport
// instances.
type Writer interface {
	Write(context.Context, []v1alpha1.ExposedSecretReport) error
}

// Reader is the interface that wraps methods for finding v1alpha1.VulnerabilityReport objects.
//
// FindByOwner returns the slice of v1alpha1.VulnerabilityReport instances
// owned by the given kube.ObjectRef or an empty slice if the reports are not found.
type Reader interface {
	FindByOwner(context.Context, kube.ObjectRef) ([]v1alpha1.ExposedSecretReport, error)
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

func (r *readWriter) Write(ctx context.Context, reports []v1alpha1.ExposedSecretReport) error {
	for _, report := range reports {
		err := r.createOrUpdate(ctx, report)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *readWriter) createOrUpdate(ctx context.Context, report v1alpha1.ExposedSecretReport) error {
	var existing v1alpha1.ExposedSecretReport
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

func (r *readWriter) FindByOwner(ctx context.Context, owner kube.ObjectRef) ([]v1alpha1.ExposedSecretReport, error) {
	var list v1alpha1.ExposedSecretReportList

	labels := client.MatchingLabels(kube.ObjectRefToLabels(owner))

	err := r.List(ctx, &list, labels, client.InNamespace(owner.Namespace))
	if err != nil {
		return nil, err
	}

	return list.DeepCopy().Items, nil
}

func BuildExposedSecretsReportData(clock ext.Clock, registry v1alpha1.Registry, artifact v1alpha1.Artifact, version string, secrets []v1alpha1.ExposedSecret) v1alpha1.ExposedSecretReportData {
	return v1alpha1.ExposedSecretReportData{
		UpdateTimestamp: metav1.NewTime(clock.Now()),
		Scanner: v1alpha1.Scanner{
			Name:    v1alpha1.ScannerNameTrivy,
			Vendor:  "Aqua Security",
			Version: version,
		},
		Registry: registry,
		Artifact: artifact,
		Summary:  secretSummary(secrets),
		Secrets:  secrets,
	}
}

func secretSummary(secrets []v1alpha1.ExposedSecret) v1alpha1.ExposedSecretSummary {
	var s v1alpha1.ExposedSecretSummary
	for _, v := range secrets {
		switch v.Severity {
		case v1alpha1.SeverityCritical:
			s.CriticalCount++
		case v1alpha1.SeverityHigh:
			s.HighCount++
		case v1alpha1.SeverityMedium:
			s.MediumCount++
		case v1alpha1.SeverityLow:
			s.LowCount++
		}
	}
	return s
}
