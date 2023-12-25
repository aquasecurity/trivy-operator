package sbomreport

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	fg "github.com/aquasecurity/trivy/pkg/flag"
	tr "github.com/aquasecurity/trivy/pkg/report"
	ty "github.com/aquasecurity/trivy/pkg/types"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Writer is the interface that wraps the basic Write method.
//
// Write creates or updates the given slice of v1alpha1.SbomReport
// instances.
type Writer interface {
	Write(context.Context, []v1alpha1.SbomReport) error
	WriteCluster(context.Context, []v1alpha1.ClusterSbomReport) error
}

// Reader is the interface that wraps methods for finding v1alpha1.SbomReport objects.
//
// FindByOwner returns the slice of v1alpha1.SbomReport instances
// owned by the given kube.ObjectRef or an empty slice if the reports are not found.
type Reader interface {
	FindByOwner(context.Context, kube.ObjectRef) ([]v1alpha1.SbomReport, error)
	FindReportByImageRef(ctx context.Context, imageRef string) ([]v1alpha1.ClusterSbomReport, error)
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

func (r *readWriter) WriteCluster(ctx context.Context, reports []v1alpha1.ClusterSbomReport) error {
	for _, report := range reports {
		err := r.createOrUpdateCluster(ctx, report)
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

func (r *readWriter) createOrUpdateCluster(ctx context.Context, report v1alpha1.ClusterSbomReport) error {
	var existing v1alpha1.ClusterSbomReport
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

func (r *readWriter) FindByOwner(ctx context.Context, owner kube.ObjectRef) ([]v1alpha1.SbomReport, error) {
	var list v1alpha1.SbomReportList

	labels := client.MatchingLabels(kube.ObjectRefToLabels(owner))

	err := r.List(ctx, &list, labels, client.InNamespace(owner.Namespace))
	if err != nil {
		return nil, err
	}

	return list.DeepCopy().Items, nil
}

func (r *readWriter) FindReportByImageRef(ctx context.Context, imageRef string) ([]v1alpha1.ClusterSbomReport, error) {
	var list v1alpha1.ClusterSbomReportList
	imageRef, err := ImageRef(imageRef)
	if err != nil {
		return nil, err
	}
	labels := client.MatchingLabels(map[string]string{
		trivyoperator.LabelResourceImageID: imageRef,
	})

	err = r.List(ctx, &list, labels)
	if err != nil {
		return nil, err
	}

	return list.DeepCopy().Items, nil
}

func ImageRef(imageRef string) (string, error) {
	parsedRef, err := ParseReference(imageRef)
	if err != nil {
		return "", err
	}
	server := parsedRef.Context().RegistryStr()
	repo := parsedRef.Context().RepositoryStr()
	tag := parsedRef.Identifier()

	return ReportGlobalName(fmt.Sprintf("%s/%s:%s", server, strings.TrimPrefix(repo, "library/"), tag)), nil
}

func BuildSbomReportData(reports ty.Report, clock ext.Clock, registry v1alpha1.Registry, artifact v1alpha1.Artifact, version string) (*v1alpha1.SbomReportData, error) {
	bom, err := generateSbomFromScanResult(reports)
	if err != nil {
		return nil, err
	}
	if bom == nil {
		return nil, nil
	}
	return &v1alpha1.SbomReportData{
		UpdateTimestamp: metav1.NewTime(clock.Now()),
		Scanner: v1alpha1.Scanner{
			Name:    v1alpha1.ScannerNameTrivy,
			Vendor:  "Aqua Security",
			Version: version,
		},
		Registry: registry,
		Artifact: artifact,
		Summary:  BomSummary(*bom),
		Bom:      *bom,
	}, nil
}

func generateSbomFromScanResult(report ty.Report) (*v1alpha1.BOM, error) {
	var bom *v1alpha1.BOM
	if len(report.Results) > 0 && len(report.Results[0].Packages) > 0 {
		// capture os.Stdout with a writer
		done := capture()
		err := tr.Write(context.TODO(), report, fg.Options{
			ReportOptions: fg.ReportOptions{
				Format: ty.FormatCycloneDX,
			},
		})
		if err != nil {
			return nil, err
		}
		bomWriter, err := done()
		if err != nil {
			return nil, err
		}
		var bom cdx.BOM
		err = json.Unmarshal([]byte(bomWriter), &bom)
		if err != nil {
			return nil, err
		}
		return cycloneDxBomToReport(bom), nil
	}
	return bom, nil
}

func BomSummary(bom v1alpha1.BOM) v1alpha1.SbomSummary {
	return v1alpha1.SbomSummary{
		ComponentsCount:   len(bom.Components) + 1,
		DependenciesCount: len(*bom.Dependencies),
	}
}
