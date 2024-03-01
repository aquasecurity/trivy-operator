package sbomreport

import (
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/aws/aws-sdk-go/aws/arn"
	containerimage "github.com/google/go-containerregistry/pkg/name"
)

type ReportBuilder struct {
	scheme                  *runtime.Scheme
	controller              client.Object
	container               string
	hash                    string
	data                    v1alpha1.SbomReportData
	resourceLabelsToInclude []string
	additionalReportLabels  labels.Set
	cacheTTL                *time.Duration
}

func NewReportBuilder(scheme *runtime.Scheme) *ReportBuilder {
	return &ReportBuilder{
		scheme: scheme,
	}
}

func (b *ReportBuilder) Controller(controller client.Object) *ReportBuilder {
	b.controller = controller
	return b
}

func (b *ReportBuilder) Container(name string) *ReportBuilder {
	b.container = name
	return b
}

func (b *ReportBuilder) PodSpecHash(hash string) *ReportBuilder {
	b.hash = hash
	return b
}

func (b *ReportBuilder) Data(data v1alpha1.SbomReportData) *ReportBuilder {
	b.data = data
	return b
}

func (b *ReportBuilder) ResourceLabelsToInclude(resourceLabelsToInclude []string) *ReportBuilder {
	b.resourceLabelsToInclude = resourceLabelsToInclude
	return b
}

func (b *ReportBuilder) AdditionalReportLabels(additionalReportLabels map[string]string) *ReportBuilder {
	b.additionalReportLabels = additionalReportLabels
	return b
}

func (b *ReportBuilder) CacheTTL(cacheTTL *time.Duration) *ReportBuilder {
	b.cacheTTL = cacheTTL
	return b
}

func (b *ReportBuilder) reportName() string {
	kind := b.controller.GetObjectKind().GroupVersionKind().Kind
	name := b.controller.GetName()
	reportName := fmt.Sprintf("%s-%s-%s", strings.ToLower(kind), name, b.container)
	if len(validation.IsValidLabelValue(reportName)) == 0 {
		return reportName
	}

	return fmt.Sprintf("%s-%s", strings.ToLower(kind), kube.ComputeHash(name+"-"+b.container))
}
func ReportGlobalName(artifact string) string {
	return kube.ComputeHash(artifact)
}

func ParseReference(ref string) (containerimage.Reference, error) {
	if strings.HasPrefix(ref, "arn:aws:ecr") {
		parsed, err := arn.Parse(ref)
		if err != nil {
			return nil, err
		}
		ref = parsed.Resource
	}
	return containerimage.ParseReference(ref)
}

func (b *ReportBuilder) NamespacedReport() (v1alpha1.SbomReport, error) {
	reportLabels := map[string]string{
		trivyoperator.LabelContainerName: b.container,
	}

	// append matching resource labels by config to report
	kube.AppendResourceLabels(b.resourceLabelsToInclude, b.controller.GetLabels(), reportLabels)
	// append custom labels by config to report
	kube.AppendCustomLabels(b.additionalReportLabels, reportLabels)

	if b.hash != "" {
		reportLabels[trivyoperator.LabelResourceSpecHash] = b.hash
	}

	report := v1alpha1.SbomReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.reportName(),
			Namespace: b.controller.GetNamespace(),
			Labels:    reportLabels,
		},
		Report: b.data,
	}
	err := kube.ObjectToObjectMeta(b.controller, &report.ObjectMeta)
	if err != nil {
		return v1alpha1.SbomReport{}, err
	}
	err = controllerutil.SetControllerReference(b.controller, &report, b.scheme)
	if err != nil {
		return v1alpha1.SbomReport{}, fmt.Errorf("setting controller reference: %w", err)
	}
	// The OwnerReferencesPermissionsEnforcement admission controller protects the
	// access to metadata.ownerReferences[x].blockOwnerDeletion of an object, so
	// that only users with "update" permission to the finalizers subresource of the
	// referenced owner can change it.
	// We set metadata.ownerReferences[x].blockOwnerDeletion to false so that
	// additional RBAC permissions are not required when the OwnerReferencesPermissionsEnforcement
	// is enabled.
	// See https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#ownerreferencespermissionenforcement
	report.OwnerReferences[0].BlockOwnerDeletion = ptr.To[bool](false)
	return report, nil
}

func (b *ReportBuilder) Get() (v1alpha1.SbomReport, v1alpha1.ClusterSbomReport, error) {
	report, err := b.NamespacedReport()
	if err != nil {
		return v1alpha1.SbomReport{}, v1alpha1.ClusterSbomReport{}, err
	}
	return report, b.ClusterReport(), nil
}

func (b *ReportBuilder) ClusterReport() v1alpha1.ClusterSbomReport {
	artifactRef := ArtifactRef(b.data)
	reportLabels := map[string]string{
		trivyoperator.LabelResourceImageID: artifactRef,
	}
	kube.AppendCustomLabels(b.additionalReportLabels, reportLabels)
	clusterReport := v1alpha1.ClusterSbomReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:   artifactRef,
			Labels: reportLabels,
		},
		Report: b.data,
	}
	if b.cacheTTL != nil {
		clusterReport.Annotations = map[string]string{
			v1alpha1.TTLReportAnnotation: b.cacheTTL.String(),
		}
	}
	return clusterReport
}

func ArtifactRef(data v1alpha1.SbomReportData) string {
	return ReportGlobalName(fmt.Sprintf("%s/%s:%s", data.Registry.Server, strings.TrimPrefix(data.Artifact.Repository, "library/"), data.Artifact.Tag))
}
