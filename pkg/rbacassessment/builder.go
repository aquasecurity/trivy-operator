package rbacassessment

import (
	"context"
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
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type ReportBuilder struct {
	scheme                  *runtime.Scheme
	controller              client.Object
	resourceSpecHash        string
	pluginConfigHash        string
	data                    v1alpha1.RbacAssessmentReportData
	reportTTL               *time.Duration
	resourceLabelsToInclude []string
	additionalReportLabels  labels.Set
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

func (b *ReportBuilder) ResourceSpecHash(hash string) *ReportBuilder {
	b.resourceSpecHash = hash
	return b
}

func (b *ReportBuilder) PluginConfigHash(hash string) *ReportBuilder {
	b.pluginConfigHash = hash
	return b
}

func (b *ReportBuilder) Data(data v1alpha1.RbacAssessmentReportData) *ReportBuilder {
	b.data = data
	return b
}

func (b *ReportBuilder) ReportTTL(ttl *time.Duration) *ReportBuilder {
	b.reportTTL = ttl
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

func (b *ReportBuilder) reportName() string {
	kind := b.controller.GetObjectKind().GroupVersionKind().Kind
	name := b.controller.GetName()
	reportName := fmt.Sprintf("%s-%s", strings.ToLower(kind), name)
	if len(validation.IsDNS1123Label(reportName)) == 0 {
		return reportName
	}
	return fmt.Sprintf("%s-%s", strings.ToLower(kind), kube.ComputeHash(name))
}

func (b *ReportBuilder) GetClusterReport() (v1alpha1.ClusterRbacAssessmentReport, error) {
	labelsSet := make(labels.Set)
	// append matching resource labels by config to report
	kube.AppendResourceLabels(b.resourceLabelsToInclude, b.controller.GetLabels(), labelsSet)
	// append custom labels by config to report
	kube.AppendCustomLabels(b.additionalReportLabels, labelsSet)
	if b.resourceSpecHash != "" {
		labelsSet[trivyoperator.LabelResourceSpecHash] = b.resourceSpecHash
	}
	if b.pluginConfigHash != "" {
		labelsSet[trivyoperator.LabelPluginConfigHash] = b.pluginConfigHash
	}

	report := v1alpha1.ClusterRbacAssessmentReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:   b.reportName(),
			Labels: labelsSet,
		},
		Report: b.data,
	}
	err := kube.ObjectToObjectMeta(b.controller, &report.ObjectMeta)
	if err != nil {
		return v1alpha1.ClusterRbacAssessmentReport{}, err
	}
	err = controllerutil.SetControllerReference(b.controller, &report, b.scheme)
	if err != nil {
		return v1alpha1.ClusterRbacAssessmentReport{}, fmt.Errorf("setting controller reference: %w", err)
	}
	// The OwnerReferencesPermissionsEnforcement admission controller protects the
	// access to metadata.ownerReferences[x].blockOwnerDeletion of an object, so
	// that only users with "update" permission to the finalizers subresource of the
	// referenced owner can change it.
	// We set metadata.ownerReferences[x].blockOwnerDeletion to false so that
	// additional RBAC permissions are not required when the OwnerReferencesPermissionsEnforcement
	// is enabled.
	// See https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#ownerreferencespermissionenforcement
	report.OwnerReferences[0].BlockOwnerDeletion = pointer.Bool(false)
	return report, nil
}

func (b *ReportBuilder) GetReport() (v1alpha1.RbacAssessmentReport, error) {
	labelsSet := make(labels.Set)
	// append matching resource labels by config to report
	kube.AppendResourceLabels(b.resourceLabelsToInclude, b.controller.GetLabels(), labelsSet)
	// append custom labels by config to report
	kube.AppendCustomLabels(b.additionalReportLabels, labelsSet)
	if b.resourceSpecHash != "" {
		labelsSet[trivyoperator.LabelResourceSpecHash] = b.resourceSpecHash
	}
	if b.pluginConfigHash != "" {
		labelsSet[trivyoperator.LabelPluginConfigHash] = b.pluginConfigHash
	}

	report := v1alpha1.RbacAssessmentReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.reportName(),
			Namespace: b.controller.GetNamespace(),
			Labels:    labelsSet,
		},
		Report: b.data,
	}
	if b.reportTTL != nil {
		report.Annotations = map[string]string{
			v1alpha1.TTLReportAnnotation: b.reportTTL.String(),
		}
	}
	err := kube.ObjectToObjectMeta(b.controller, &report.ObjectMeta)
	if err != nil {
		return v1alpha1.RbacAssessmentReport{}, err
	}
	err = controllerutil.SetControllerReference(b.controller, &report, b.scheme)
	if err != nil {
		return v1alpha1.RbacAssessmentReport{}, fmt.Errorf("setting controller reference: %w", err)
	}
	// The OwnerReferencesPermissionsEnforcement admission controller protects the
	// access to metadata.ownerReferences[x].blockOwnerDeletion of an object, so
	// that only users with "update" permission to the finalizers subresource of the
	// referenced owner can change it.
	// We set metadata.ownerReferences[x].blockOwnerDeletion to false so that
	// additional RBAC permissions are not required when the OwnerReferencesPermissionsEnforcement
	// is enabled.
	// See https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#ownerreferencespermissionenforcement
	report.OwnerReferences[0].BlockOwnerDeletion = pointer.Bool(false)
	return report, nil
}

func (b *ReportBuilder) Write(ctx context.Context, writer Writer) error {
	if kube.IsClusterScopedKind(b.controller.GetObjectKind().GroupVersionKind().Kind) {
		report, err := b.GetClusterReport()
		if err != nil {
			return err
		}
		return writer.WriteClusterReport(ctx, report)
	}
	report, err := b.GetReport()
	if err != nil {
		return err
	}
	return writer.WriteReport(ctx, report)

}
