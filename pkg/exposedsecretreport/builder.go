package exposedsecretreport

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type ReportBuilder struct {
	scheme                  *runtime.Scheme
	controller              client.Object
	container               string
	hash                    string
	data                    v1alpha1.ExposedSecretReportData
	resourceLabelsToInclude []string
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

func (b *ReportBuilder) Data(data v1alpha1.ExposedSecretReportData) *ReportBuilder {
	b.data = data
	return b
}

func (b *ReportBuilder) ResourceLabelsToInclude(resourceLabelsToInclude []string) *ReportBuilder {
	b.resourceLabelsToInclude = resourceLabelsToInclude
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

func (b *ReportBuilder) Get() (v1alpha1.ExposedSecretReport, error) {
	labels := map[string]string{
		trivyoperator.LabelContainerName: b.container,
	}

	objectLabels := b.controller.GetLabels()
	for _, labelToInclude := range b.resourceLabelsToInclude {
		if value, ok := objectLabels[labelToInclude]; ok {
			labels[labelToInclude] = value
		}
	}

	if b.hash != "" {
		labels[trivyoperator.LabelResourceSpecHash] = b.hash
	}

	report := v1alpha1.ExposedSecretReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.reportName(),
			Namespace: b.controller.GetNamespace(),
			Labels:    labels,
		},
		Report: b.data,
	}

	err := kube.ObjectToObjectMeta(b.controller, &report.ObjectMeta)
	if err != nil {
		return v1alpha1.ExposedSecretReport{}, err
	}
	err = controllerutil.SetControllerReference(b.controller, &report, b.scheme)
	if err != nil {
		return v1alpha1.ExposedSecretReport{}, fmt.Errorf("setting controller reference: %w", err)
	}
	// The OwnerReferencesPermissionsEnforcement admission controller protects the
	// access to metadata.ownerReferences[x].blockOwnerDeletion of an object, so
	// that only users with "update" permission to the finalizers subresource of the
	// referenced owner can change it.
	// We set metadata.ownerReferences[x].blockOwnerDeletion to false so that
	// additional RBAC permissions are not required when the OwnerReferencesPermissionsEnforcement
	// is enabled.
	// See https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#ownerreferencespermissionenforcement
	report.OwnerReferences[0].BlockOwnerDeletion = pointer.BoolPtr(false)
	return report, nil
}
