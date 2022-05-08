package configauditreport

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type ScanJobBuilder struct {
	plugin            Plugin
	pluginContext     trivyoperator.PluginContext
	timeout           time.Duration
	object            client.Object
	tolerations       []corev1.Toleration
	annotations       map[string]string
	podTemplateLabels labels.Set
}

func NewScanJobBuilder() *ScanJobBuilder {
	return &ScanJobBuilder{}
}

func (s *ScanJobBuilder) WithPlugin(plugin Plugin) *ScanJobBuilder {
	s.plugin = plugin
	return s
}

func (s *ScanJobBuilder) WithPluginContext(pluginContext trivyoperator.PluginContext) *ScanJobBuilder {
	s.pluginContext = pluginContext
	return s
}

func (s *ScanJobBuilder) WithTimeout(timeout time.Duration) *ScanJobBuilder {
	s.timeout = timeout
	return s
}

func (s *ScanJobBuilder) WithObject(object client.Object) *ScanJobBuilder {
	s.object = object
	return s
}

func (s *ScanJobBuilder) WithTolerations(tolerations []corev1.Toleration) *ScanJobBuilder {
	s.tolerations = tolerations
	return s
}

func (s *ScanJobBuilder) WithAnnotations(annotations map[string]string) *ScanJobBuilder {
	s.annotations = annotations
	return s
}

func (s *ScanJobBuilder) WithPodTemplateLabels(podTemplateLabels labels.Set) *ScanJobBuilder {
	s.podTemplateLabels = podTemplateLabels
	return s
}

func (s *ScanJobBuilder) Get() (*batchv1.Job, []*corev1.Secret, error) {
	jobSpec, secrets, err := s.plugin.GetScanJobSpec(s.pluginContext, s.object)
	if err != nil {
		return nil, nil, err
	}

	resourceSpecHash, err := kube.ComputeSpecHash(s.object)
	if err != nil {
		return nil, nil, err
	}

	jobSpec.Tolerations = append(jobSpec.Tolerations, s.tolerations...)

	pluginConfigHash, err := s.plugin.ConfigHash(s.pluginContext, kube.Kind(s.object.GetObjectKind().GroupVersionKind().Kind))
	if err != nil {
		return nil, nil, err
	}

	labelsSet := labels.Set{
		trivyoperator.LabelResourceSpecHash:         resourceSpecHash,
		trivyoperator.LabelPluginConfigHash:         pluginConfigHash,
		trivyoperator.LabelConfigAuditReportScanner: s.pluginContext.GetName(),
		trivyoperator.LabelK8SAppManagedBy:          trivyoperator.AppTrivyOperator,
	}

	podTemplateLabelsSet := make(labels.Set)
	for index, element := range labelsSet {
		podTemplateLabelsSet[index] = element
	}
	for index, element := range s.podTemplateLabels {
		podTemplateLabelsSet[index] = element
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        GetScanJobName(s.object),
			Namespace:   s.pluginContext.GetNamespace(),
			Labels:      labelsSet,
			Annotations: s.annotations,
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: kube.GetActiveDeadlineSeconds(s.timeout),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      podTemplateLabelsSet,
					Annotations: s.annotations,
				},
				Spec: jobSpec,
			},
		},
	}

	err = kube.ObjectToObjectMeta(s.object, &job.ObjectMeta)
	if err != nil {
		return nil, nil, err
	}

	err = kube.ObjectToObjectMeta(s.object, &job.Spec.Template.ObjectMeta)
	if err != nil {
		return nil, nil, err
	}

	for _, secret := range secrets {
		if secret.Labels == nil {
			secret.Labels = make(map[string]string)
		}
		for k, v := range labelsSet {
			secret.Labels[k] = v
		}
		err = kube.ObjectToObjectMeta(s.object, &secret.ObjectMeta)
	}

	return job, secrets, nil
}

func GetScanJobName(obj client.Object) string {
	return fmt.Sprintf("scan-configauditreport-%s", kube.ComputeHash(kube.ObjectRef{
		Kind:      kube.Kind(obj.GetObjectKind().GroupVersionKind().Kind),
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
	}))
}

type ReportBuilder struct {
	scheme           *runtime.Scheme
	controller       client.Object
	resourceSpecHash string
	pluginConfigHash string
	data             v1alpha1.ConfigAuditReportData
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

func (b *ReportBuilder) Data(data v1alpha1.ConfigAuditReportData) *ReportBuilder {
	b.data = data
	return b
}

func (b *ReportBuilder) reportName() string {
	kind := b.controller.GetObjectKind().GroupVersionKind().Kind
	name := b.controller.GetName()
	reportName := fmt.Sprintf("%s-%s", strings.ToLower(kind), name)
	if len(validation.IsValidLabelValue(reportName)) == 0 {
		return reportName
	}
	return fmt.Sprintf("%s-%s", strings.ToLower(kind), kube.ComputeHash(name))
}

func (b *ReportBuilder) GetClusterReport() (v1alpha1.ClusterConfigAuditReport, error) {
	labelsSet := make(labels.Set)
	if b.resourceSpecHash != "" {
		labelsSet[trivyoperator.LabelResourceSpecHash] = b.resourceSpecHash
	}
	if b.pluginConfigHash != "" {
		labelsSet[trivyoperator.LabelPluginConfigHash] = b.pluginConfigHash
	}

	report := v1alpha1.ClusterConfigAuditReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:   b.reportName(),
			Labels: labelsSet,
		},
		Report: b.data,
	}
	err := kube.ObjectToObjectMeta(b.controller, &report.ObjectMeta)
	if err != nil {
		return v1alpha1.ClusterConfigAuditReport{}, err
	}
	err = controllerutil.SetControllerReference(b.controller, &report, b.scheme)
	if err != nil {
		return v1alpha1.ClusterConfigAuditReport{}, fmt.Errorf("setting controller reference: %w", err)
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

func (b *ReportBuilder) GetReport() (v1alpha1.ConfigAuditReport, error) {
	labelsSet := make(labels.Set)
	if b.resourceSpecHash != "" {
		labelsSet[trivyoperator.LabelResourceSpecHash] = b.resourceSpecHash
	}
	if b.pluginConfigHash != "" {
		labelsSet[trivyoperator.LabelPluginConfigHash] = b.pluginConfigHash
	}

	report := v1alpha1.ConfigAuditReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.reportName(),
			Namespace: b.controller.GetNamespace(),
			Labels:    labelsSet,
		},
		Report: b.data,
	}
	err := kube.ObjectToObjectMeta(b.controller, &report.ObjectMeta)
	if err != nil {
		return v1alpha1.ConfigAuditReport{}, err
	}
	err = controllerutil.SetControllerReference(b.controller, &report, b.scheme)
	if err != nil {
		return v1alpha1.ConfigAuditReport{}, fmt.Errorf("setting controller reference: %w", err)
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

func (b *ReportBuilder) Write(ctx context.Context, writer Writer) error {
	if kube.IsClusterScopedKind(b.controller.GetObjectKind().GroupVersionKind().Kind) {
		report, err := b.GetClusterReport()
		if err != nil {
			return err
		}
		return writer.WriteClusterReport(ctx, report)
	} else {
		report, err := b.GetReport()
		if err != nil {
			return err
		}
		return writer.WriteReport(ctx, report)
	}
}
