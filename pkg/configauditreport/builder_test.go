package configauditreport_test

import (
	. "github.com/onsi/gomega"

	"io"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/configauditreport"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestReportBuilder(t *testing.T) {

	t.Run("Should build report for namespaced resource", func(t *testing.T) {
		g := NewGomegaWithT(t)

		report, err := configauditreport.NewReportBuilder(scheme.Scheme).
			Controller(&appsv1.ReplicaSet{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ReplicaSet",
					APIVersion: "apps/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-owner",
					Namespace: "qa",
				},
			}).
			ResourceSpecHash("xyz").
			PluginConfigHash("nop").
			Data(v1alpha1.ConfigAuditReportData{}).
			GetReport()

		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(report).To(Equal(v1alpha1.ConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "replicaset-some-owner",
				Namespace: "qa",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "apps/v1",
						Kind:               "ReplicaSet",
						Name:               "some-owner",
						Controller:         pointer.BoolPtr(true),
						BlockOwnerDeletion: pointer.BoolPtr(false),
					},
				},
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "ReplicaSet",
					trivyoperator.LabelResourceName:      "some-owner",
					trivyoperator.LabelResourceNamespace: "qa",
					trivyoperator.LabelResourceSpecHash:  "xyz",
					trivyoperator.LabelPluginConfigHash:  "nop",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{},
		}))
	})

	t.Run("Should build report for cluster scoped resource", func(t *testing.T) {
		g := NewGomegaWithT(t)

		report, err := configauditreport.NewReportBuilder(scheme.Scheme).
			Controller(&rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ClusterRole",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "system:controller:node-controller",
				},
			}).
			ResourceSpecHash("xyz").
			PluginConfigHash("nop").
			Data(v1alpha1.ConfigAuditReportData{}).
			GetClusterReport()

		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(report).To(Equal(v1alpha1.ClusterConfigAuditReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "clusterrole-6f69bb5b79",
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion:         "rbac.authorization.k8s.io/v1",
						Kind:               "ClusterRole",
						Name:               "system:controller:node-controller",
						Controller:         pointer.BoolPtr(true),
						BlockOwnerDeletion: pointer.BoolPtr(false),
					},
				},
				Labels: map[string]string{
					trivyoperator.LabelResourceKind:      "ClusterRole",
					trivyoperator.LabelResourceNameHash:  "6f69bb5b79",
					trivyoperator.LabelResourceNamespace: "",
					trivyoperator.LabelResourceSpecHash:  "xyz",
					trivyoperator.LabelPluginConfigHash:  "nop",
				},
				Annotations: map[string]string{
					trivyoperator.LabelResourceName: "system:controller:node-controller",
				},
			},
			Report: v1alpha1.ConfigAuditReportData{},
		}))
	})
}

type testPlugin struct {
	configHash string
}

func (p *testPlugin) SupportedKinds() []kube.Kind {
	return []kube.Kind{}
}

func (p *testPlugin) IsApplicable(_ trivyoperator.PluginContext, _ client.Object) (bool, string, error) {
	return true, "", nil
}

func (p *testPlugin) Init(_ trivyoperator.PluginContext) error {
	return nil
}

func (p *testPlugin) GetScanJobSpec(_ trivyoperator.PluginContext, obj client.Object) (corev1.PodSpec, []*corev1.Secret, error) {
	return corev1.PodSpec{}, nil, nil
}

func (p *testPlugin) ParseConfigAuditReportData(_ trivyoperator.PluginContext, logsReader io.ReadCloser) (v1alpha1.ConfigAuditReportData, error) {
	return v1alpha1.ConfigAuditReportData{}, nil
}

func (p *testPlugin) GetContainerName() string {
	return ""
}

func (p *testPlugin) ConfigHash(_ trivyoperator.PluginContext, _ kube.Kind) (string, error) {
	return p.configHash, nil
}

func TestScanJobBuilder(t *testing.T) {

	t.Run("Should build scan job for resource with simple name", func(t *testing.T) {
		g := NewGomegaWithT(t)
		job, _, err := configauditreport.NewScanJobBuilder().
			WithPlugin(&testPlugin{
				configHash: "hash-test",
			}).
			WithPluginContext(trivyoperator.NewPluginContext().
				WithName("plugin-test").
				WithNamespace("trivy-operator-ns").
				WithServiceAccountName("trivy-operator-sa").
				Get()).
			WithTimeout(3 * time.Second).
			WithObject(&appsv1.ReplicaSet{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ReplicaSet",
					APIVersion: "apps/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nginx-6799fc88d8",
					Namespace: "prod-ns",
				},
			}).
			Get()
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(job).To(Equal(&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scan-configauditreport-64d65c457",
				Namespace: "trivy-operator-ns",
				Labels: map[string]string{
					trivyoperator.LabelResourceSpecHash:         "755877d4bb",
					trivyoperator.LabelPluginConfigHash:         "hash-test",
					trivyoperator.LabelConfigAuditReportScanner: "plugin-test",
					trivyoperator.LabelK8SAppManagedBy:          "trivy-operator",
					trivyoperator.LabelResourceKind:             "ReplicaSet",
					trivyoperator.LabelResourceName:             "nginx-6799fc88d8",
					trivyoperator.LabelResourceNamespace:        "prod-ns",
				},
			},
			Spec: batchv1.JobSpec{
				BackoffLimit:          pointer.Int32Ptr(0),
				Completions:           pointer.Int32Ptr(1),
				ActiveDeadlineSeconds: pointer.Int64Ptr(3),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							trivyoperator.LabelResourceSpecHash:         "755877d4bb",
							trivyoperator.LabelPluginConfigHash:         "hash-test",
							trivyoperator.LabelConfigAuditReportScanner: "plugin-test",
							trivyoperator.LabelK8SAppManagedBy:          "trivy-operator",
							trivyoperator.LabelResourceKind:             "ReplicaSet",
							trivyoperator.LabelResourceName:             "nginx-6799fc88d8",
							trivyoperator.LabelResourceNamespace:        "prod-ns",
						},
					},
					Spec: corev1.PodSpec{},
				},
			},
		}))
	})

	t.Run("Should build scan job for resource with special name", func(t *testing.T) {
		g := NewGomegaWithT(t)
		job, _, err := configauditreport.NewScanJobBuilder().
			WithPlugin(&testPlugin{
				configHash: "hash-test",
			}).
			WithPluginContext(trivyoperator.NewPluginContext().
				WithName("plugin-test").
				WithNamespace("trivy-operator-ns").
				WithServiceAccountName("trivy-operator-sa").
				Get()).
			WithTimeout(3 * time.Second).
			WithObject(&rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ClusterRole",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "system:controller:node-controller",
				},
			}).
			Get()
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(job).NotTo(BeNil())
		g.Expect(job).To(Equal(&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scan-configauditreport-5bfbdd65c9",
				Namespace: "trivy-operator-ns",
				Labels: map[string]string{
					trivyoperator.LabelResourceSpecHash:         "7c48697ccf",
					trivyoperator.LabelPluginConfigHash:         "hash-test",
					trivyoperator.LabelConfigAuditReportScanner: "plugin-test",
					trivyoperator.LabelK8SAppManagedBy:          "trivy-operator",
					trivyoperator.LabelResourceKind:             "ClusterRole",
					trivyoperator.LabelResourceNameHash:         "6f69bb5b79",
					trivyoperator.LabelResourceNamespace:        "",
				},
				Annotations: map[string]string{
					trivyoperator.LabelResourceName: "system:controller:node-controller",
				},
			},
			Spec: batchv1.JobSpec{
				BackoffLimit:          pointer.Int32Ptr(0),
				Completions:           pointer.Int32Ptr(1),
				ActiveDeadlineSeconds: pointer.Int64Ptr(3),
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							trivyoperator.LabelResourceSpecHash:         "7c48697ccf",
							trivyoperator.LabelPluginConfigHash:         "hash-test",
							trivyoperator.LabelConfigAuditReportScanner: "plugin-test",
							trivyoperator.LabelK8SAppManagedBy:          "trivy-operator",
							trivyoperator.LabelResourceKind:             "ClusterRole",
							trivyoperator.LabelResourceNameHash:         "6f69bb5b79",
							trivyoperator.LabelResourceNamespace:        "",
						},
						Annotations: map[string]string{
							trivyoperator.LabelResourceName: "system:controller:node-controller",
						},
					},
					Spec: corev1.PodSpec{},
				},
			},
		}))
	})
}
