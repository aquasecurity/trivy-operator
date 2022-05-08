package cmd

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/types"

	embedded "github.com/aquasecurity/trivy-operator"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/plugin"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	ext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	clusterRoleStarboard        = "starboard"
	clusterRoleBindingStarboard = "starboard"
)

var (
	namespace = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: trivyoperator.NamespaceName,
			Labels: labels.Set{
				trivyoperator.LabelK8SAppManagedBy: "starboard",
			},
		},
	}
	serviceAccount = &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: trivyoperator.ServiceAccountName,
			Labels: labels.Set{
				trivyoperator.LabelK8SAppManagedBy: "starboard",
			},
		},
		AutomountServiceAccountToken: pointer.BoolPtr(false),
	}
	clusterRole = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterRoleStarboard,
			Labels: labels.Set{
				trivyoperator.LabelK8SAppManagedBy: "starboard",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{
					"",
				},
				Resources: []string{
					"nodes",
					"namespaces",
					"pods",
				},
				Verbs: []string{
					"list",
					"get",
				},
			},
			{
				APIGroups: []string{
					"apps",
				},
				Resources: []string{
					"deployments",
					"statefulsets",
					"daemonsets",
					"replicationcontrollers",
					"replicasets",
				},
				Verbs: []string{
					"list",
					"get",
				},
			},
			{
				APIGroups: []string{
					"batch",
				},
				Resources: []string{
					"jobs",
					"cronjobs",
				},
				Verbs: []string{
					"list",
					"get",
				},
			},
		},
	}
	clusterRoleBinding = &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterRoleBindingStarboard,
			Labels: labels.Set{
				trivyoperator.LabelK8SAppManagedBy: "starboard",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterRoleStarboard,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      trivyoperator.ServiceAccountName,
				Namespace: trivyoperator.NamespaceName,
			},
		},
	}
)

type Installer struct {
	buildInfo     trivyoperator.BuildInfo
	client        client.Client
	clientset     kubernetes.Interface
	clientsetext  extapi.ApiextensionsV1Interface
	configManager trivyoperator.ConfigManager
}

// NewInstaller constructs an Installer with the given starboard.ConfigManager and kubernetes.Interface.
func NewInstaller(
	buildInfo trivyoperator.BuildInfo,
	// TODO Get rid of kubernetes.Interface and ApiextensionsV1Interface and use just client.Client
	clientset kubernetes.Interface,
	clientsetext extapi.ApiextensionsV1Interface,
	client client.Client,
	configManager trivyoperator.ConfigManager,
) *Installer {
	return &Installer{
		buildInfo:     buildInfo,
		clientset:     clientset,
		clientsetext:  clientsetext,
		client:        client,
		configManager: configManager,
	}
}

// Install creates Kubernetes API objects required by Starboard CLI.
func (m *Installer) Install(ctx context.Context) error {
	vulnerabilityReportsCRD, err := embedded.GetVulnerabilityReportsCRD()
	if err != nil {
		return err
	}
	err = m.createOrUpdateCRD(ctx, &vulnerabilityReportsCRD)
	if err != nil {
		return err
	}
	clusterVulnerabilityReportsCRD, err := embedded.GetClusterVulnerabilityReportsCRD()
	if err != nil {
		return err
	}
	err = m.createOrUpdateCRD(ctx, &clusterVulnerabilityReportsCRD)
	if err != nil {
		return err
	}
	kubeBenchReportsCRD, err := embedded.GetCISKubeBenchReportsCRD()
	if err != nil {
		return err
	}
	err = m.createOrUpdateCRD(ctx, &kubeBenchReportsCRD)
	if err != nil {
		return err
	}

	kubeHunterReportsCRD, err := embedded.GetKubeHunterReportsCRD()
	if err != nil {
		return err
	}
	err = m.createOrUpdateCRD(ctx, &kubeHunterReportsCRD)
	if err != nil {
		return err
	}

	configAuditReportsCRD, err := embedded.GetConfigAuditReportsCRD()
	if err != nil {
		return err
	}
	err = m.createOrUpdateCRD(ctx, &configAuditReportsCRD)
	if err != nil {
		return err
	}
	clusterConfigAuditReportsCRD, err := embedded.GetClusterConfigAuditReportsCRD()
	if err != nil {
		return err
	}
	err = m.createOrUpdateCRD(ctx, &clusterConfigAuditReportsCRD)
	if err != nil {
		return err
	}
	clusterComplianceReportsCRD, err := embedded.GetClusterComplianceReportsCRD()
	if err != nil {
		return err
	}
	err = m.createOrUpdateCRD(ctx, &clusterComplianceReportsCRD)
	if err != nil {
		return err
	}
	clusterComplianceDetailReportsCRD, err := embedded.GetClusterComplianceDetailReportsCRD()
	if err != nil {
		return err
	}
	err = m.createOrUpdateCRD(ctx, &clusterComplianceDetailReportsCRD)
	if err != nil {
		return err
	}

	// TODO We should wait for CRD statuses and make sure that the names were accepted

	// compliance report
	clusterComplianceReportSpec, err := embedded.GetNSASpecV10()
	if err != nil {
		return err
	}
	err = m.createOrUpdateComplianceSpec(ctx, clusterComplianceReportSpec)
	if err != nil {
		return err
	}
	err = m.createNamespaceIfNotFound(ctx, namespace)
	if err != nil {
		return err
	}

	err = m.configManager.EnsureDefault(ctx)
	if err != nil {
		return err
	}

	config, err := m.configManager.Read(ctx)
	if err != nil {
		return err
	}

	pluginResolver := plugin.NewResolver().
		WithBuildInfo(m.buildInfo).
		WithNamespace(trivyoperator.NamespaceName).
		WithServiceAccountName(trivyoperator.ServiceAccountName).
		WithConfig(config).
		WithClient(m.client)

	vulnerabilityPlugin, pluginContext, err := pluginResolver.GetVulnerabilityPlugin()
	if err != nil {
		return err
	}

	err = vulnerabilityPlugin.Init(pluginContext)
	if err != nil {
		return fmt.Errorf("initializing %s plugin: %w", pluginContext.GetName(), err)
	}

	configAuditPlugin, pluginContext, err := pluginResolver.GetConfigAuditPlugin()
	if err != nil {
		return err
	}
	err = configAuditPlugin.Init(pluginContext)
	if err != nil {
		return fmt.Errorf("initializing %s plugin: %w", pluginContext.GetName(), err)
	}

	return m.initRBAC(ctx)
}

func (m *Installer) initRBAC(ctx context.Context) error {
	err := m.createServiceAccountIfNotFound(ctx, serviceAccount)
	if err != nil {
		return err
	}

	err = m.createOrUpdateClusterRole(ctx, clusterRole)
	if err != nil {
		return err
	}

	return m.createOrUpdateClusterRoleBinding(ctx, clusterRoleBinding)
}

func (m *Installer) cleanupRBAC(ctx context.Context) (err error) {
	klog.V(3).Infof("Deleting ClusterRoleBinding %q", clusterRoleBindingStarboard)
	err = m.clientset.RbacV1().ClusterRoleBindings().Delete(ctx, clusterRoleBindingStarboard, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return
	}
	klog.V(3).Infof("Deleting ClusterRole %q", clusterRoleStarboard)
	err = m.clientset.RbacV1().ClusterRoles().Delete(ctx, clusterRoleStarboard, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return
	}
	klog.V(3).Infof("Deleting ServiceAccount %q", trivyoperator.NamespaceName+"/"+trivyoperator.ServiceAccountName)
	err = m.clientset.CoreV1().ServiceAccounts(trivyoperator.NamespaceName).Delete(ctx, trivyoperator.ServiceAccountName, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return
	}
	return nil
}

var (
	cleanupPollingInterval = 2 * time.Second
	cleanupTimeout         = 30 * time.Second
)

func (m *Installer) cleanupNamespace(ctx context.Context) error {
	klog.V(3).Infof("Deleting Namespace %q", trivyoperator.NamespaceName)
	err := m.clientset.CoreV1().Namespaces().Delete(ctx, trivyoperator.NamespaceName, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	for {
		select {
		// This case controls the polling interval
		case <-time.After(cleanupPollingInterval):
			_, err := m.clientset.CoreV1().Namespaces().Get(ctx, trivyoperator.NamespaceName, metav1.GetOptions{})
			if errors.IsNotFound(err) {
				klog.V(3).Infof("Deleted Namespace %q", trivyoperator.NamespaceName)
				return nil
			}
		// This case caters for polling timeout
		case <-time.After(cleanupTimeout):
			return fmt.Errorf("deleting namespace timed out")
		}
	}
}

func (m *Installer) createNamespaceIfNotFound(ctx context.Context, ns *corev1.Namespace) (err error) {
	_, err = m.clientset.CoreV1().Namespaces().Get(ctx, ns.Name, metav1.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("Namespace %q already exists", ns.Name)
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating Namespace %q", ns.Name)
		_, err = m.clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		return
	}
	return
}

func (m *Installer) createServiceAccountIfNotFound(ctx context.Context, sa *corev1.ServiceAccount) (err error) {
	name := sa.Name
	_, err = m.clientset.CoreV1().ServiceAccounts(trivyoperator.NamespaceName).Get(ctx, name, metav1.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("ServiceAccount %q already exists", trivyoperator.NamespaceName+"/"+name)
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating ServiceAccount %q", trivyoperator.NamespaceName+"/"+name)
		_, err = m.clientset.CoreV1().ServiceAccounts(trivyoperator.NamespaceName).Create(ctx, sa, metav1.CreateOptions{})
		return
	}
	return
}

func (m *Installer) createOrUpdateClusterRole(ctx context.Context, cr *rbacv1.ClusterRole) (err error) {
	existingRole, err := m.clientset.RbacV1().ClusterRoles().Get(ctx, cr.GetName(), metav1.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("Updating ClusterRole %q", cr.GetName())
		deepCopy := existingRole.DeepCopy()
		deepCopy.Rules = cr.Rules
		_, err = m.clientset.RbacV1().ClusterRoles().Update(ctx, deepCopy, metav1.UpdateOptions{})
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating ClusterRole %q", cr.GetName())
		_, err = m.clientset.RbacV1().ClusterRoles().Create(ctx, cr, metav1.CreateOptions{})
		return
	}
	return
}

func (m *Installer) createOrUpdateClusterRoleBinding(ctx context.Context, crb *rbacv1.ClusterRoleBinding) (err error) {
	existingBinding, err := m.clientset.RbacV1().ClusterRoleBindings().Get(ctx, crb.Name, metav1.GetOptions{})
	switch {
	case err == nil:
		klog.V(3).Infof("Updating ClusterRoleBinding %q", crb.GetName())
		deepCopy := existingBinding.DeepCopy()
		deepCopy.RoleRef = crb.RoleRef
		deepCopy.Subjects = crb.Subjects
		_, err = m.clientset.RbacV1().ClusterRoleBindings().Update(ctx, deepCopy, metav1.UpdateOptions{})
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating ClusterRoleBinding %q", crb.GetName())
		_, err = m.clientset.RbacV1().ClusterRoleBindings().Create(ctx, crb, metav1.CreateOptions{})
		return
	}
	return
}

func (m *Installer) createOrUpdateCRD(ctx context.Context, crd *ext.CustomResourceDefinition) (err error) {
	existingCRD, err := m.clientsetext.CustomResourceDefinitions().Get(ctx, crd.Name, metav1.GetOptions{})

	switch {
	case err == nil:
		klog.V(3).Infof("Updating CRD %q", crd.Name)
		deepCopy := existingCRD.DeepCopy()
		deepCopy.Spec = crd.Spec
		_, err = m.clientsetext.CustomResourceDefinitions().Update(ctx, deepCopy, metav1.UpdateOptions{})
		return
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating CRD %q", crd.Name)
		_, err = m.clientsetext.CustomResourceDefinitions().Create(ctx, crd, metav1.CreateOptions{})
		return
	}
	return
}

func (m *Installer) createOrUpdateComplianceSpec(ctx context.Context, spec v1alpha1.ClusterComplianceReport) error {
	namespaceName := types.NamespacedName{Name: spec.Spec.Name}
	err := m.client.Get(ctx, namespaceName, &spec)
	switch {
	case err == nil:
		klog.V(3).Infof("Updating compliance spec %q", spec.Spec.Name)
		deepCopy := spec.DeepCopy()
		deepCopy.Spec = spec.Spec
		return m.client.Update(ctx, deepCopy)
	case errors.IsNotFound(err):
		klog.V(3).Infof("Creating compliance spec %q", spec.Spec.Name)
		return m.client.Create(ctx, &spec)
	}
	return nil
}

func (m *Installer) deleteCRD(ctx context.Context, name string) (err error) {
	klog.V(3).Infof("Deleting CRD %q", name)
	err = m.clientsetext.CustomResourceDefinitions().Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && errors.IsNotFound(err) {
		return nil
	}
	return
}

func (m *Installer) Uninstall(ctx context.Context) error {
	err := m.deleteCRD(ctx, v1alpha1.VulnerabilityReportsCRName)
	if err != nil {
		return err
	}
	err = m.deleteCRD(ctx, v1alpha1.ClusterVulnerabilityReportsCRName)
	if err != nil {
		return err
	}
	err = m.deleteCRD(ctx, v1alpha1.CISKubeBenchReportCRName)
	if err != nil {
		return err
	}
	err = m.deleteCRD(ctx, v1alpha1.KubeHunterReportCRName)
	if err != nil {
		return err
	}
	err = m.deleteCRD(ctx, v1alpha1.ConfigAuditReportCRName)
	if err != nil {
		return err
	}
	err = m.deleteCRD(ctx, v1alpha1.ClusterConfigAuditReportCRName)
	if err != nil {
		return err
	}
	err = m.deleteCRD(ctx, v1alpha1.ClusterComplianceReportCRName)
	if err != nil {
		return err
	}
	err = m.deleteCRD(ctx, v1alpha1.ClusterComplianceDetailReportCRName)
	if err != nil {
		return err
	}
	err = m.cleanupRBAC(ctx)
	if err != nil {
		return err
	}

	err = m.configManager.Delete(ctx)
	if err != nil {
		return err
	}

	err = m.cleanupNamespace(ctx)
	if err != nil {
		return err
	}
	return nil
}
