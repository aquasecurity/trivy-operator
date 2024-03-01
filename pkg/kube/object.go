package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	ocpappsv1 "github.com/openshift/api/apps/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

// ObjectRef is a simplified representation of a Kubernetes client.Object.
// Each object has Kind, which designates the type of the entity it represents.
// Objects have names and many of them live in namespaces.
type ObjectRef struct {
	Kind      Kind
	Name      string
	Namespace string
}

// Kind represents the type of Kubernetes client.Object.
type Kind string

const (
	KindPod                   Kind = "Pod"
	KindReplicaSet            Kind = "ReplicaSet"
	KindReplicationController Kind = "ReplicationController"
	KindDeployment            Kind = "Deployment"
	KindDeploymentConfig      Kind = "DeploymentConfig"
	KindStatefulSet           Kind = "StatefulSet"
	KindDaemonSet             Kind = "DaemonSet"
	KindCronJob               Kind = "CronJob"
	KindJob                   Kind = "Job"
	KindService               Kind = "Service"
	KindConfigMap             Kind = "ConfigMap"
	KindRole                  Kind = "Role"
	KindRoleBinding           Kind = "RoleBinding"
	KindNetworkPolicy         Kind = "NetworkPolicy"
	KindIngress               Kind = "Ingress"
	KindResourceQuota         Kind = "ResourceQuota"
	KindLimitRange            Kind = "LimitRange"

	KindClusterRole              Kind = "ClusterRole"
	KindClusterRoleBindings      Kind = "ClusterRoleBinding"
	KindCustomResourceDefinition Kind = "CustomResourceDefinition"
	KindNode                     Kind = "Node"
	KindClusterSbomReport        Kind = "ClusterSbomReport"
)

const (
	deploymentAnnotation       string = "deployment.kubernetes.io/revision"
	deploymentConfigAnnotation string = "openshift.io/deployment-config.latest-version"

	DeployerPodForDeploymentAnnotation string = "openshift.io/deployment-config.name"
)
const (
	cronJobResource        = "cronjobs"
	apiBatchV1beta1CronJob = "batch/v1beta1, Kind=CronJob"
	apiBatchV1CronJob      = "batch/v1, Kind=CronJob"
)

// IsBuiltInWorkload returns true if the specified v1.OwnerReference
// is a built-in Kubernetes workload, false otherwise.
func IsBuiltInWorkload(controller *metav1.OwnerReference) bool {
	return controller != nil &&
		(controller.Kind == string(KindReplicaSet) ||
			controller.Kind == string(KindReplicationController) ||
			controller.Kind == string(KindStatefulSet) ||
			controller.Kind == string(KindDaemonSet) ||
			controller.Kind == string(KindJob))
}

// IsWorkload returns true if the specified resource kinds represents Kubernetes
// workload, false otherwise.
func IsWorkload(kind string) bool {
	return kind == "Pod" ||
		kind == "Deployment" ||
		kind == "ReplicaSet" ||
		kind == "ReplicationController" ||
		kind == "StatefulSet" ||
		kind == "DaemonSet" ||
		kind == "Job" ||
		kind == "CronJob"
}

// IsClusterScopedKind returns true if the specified kind is ClusterRole,
// ClusterRoleBinding, and CustomResourceDefinition.
// TODO Use discovery client to have a generic implementation.
func IsClusterScopedKind(kind string) bool {
	switch kind {
	case string(KindClusterRole), string(KindClusterRoleBindings), string(KindCustomResourceDefinition), string(KindNode):
		return true
	default:
		return false
	}
}

// ObjectRefToLabels encodes the specified ObjectRef as a set of labels.
//
// If Object's name cannot be used as the value of the
// trivy-operator.LabelResourceName label, as a fallback, this method will calculate
// a hash of the Object's name and use it as the value of the
// trivy-operator.LabelResourceNameHash label.
func ObjectRefToLabels(obj ObjectRef) map[string]string {
	labels := map[string]string{
		trivyoperator.LabelResourceKind:      string(obj.Kind),
		trivyoperator.LabelResourceNamespace: obj.Namespace,
	}
	if len(validation.IsValidLabelValue(obj.Name)) == 0 {
		labels[trivyoperator.LabelResourceName] = obj.Name
	} else {
		labels[trivyoperator.LabelResourceNameHash] = ComputeHash(obj.Name)
	}
	return labels
}

// ObjectToObjectMeta encodes the specified client.Object as a set of labels
// and annotations added to the given ObjectMeta.
func ObjectToObjectMeta(obj client.Object, objectMeta *metav1.ObjectMeta) error {
	if objectMeta.Labels == nil {
		objectMeta.Labels = make(map[string]string)
	}
	objectMeta.Labels[trivyoperator.LabelResourceKind] = obj.GetObjectKind().GroupVersionKind().Kind
	objectMeta.Labels[trivyoperator.LabelResourceNamespace] = obj.GetNamespace()
	if len(validation.IsValidLabelValue(obj.GetName())) == 0 {
		objectMeta.Labels[trivyoperator.LabelResourceName] = obj.GetName()
	} else {
		objectMeta.Labels[trivyoperator.LabelResourceNameHash] = ComputeHash(obj.GetName())
		if objectMeta.Annotations == nil {
			objectMeta.Annotations = make(map[string]string)
		}
		objectMeta.Annotations[trivyoperator.LabelResourceName] = obj.GetName()
	}
	return nil
}

func ObjectRefFromObjectMeta(objectMeta metav1.ObjectMeta) (ObjectRef, error) {
	if _, found := objectMeta.Labels[trivyoperator.LabelResourceKind]; !found {
		return ObjectRef{}, fmt.Errorf("required label does not exist: %s", trivyoperator.LabelResourceKind)
	}
	var objname string
	if _, found := objectMeta.Labels[trivyoperator.LabelResourceName]; !found {
		if _, found := objectMeta.Annotations[trivyoperator.LabelResourceName]; found {
			objname = objectMeta.Annotations[trivyoperator.LabelResourceName]
		} else {
			return ObjectRef{}, fmt.Errorf("required label does not exist: %s", trivyoperator.LabelResourceName)
		}
	} else {
		objname = objectMeta.Labels[trivyoperator.LabelResourceName]
	}
	return ObjectRef{
		Kind:      Kind(objectMeta.Labels[trivyoperator.LabelResourceKind]),
		Name:      objname,
		Namespace: objectMeta.Labels[trivyoperator.LabelResourceNamespace],
	}, nil
}

// ContainerImages is a simple structure to hold the mapping between container
// names and container image references.
type ContainerImages map[string]string

func (ci ContainerImages) AsJSON() (string, error) {
	writer, err := json.Marshal(ci)
	if err != nil {
		return "", err
	}
	return string(writer), nil
}

func (ci ContainerImages) FromJSON(value string) error {
	return json.Unmarshal([]byte(value), &ci)
}

func ObjectRefFromKindAndObjectKey(kind Kind, name client.ObjectKey) ObjectRef {
	return ObjectRef{
		Kind:      kind,
		Name:      name.Name,
		Namespace: name.Namespace,
	}
}

// ComputeSpecHash computes hash of the specified K8s client.Object. The hash is
// used to indicate whether the client.Object should be rescanned or not by
// adding it as the trivy-operator.LabelResourceSpecHash label to an instance of a
// security report.
func ComputeSpecHash(obj client.Object) (string, error) {
	switch t := obj.(type) {
	case *corev1.Pod, *appsv1.Deployment, *appsv1.ReplicaSet, *corev1.ReplicationController, *appsv1.StatefulSet, *appsv1.DaemonSet, *batchv1.CronJob, *batchv1beta1.CronJob, *batchv1.Job:
		spec, err := GetPodSpec(obj)
		if err != nil {
			return "", err
		}
		return ComputeHash(spec), nil
	case *corev1.Service:
		return ComputeHash(obj), nil
	case *corev1.ConfigMap:
		return ComputeHash(obj), nil
	case *rbacv1.Role:
		return ComputeHash(obj), nil
	case *rbacv1.RoleBinding:
		return ComputeHash(obj), nil
	case *networkingv1.NetworkPolicy:
		return ComputeHash(obj), nil
	case *networkingv1.Ingress:
		return ComputeHash(obj), nil
	case *corev1.ResourceQuota:
		return ComputeHash(obj), nil
	case *corev1.Node:
		return ComputeHash(obj), nil
	case *corev1.LimitRange:
		return ComputeHash(obj), nil
	case *rbacv1.ClusterRole:
		return ComputeHash(obj), nil
	case *rbacv1.ClusterRoleBinding:
		return ComputeHash(obj), nil
	case *apiextensionsv1.CustomResourceDefinition:
		return ComputeHash(obj), nil
	default:
		return "", fmt.Errorf("computing spec hash of unsupported object: %T", t)
	}
}

// GetPodSpec returns v1.PodSpec from the specified Kubernetes client.Object.
// Returns error if the given client.Object is not a Kubernetes workload.
func GetPodSpec(obj client.Object) (corev1.PodSpec, error) {
	switch t := obj.(type) {
	case *corev1.Pod:
		return (obj.(*corev1.Pod)).Spec, nil
	case *appsv1.Deployment:
		return (obj.(*appsv1.Deployment)).Spec.Template.Spec, nil
	case *appsv1.ReplicaSet:
		return (obj.(*appsv1.ReplicaSet)).Spec.Template.Spec, nil
	case *corev1.ReplicationController:
		return (obj.(*corev1.ReplicationController)).Spec.Template.Spec, nil
	case *appsv1.StatefulSet:
		return (obj.(*appsv1.StatefulSet)).Spec.Template.Spec, nil
	case *appsv1.DaemonSet:
		return (obj.(*appsv1.DaemonSet)).Spec.Template.Spec, nil
	case *batchv1beta1.CronJob:
		return (obj.(*batchv1beta1.CronJob)).Spec.JobTemplate.Spec.Template.Spec, nil
	case *batchv1.CronJob:
		return (obj.(*batchv1.CronJob)).Spec.JobTemplate.Spec.Template.Spec, nil
	case *batchv1.Job:
		return (obj.(*batchv1.Job)).Spec.Template.Spec, nil
	default:
		return corev1.PodSpec{}, fmt.Errorf("unsupported workload: %T", t)
	}
}

var ErrReplicaSetNotFound = errors.New("replicaset not found")
var ErrNoRunningPods = errors.New("no active pods for controller")
var ErrUnSupportedKind = errors.New("unsupported workload kind")

// CompatibleMgr provide k8s compatible objects (group/api/kind) capabilities
type CompatibleMgr interface {
	// GetSupportedObjectByKind get specific k8s compatible object (group/api/kind) by kind
	GetSupportedObjectByKind(kind Kind, defaultObject client.Object) client.Object
}

type CompatibleObjectMapper struct {
	kindObjectMap map[string]string
}

type ObjectResolver struct {
	client.Client
	CompatibleMgr
}

func NewObjectResolver(c client.Client, cm CompatibleMgr) ObjectResolver {
	return ObjectResolver{c, cm}
}

// InitCompatibleMgr initializes a CompatibleObjectMapper who store a map the of supported kinds with it compatible Objects (group/api/kind)
// it dynamically fetches the compatible k8s objects (group/api/kind) by resource from the cluster and store it in kind vs k8s object mapping
// It will enable the operator to support old and new API resources based on cluster version support
func InitCompatibleMgr() (CompatibleMgr, error) {
	cf := genericclioptions.NewConfigFlags(true)
	restMapper, err := cf.ToRESTMapper()
	if err != nil {
		return nil, err
	}
	kindObjectMap := make(map[string]string)
	for _, resource := range getCompatibleResources() {
		gvk, err := restMapper.KindFor(schema.GroupVersionResource{Resource: resource})
		if err != nil {
			return nil, err
		}
		kindObjectMap[gvk.Kind] = gvk.String()
	}
	return &CompatibleObjectMapper{kindObjectMap: kindObjectMap}, nil
}

// return a map of supported object api per k8s version
func supportedObjectsByK8sKind(api string) client.Object {
	switch api {
	case apiBatchV1beta1CronJob:
		return &batchv1beta1.CronJob{}
	case apiBatchV1CronJob:
		return &batchv1.CronJob{}
	default:
		return nil
	}
}

func getCompatibleResources() []string {
	return []string{cronJobResource}
}

// GetSupportedObjectByKind accept kind and return the supported object (group/api/kind) of the cluster
func (o *CompatibleObjectMapper) GetSupportedObjectByKind(kind Kind, defaultObject client.Object) client.Object {
	api, ok := o.kindObjectMap[string(kind)]
	if !ok {
		return defaultObject
	}
	return supportedObjectsByK8sKind(api)
}

func (o *ObjectResolver) ObjectFromObjectRef(ctx context.Context, ref ObjectRef) (client.Object, error) {
	var obj client.Object
	switch ref.Kind {
	case KindPod:
		obj = &corev1.Pod{}
	case KindReplicaSet:
		obj = &appsv1.ReplicaSet{}
	case KindReplicationController:
		obj = &corev1.ReplicationController{}
	case KindDeployment:
		obj = &appsv1.Deployment{}
	case KindStatefulSet:
		obj = &appsv1.StatefulSet{}
	case KindDaemonSet:
		obj = &appsv1.DaemonSet{}
	case KindCronJob:
		obj = o.CompatibleMgr.GetSupportedObjectByKind(KindCronJob, &batchv1.CronJob{})
	case KindJob:
		obj = &batchv1.Job{}
	case KindNode:
		obj = &corev1.Node{}
	case KindService:
		obj = &corev1.Service{}
	case KindConfigMap:
		obj = &corev1.ConfigMap{}
	case KindRole:
		obj = &rbacv1.Role{}
	case KindRoleBinding:
		obj = &rbacv1.RoleBinding{}
	case KindNetworkPolicy:
		obj = &networkingv1.NetworkPolicy{}
	case KindIngress:
		obj = &networkingv1.Ingress{}
	case KindResourceQuota:
		obj = &corev1.ResourceQuota{}
	case KindLimitRange:
		obj = &corev1.LimitRange{}
	case KindClusterRole:
		obj = &rbacv1.ClusterRole{}
	case KindClusterRoleBindings:
		obj = &rbacv1.ClusterRoleBinding{}
	case KindCustomResourceDefinition:
		obj = &apiextensionsv1.CustomResourceDefinition{}
	case KindClusterSbomReport:
		obj = &v1alpha1.ClusterSbomReport{}
	default:
		return nil, fmt.Errorf("unknown kind: %s", ref.Kind)
	}
	err := o.Client.Get(ctx, client.ObjectKey{
		Name:      ref.Name,
		Namespace: ref.Namespace,
	}, obj)
	if err != nil {
		return nil, err
	}
	return o.ensureGVK(obj)
}

// ReportOwner resolves the owner of a security report for the specified object.
func (o *ObjectResolver) ReportOwner(ctx context.Context, obj client.Object) (client.Object, error) {
	switch r := obj.(type) {
	case *appsv1.Deployment:
		return o.ReplicaSetByDeployment(ctx, obj.(*appsv1.Deployment))
	case *batchv1.Job:
		controller := metav1.GetControllerOf(obj)
		if controller == nil {
			// Unmanaged Job
			return obj, nil
		}
		if controller.Kind == string(KindCronJob) {
			return o.CronJobByJob(ctx, r)
		}
		// Job controlled by sth else (usually frameworks)
		return obj, nil
	case *corev1.Pod:
		controller := metav1.GetControllerOf(obj)
		if controller == nil {
			// Unmanaged Pod
			return obj, nil
		}
		if controller.Kind == string(KindReplicaSet) {
			return o.ReplicaSetByPod(ctx, r)
		}
		if controller.Kind == string(KindJob) {
			// Managed by Job or CronJob
			job, err := o.JobByPod(ctx, r)
			if err != nil {
				return nil, err
			}
			return o.ReportOwner(ctx, job)
		}
		// Pod controlled by sth else (usually frameworks)
		return obj, nil
	case *appsv1.ReplicaSet, *corev1.ReplicationController, *appsv1.StatefulSet, *appsv1.DaemonSet, *batchv1beta1.CronJob, *batchv1.CronJob:
		return obj, nil
	default:
		return obj, nil
	}
}

// ReplicaSetByDeploymentRef returns the current revision of the specified
// Deployment reference. If the current revision cannot be found the
// ErrReplicaSetNotFound error is returned.
func (o *ObjectResolver) ReplicaSetByDeploymentRef(ctx context.Context, deploymentRef ObjectRef) (*appsv1.ReplicaSet, error) {
	deployment := &appsv1.Deployment{}
	err := o.Client.Get(ctx, client.ObjectKey{
		Namespace: deploymentRef.Namespace,
		Name:      deploymentRef.Name,
	}, deployment)
	if err != nil {
		return nil, fmt.Errorf("getting deployment %q: %w", deploymentRef.Namespace+"/"+deploymentRef.Name, err)
	}
	return o.ReplicaSetByDeployment(ctx, deployment)
}

// ReplicaSetByDeployment returns the current revision of the specified
// Deployment. If the current revision cannot be found the ErrReplicaSetNotFound
// error is returned.
func (o *ObjectResolver) ReplicaSetByDeployment(ctx context.Context, deployment *appsv1.Deployment) (*appsv1.ReplicaSet, error) {
	var rsList appsv1.ReplicaSetList
	err := o.Client.List(ctx, &rsList,
		client.InNamespace(deployment.Namespace),
		client.MatchingLabels(deployment.Spec.Selector.MatchLabels))
	if err != nil {
		return nil, fmt.Errorf("listing replicasets for deployment %q: %w", deployment.Namespace+"/"+deployment.Name, err)
	}

	if len(rsList.Items) == 0 {
		return nil, ErrReplicaSetNotFound
	}

	for _, rs := range rsList.Items {
		if deployment.Annotations[deploymentAnnotation] !=
			rs.Annotations[deploymentAnnotation] {
			continue
		}
		rsCopy := rs.DeepCopy()
		_, err = o.ensureGVK(rsCopy)
		return rsCopy, err
	}

	return nil, ErrReplicaSetNotFound
}

// ReplicaSetByPodRef returns the controller ReplicaSet of the specified Pod
// reference.
func (o *ObjectResolver) ReplicaSetByPodRef(ctx context.Context, object ObjectRef) (*appsv1.ReplicaSet, error) {
	pod := &corev1.Pod{}
	err := o.Client.Get(ctx, client.ObjectKey{
		Namespace: object.Namespace,
		Name:      object.Name,
	}, pod)
	if err != nil {
		return nil, err
	}
	return o.ReplicaSetByPod(ctx, pod)
}

// ReplicaSetByPod returns the controller ReplicaSet of the specified Pod.
func (o *ObjectResolver) ReplicaSetByPod(ctx context.Context, pod *corev1.Pod) (*appsv1.ReplicaSet, error) {
	controller := metav1.GetControllerOf(pod)
	if controller == nil {
		return nil, fmt.Errorf("did not find a controller for pod %q", pod.Namespace+"/"+pod.Name)
	}
	if controller.Kind != "ReplicaSet" {
		return nil, fmt.Errorf("pod %q is controlled by a %q, want replicaset", pod.Name, controller.Kind)
	}
	rs := &appsv1.ReplicaSet{}
	err := o.Client.Get(ctx, client.ObjectKey{
		Namespace: pod.Namespace,
		Name:      controller.Name,
	}, rs)
	if err != nil {
		return nil, err
	}
	rsCopy := rs.DeepCopy()
	_, err = o.ensureGVK(rsCopy)
	return rsCopy, err
}

func (o *ObjectResolver) CronJobByJob(ctx context.Context, job *batchv1.Job) (client.Object, error) {
	controller := metav1.GetControllerOf(job)
	if controller == nil {
		return nil, fmt.Errorf("did not find a controller for job %q", job.Name)
	}
	if controller.Kind != "CronJob" {
		return nil, fmt.Errorf("pod %q is controlled by a %q, want CronJob", job.Name, controller.Kind)
	}
	cj := o.CompatibleMgr.GetSupportedObjectByKind(KindCronJob, &batchv1.CronJob{})
	err := o.Client.Get(ctx, client.ObjectKey{Namespace: job.Namespace, Name: controller.Name}, cj)
	if err != nil {
		return nil, err
	}
	obj, err := o.ensureGVK(cj)
	return obj, err
}

func (o *ObjectResolver) JobByPod(ctx context.Context, pod *corev1.Pod) (*batchv1.Job, error) {
	controller := metav1.GetControllerOf(pod)
	if controller == nil {
		return nil, fmt.Errorf("did not find a controller for pod %q", pod.Name)
	}
	if controller.Kind != "Job" {
		return nil, fmt.Errorf("pod %q is controlled by a %q, want replicaset", pod.Name, controller.Kind)
	}
	rs := &batchv1.Job{}
	err := o.Client.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: controller.Name}, rs)
	if err != nil {
		return nil, err
	}
	obj, err := o.ensureGVK(rs)
	return obj.(*batchv1.Job), err
}

func (o *ObjectResolver) ensureGVK(obj client.Object) (client.Object, error) {
	gvk, err := apiutil.GVKForObject(obj, o.Client.Scheme())
	if err != nil {
		return nil, err
	}
	obj.GetObjectKind().SetGroupVersionKind(gvk)
	return obj, nil
}

// RelatedReplicaSetName attempts to find the replicaset that is associated with
// the given owner. If the owner is a Deployment, it will look for a ReplicaSet
// that is controlled by the Deployment. If the owner is a Pod, it will look for
// the ReplicaSet that owns the Pod.
func (o *ObjectResolver) RelatedReplicaSetName(ctx context.Context, object ObjectRef) (string, error) {
	switch object.Kind {
	case KindDeployment:
		rs, err := o.ReplicaSetByDeploymentRef(ctx, object)
		if err != nil {
			return "", err
		}
		return rs.Name, nil
	case KindPod:
		rs, err := o.ReplicaSetByPodRef(ctx, object)
		if err != nil {
			return "", err
		}
		return rs.Name, nil
	}
	return "", fmt.Errorf("can only get related ReplicaSet for Deployment or Pod, not %q", string(object.Kind))
}

// GetNodeName returns the name of the node on which the given workload is
// scheduled. If there are no running pods then the ErrNoRunningPods error is
// returned. If there are no active ReplicaSets for the Deployment the
// ErrReplicaSetNotFound error is returned. If the specified workload is a
// CronJob the ErrUnSupportedKind error is returned.
func (o *ObjectResolver) GetNodeName(ctx context.Context, obj client.Object) (string, error) {
	switch r := obj.(type) {
	case *corev1.Pod:
		return r.Spec.NodeName, nil
	case *appsv1.Deployment:
		replicaSet, err := o.ReplicaSetByDeployment(ctx, r)
		if err != nil {
			return "", err
		}
		pods, err := o.GetActivePodsMatchingLabels(ctx, obj.GetNamespace(), replicaSet.Spec.Selector.MatchLabels)
		if err != nil {
			return "", err
		}
		return pods[0].Spec.NodeName, nil
	case *appsv1.ReplicaSet:
		pods, err := o.GetActivePodsMatchingLabels(ctx, obj.GetNamespace(), r.Spec.Selector.MatchLabels)
		if err != nil {
			return "", err
		}
		return pods[0].Spec.NodeName, nil
	case *corev1.ReplicationController:
		pods, err := o.GetActivePodsMatchingLabels(ctx, obj.GetNamespace(), r.Spec.Selector)
		if err != nil {
			return "", err
		}
		return pods[0].Spec.NodeName, nil
	case *appsv1.StatefulSet:
		pods, err := o.GetActivePodsMatchingLabels(ctx, obj.GetNamespace(), r.Spec.Selector.MatchLabels)
		if err != nil {
			return "", err
		}
		return pods[0].Spec.NodeName, nil
	case *appsv1.DaemonSet:
		pods, err := o.GetActivePodsMatchingLabels(ctx, obj.GetNamespace(), r.Spec.Selector.MatchLabels)
		if err != nil {
			return "", err
		}
		return pods[0].Spec.NodeName, nil
	case *batchv1beta1.CronJob:
		return "", ErrUnSupportedKind
	case *batchv1.CronJob:
		return "", ErrUnSupportedKind
	case *batchv1.Job:
		pods, err := o.GetActivePodsMatchingLabels(ctx, obj.GetNamespace(), r.Spec.Selector.MatchLabels)
		if err != nil {
			return "", err
		}
		return pods[0].Spec.NodeName, nil
	default:
		return "", ErrUnSupportedKind
	}
}

// TODO: Figure out if cluster-wide access to deployments can be avoided
// See: https://github.com/aquasecurity/trivy-operator/issues/373 for background
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch

func (o *ObjectResolver) IsActiveReplicaSet(ctx context.Context, workloadObj client.Object, controller *metav1.OwnerReference) (bool, error) {
	if controller != nil && controller.Kind == string(KindDeployment) {
		deploymentObject := &appsv1.Deployment{}

		err := o.Client.Get(ctx, client.ObjectKey{
			Namespace: workloadObj.GetNamespace(),
			Name:      controller.Name,
		}, deploymentObject)
		if err != nil {
			return false, err
		}
		deploymentRevisionAnnotation := deploymentObject.GetAnnotations()
		replicasetRevisionAnnotation := workloadObj.GetAnnotations()
		return replicasetRevisionAnnotation[deploymentAnnotation] == deploymentRevisionAnnotation[deploymentAnnotation], nil
	}
	return true, nil
}

// +kubebuilder:rbac:groups=apps.openshift.io,resources=deploymentconfigs,verbs=get;list;watch

func (o *ObjectResolver) IsActiveReplicationController(ctx context.Context, workloadObj client.Object, controller *metav1.OwnerReference) (bool, error) {
	if controller != nil && controller.Kind == string(KindDeploymentConfig) {
		deploymentConfigObj := &ocpappsv1.DeploymentConfig{}

		err := o.Client.Get(ctx, client.ObjectKey{
			Namespace: workloadObj.GetNamespace(),
			Name:      controller.Name,
		}, deploymentConfigObj)

		if err != nil {
			return false, err
		}
		replicasetRevisionAnnotation := workloadObj.GetAnnotations()
		latestRevision := fmt.Sprintf("%d", deploymentConfigObj.Status.LatestVersion)
		return replicasetRevisionAnnotation[deploymentConfigAnnotation] == latestRevision, nil
	}
	return true, nil
}

func (o *ObjectResolver) getPodsMatchingLabels(ctx context.Context, namespace string,
	labels map[string]string) ([]corev1.Pod, error) {
	podList := &corev1.PodList{}
	err := o.Client.List(ctx, podList,
		client.InNamespace(namespace),
		client.MatchingLabels(labels))
	if err != nil {
		return podList.Items, fmt.Errorf("listing pods in namespace %s matching labels %v: %w", namespace,
			labels, err)
	}
	return podList.Items, err
}

func (o *ObjectResolver) GetActivePodsMatchingLabels(ctx context.Context, namespace string,
	labels map[string]string) ([]corev1.Pod, error) {
	pods, err := o.getPodsMatchingLabels(ctx, namespace, labels)
	if err != nil {
		return pods, err
	}
	if len(pods) == 0 {
		return pods, ErrNoRunningPods
	}
	return pods, nil
}

// Resource represents a Kubernetes resource Object
type Resource struct {
	Kind       Kind
	ForObject  client.Object
	OwnsObject client.Object
}

// GetWorkloadResource returns a Resource object which can be used by controllers for reconciliation
func (r *Resource) GetWorkloadResource(kind string, object client.Object, resolver ObjectResolver) error {

	kind = strings.ToLower(kind)

	switch kind {
	case "pod":
		*r = Resource{Kind: KindPod, ForObject: &corev1.Pod{}, OwnsObject: object}
	case "replicaset":
		*r = Resource{Kind: KindReplicaSet, ForObject: &appsv1.ReplicaSet{}, OwnsObject: object}
	case "replicationcontroller":
		*r = Resource{Kind: KindReplicationController, ForObject: &corev1.ReplicationController{}, OwnsObject: object}
	case "statefulset":
		*r = Resource{Kind: KindStatefulSet, ForObject: &appsv1.StatefulSet{}, OwnsObject: object}
	case "daemonset":
		*r = Resource{Kind: KindDaemonSet, ForObject: &appsv1.DaemonSet{}, OwnsObject: object}
	case "cronjob":
		*r = Resource{Kind: KindCronJob, ForObject: resolver.GetSupportedObjectByKind(KindCronJob, &batchv1.CronJob{}), OwnsObject: object}
	case "job":
		*r = Resource{Kind: KindJob, ForObject: &batchv1.Job{}, OwnsObject: object}
	case "ingress":
		*r = Resource{Kind: KindIngress, ForObject: &networkingv1.Ingress{}, OwnsObject: object}
	default:
		return fmt.Errorf("workload of kind %s is not supported", kind)
	}

	return nil
}

func IsValidK8sKind(kind string) bool {
	if IsWorkload(kind) || IsClusterScopedKind(kind) || IsRoleRelatedNamespaceScope(Kind(kind)) || isValidNamespaceResource(Kind(kind)) || kind == "Workload" {
		return true
	}
	return false
}

func IsRoleRelatedNamespaceScope(kind Kind) bool {
	if kind == KindRole || kind == KindRoleBinding {
		return true
	}
	return false
}

func IsRoleTypes(kind Kind) bool {
	if kind == KindRole || kind == KindClusterRole {
		return true
	}
	return false
}

func isValidNamespaceResource(kind Kind) bool {
	if kind == KindConfigMap || kind == KindNetworkPolicy || kind == KindIngress || kind == KindResourceQuota || kind == KindLimitRange || kind == KindService {
		return true
	}
	return false
}
