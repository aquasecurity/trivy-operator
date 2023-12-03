package operator

import (
	"bytes"
	"encoding/json"
	"sync"
	"time"

	"context"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/trivy-kubernetes/pkg/bom"
	tk "github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	"github.com/aquasecurity/trivy-operator/pkg/plugins/trivy"
	"github.com/aquasecurity/trivy-operator/pkg/sbomreport"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	vc "github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport/controller"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	triv "github.com/aquasecurity/trivy/pkg/k8s/scanner"
	ty "github.com/aquasecurity/trivy/pkg/types"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	k8sapierror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	K8sRepo               = "kubernetes"
	K8sRegistry           = "k8s.io"
	kbomScanJobIdentifier = "k8s-cluster"
	kbom                  = "kbom"
)

//	ClusterReconciler reconciles corev1.Node and corev1.Pod objects
//
// to collect cluster nodes and cluster core components (api-server,kubelet,etcd and more) infomation for vulnerability scanning
// the node information will be evaluated by the complaince control checks per relevant reports, examples: cis-benchmark and nsa
type ClusterController struct {
	logr.Logger
	*vc.WorkloadController
	cacheSyncTimeout time.Duration
	clusterCache     *sync.Map
	name             string
	version          string
	clientset        *kubernetes.Clientset
}

// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=aquasecurity.github.io,resources=clustervulnerabilityreports,verbs=get;list;watch;create;update;patch;delete

func (r *ClusterController) SetupWithManager(mgr ctrl.Manager) error {
	coreComponentsResources := []kube.Resource{
		{Kind: kube.KindNode, ForObject: &corev1.Node{}, OwnsObject: &v1alpha1.ClusterVulnerabilityReport{}},
		{Kind: kube.KindPod, ForObject: &corev1.Pod{}, OwnsObject: &v1alpha1.ClusterVulnerabilityReport{}},
	}

	for _, resource := range coreComponentsResources {
		if err := ctrl.NewControllerManagedBy(mgr).WithOptions(controller.Options{CacheSyncTimeout: r.cacheSyncTimeout}).
			For(resource.ForObject, builder.WithPredicates(
				predicate.IsCoreComponents,
				predicate.Not(predicate.ManagedByTrivyOperator),
				predicate.Not(predicate.IsBeingTerminated))).
			Owns(resource.OwnsObject).
			Complete(r.reconcileClusterComponents(resource.Kind)); err != nil {
			return fmt.Errorf("constructing controller for %s: %w", resource.Kind, err)
		}
	}
	// reconcile kbom
	return ctrl.NewControllerManagedBy(mgr).WithOptions(controller.Options{CacheSyncTimeout: r.cacheSyncTimeout}).
		For(&v1alpha1.ClusterSbomReport{}, builder.WithPredicates(predicate.IsKbom)).
		Owns(&v1alpha1.ClusterVulnerabilityReport{}).
		Complete(r.reconcileKbom())
}

func (r *ClusterController) reconcileClusterComponents(resourceKind kube.Kind) reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := r.Logger.WithValues("node", req.NamespacedName)
		resourceRef := kube.ObjectRefFromKindAndObjectKey(resourceKind, req.NamespacedName)
		obj, err := r.ObjectFromObjectRef(ctx, resourceRef)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring cached resource that must have been deleted")
				r.clusterCache.Delete(resourceRef.Name)
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting %s from cache: %w", resourceKind, err)
		}
		var key string
		var val any
		switch v := obj.(type) {
		case *corev1.Pod:
			val, err = tk.PodInfo(*v, getLabelSelector(obj))
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("getting %s bom component: %w", resourceKind, err)
			}
			key = v.Name
		case *corev1.Node:
			val = tk.NodeInfo(*v)
			key = v.Name
		}
		oldVal, ok := r.clusterCache.Load(key)
		if ok && oldVal != nil {
			//resource has not changed
			if kube.ComputeHash(oldVal) == kube.ComputeHash(val) {
				return ctrl.Result{}, nil
			}
		}
		r.clusterCache.Store(key, val)

		components := make([]bom.Component, 0)
		nodeInfo := make([]bom.NodeInfo, 0)
		r.clusterCache.Range(func(_, value interface{}) bool {
			switch p := value.(type) {
			case *bom.Component:
				components = append(components, *p)
			case bom.NodeInfo:
				nodeInfo = append(nodeInfo, p)
			}
			return true
		})

		numOfPods, numOfNodes, err := r.numOfCoreComponentPodsAndNodes(ctx)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("getting core pods and nodes count : %w", err)
		}
		// validate that all core components resources has been collected
		if !(len(nodeInfo) == numOfNodes && len(components) == numOfPods) {
			return ctrl.Result{}, nil
		}
		name := fmt.Sprintf("%s/%s", K8sRegistry, K8sRepo)
		br := &bom.Result{
			Components: components,
			ID:         name,
			Type:       "Cluster",
			Version:    r.version,
			Properties: map[string]string{"Name": r.name, "Type": "cluster"},
			NodesInfo:  nodeInfo,
		}
		ar, err := trivyk8s.BomToArtifacts(br)
		if err != nil {
			return ctrl.Result{}, err
		}
		pluginConfig, err := r.GetConfig()
		if err != nil {
			return ctrl.Result{}, err
		}
		apiVersion, err := trivy.Config{PluginConfig: pluginConfig}.GetImageTag()
		if err != nil {
			return ctrl.Result{}, err
		}
		scanner := triv.NewScanner(r.version, nil, flag.Options{
			ReportOptions: flag.ReportOptions{
				Format: ty.FormatCycloneDX,
			},
			AppVersion: apiVersion,
		})
		// scan resource data and generate kbom
		k8sreport, err := scanner.Scan(ctx, ar)
		if err != nil {
			return ctrl.Result{}, err
		}
		output := new(bytes.Buffer)
		w := report.NewCycloneDXWriter(output, cdx.BOMFileFormatJSON, apiVersion)
		err = w.Write(k8sreport.RootComponent)
		if err != nil {
			return ctrl.Result{}, err
		}
		var bomData v1alpha1.BOM
		err = json.Unmarshal(output.Bytes(), &bomData)
		if err != nil {
			return ctrl.Result{}, err
		}

		sbomReportData := v1alpha1.SbomReportData{
			UpdateTimestamp: metav1.NewTime(clock.Now()),
			Scanner: v1alpha1.Scanner{
				Name:    v1alpha1.ScannerNameTrivy,
				Vendor:  "Aqua Security",
				Version: apiVersion,
			},
			Registry: v1alpha1.Registry{Server: K8sRegistry},
			Artifact: v1alpha1.Artifact{
				Repository: K8sRepo,
				Tag:        r.version,
			},
			Summary: sbomreport.BomSummary(bomData),
			Bom:     bomData,
		}
		sbomReportBuilder := sbomreport.NewReportBuilder(r.Client.Scheme()).
			Container(name).
			Data(sbomReportData).
			AdditionalReportLabels(map[string]string{trivyoperator.LabelKbom: kbom})
		sbomReport := sbomReportBuilder.ClusterReport()
		return ctrl.Result{}, r.SbomReadWriter.WriteCluster(ctx, []v1alpha1.ClusterSbomReport{sbomReport})
	}
}

func getLabelSelector(obj client.Object) string {
	label := trivyoperator.LabelCoreComponent
	if _, ok := obj.GetLabels()[trivyoperator.LabelCoreComponent]; ok {
		label = trivyoperator.LabelCoreComponent
	} else if _, ok := obj.GetLabels()[trivyoperator.LabelAddon]; ok {
		label = trivyoperator.LabelAddon
	} else if _, ok := obj.GetLabels()[trivyoperator.LabelOpenShiftAPIServer]; ok {
		label = trivyoperator.LabelOpenShiftAPIServer
	} else if _, ok := obj.GetLabels()[trivyoperator.LabelOpenShiftControllerManager]; ok {
		label = trivyoperator.LabelOpenShiftControllerManager
	} else if _, ok := obj.GetLabels()[trivyoperator.LabelOpenShiftScheduler]; ok {
		label = trivyoperator.LabelOpenShiftScheduler
	} else if _, ok := obj.GetLabels()[trivyoperator.LabelOpenShiftEtcd]; ok {
		label = trivyoperator.LabelOpenShiftEtcd
	}
	return label
}

func (r *ClusterController) reconcileKbom() reconcile.Func {
	return func(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
		log := r.Logger.WithValues("sbom", req.NamespacedName)
		kbom := &v1alpha1.ClusterSbomReport{}
		log.V(1).Info("Getting node from cache")
		err := r.Client.Get(ctx, req.NamespacedName, kbom)
		if err != nil {
			if errors.IsNotFound(err) {
				log.V(1).Info("Ignoring cached kbom that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting kbom from cache: %w", err)
		}
		mlabels := map[string]string{trivyoperator.LabelResourceName: kbom.Name}
		if r.reportExist(ctx, mlabels) {
			return ctrl.Result{}, nil
		}
		dbs := v1alpha1.SbomReportData{
			Bom: kbom.Report.Bom,
		}
		// trigger kbom scan job
		err = r.SubmitScanJob(ctx, &corev1.Pod{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ClusterSbomReport",
				APIVersion: "v1alpha1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: kbom.Name,
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  kbomScanJobIdentifier,
					Image: fmt.Sprintf("%s/%s:%s", K8sRegistry, K8sRepo, r.version),
				}},
			},
		}, map[string]v1alpha1.SbomReportData{kbomScanJobIdentifier: dbs})
		if err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

}

func (r *ClusterController) numOfCoreComponentPodsAndNodes(ctx context.Context) (int, int, error) {
	coreK8slabels := map[string]string{
		"": trivyoperator.LabelCoreComponent,
	}

	if r.isOpenShift() {
		coreK8slabels = map[string]string{
			"openshift-kube-apiserver":          trivyoperator.LabelOpenShiftAPIServer,
			"openshift-kube-controller-manager": trivyoperator.LabelOpenShiftControllerManager,
			"openshift-kube-scheduler":          trivyoperator.LabelOpenShiftScheduler,
			"openshift-etcd":                    trivyoperator.LabelOpenShiftEtcd,
		}
	}

	nodes, err := r.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, 0, err
	}

	corePodsCount := 0
	for namespace, label := range coreK8slabels {
		pods, err := r.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: label})
		if err != nil {
			return 0, 0, err
		}
		corePodsCount = corePodsCount + len(pods.Items)
	}

	addonPods, err := r.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{LabelSelector: trivyoperator.LabelAddon})
	if err != nil {
		return 0, 0, err
	}
	return corePodsCount + len(addonPods.Items), len(nodes.Items), nil
}

func (r *ClusterController) isOpenShift() bool {
	ctx := context.Background()
	_, err := r.clientset.CoreV1().Namespaces().Get(ctx, "openshift-kube-apiserver", metav1.GetOptions{})
	return !k8sapierror.IsNotFound(err)
}

func (r *ClusterController) reportExist(ctx context.Context, mlabels map[string]string) bool {
	var list v1alpha1.ClusterVulnerabilityReportList
	labels := client.MatchingLabels(mlabels)

	err := r.List(ctx, &list, labels)
	if err != nil {
		return false
	}
	return len(list.Items) > 0

}
