package workload

import (
	"fmt"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/go-logr/logr"
	"golang.org/x/net/context"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func SkipProcessing(ctx context.Context, resource client.Object, or kube.ObjectResolver, scanOnlyCurrentRevisions bool, log logr.Logger) (bool, error) {
	controller := metav1.GetControllerOf(resource)
	switch resource.(type) {
	case *appsv1.ReplicaSet:
		if scanOnlyCurrentRevisions {
			activeReplicaSet, err := or.IsActiveReplicaSet(ctx, resource, controller)
			if err != nil {
				return true, fmt.Errorf("failed checking current revision: %w", err)
			}
			if !activeReplicaSet {
				log.V(1).Info("Ignoring inactive ReplicaSet", "controllerKind", controller.Kind, "controllerName", controller.Name)
				return true, nil
			}
		}
	case *corev1.Pod:
		if kube.IsBuiltInWorkload(controller) {
			log.V(1).Info("Ignoring managed pod",
				"controllerKind", controller.Kind,
				"controllerName", controller.Name)
			return true, nil
		}
	case *batchv1.Job:
		if controller != nil && controller.Kind == string(kube.KindCronJob) {
			log.V(1).Info("Ignoring managed job", "controllerKind", controller.Kind, "controllerName", controller.Name)
			return true, nil
		}
	}
	return false, nil
}
