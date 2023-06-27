package workload

import (
	"errors"
	"fmt"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/go-logr/logr"
	"golang.org/x/exp/maps"
	"golang.org/x/net/context"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/strings/slices"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func SkipProcessing(ctx context.Context, resource client.Object, or kube.ObjectResolver, scanOnlyCurrentRevisions bool, log logr.Logger, skipResourceLabels []string) (bool, error) {
	if len(skipResourceLabels) > 0 {
		resourceLabelKeys := maps.Keys(resource.GetLabels())
		for _, skipResourceLabel := range skipResourceLabels {
			if slices.Contains(resourceLabelKeys, skipResourceLabel) {
				return true, nil
			}
		}
	}
	switch r := resource.(type) {
	case *appsv1.ReplicaSet:
		_, err := or.GetActivePodsMatchingLabels(ctx, resource.GetNamespace(), r.Spec.Selector.MatchLabels)
		if err != nil {
			if errors.Is(err, kube.ErrNoRunningPods) {
				log.V(1).Info("Ignoring ReplicaSet with no active pods", "name", resource.GetName())
				return true, nil
			}
			return true, err
		}
		if scanOnlyCurrentRevisions {
			controller := metav1.GetControllerOf(resource)
			activeReplicaSet, err := or.IsActiveReplicaSet(ctx, resource, controller)
			if err != nil {
				return true, fmt.Errorf("failed checking current revision: %w", err)
			}
			if !activeReplicaSet {
				log.V(1).Info("Ignoring inactive ReplicaSet", "controllerKind", controller.Kind, "controllerName", controller.Name)
				err := MarkOldReportForImmediateDeletion(ctx, or, resource.GetNamespace(), resource.GetName())
				if err != nil {
					return true, fmt.Errorf("failed marking old reports for immediate deletion : %w", err)
				}
				return true, nil
			}
		}
	case *corev1.ReplicationController:
		_, err := or.GetActivePodsMatchingLabels(ctx, resource.GetNamespace(), r.Spec.Selector)
		if err != nil {
			if errors.Is(err, kube.ErrNoRunningPods) {
				log.V(1).Info("Ignoring ReplicationController with no active pods", "name", resource.GetName())
				return true, nil
			}
			return true, err
		}
		if scanOnlyCurrentRevisions {
			controller := metav1.GetControllerOf(resource)
			activeReplicationController, err := or.IsActiveReplicationController(ctx, resource, controller)
			if err != nil {
				return true, fmt.Errorf("failed checking current revision: %w", err)
			}
			if !activeReplicationController {
				log.V(1).Info("Ignoring inactive ReplicationController", "controllerKind", controller.Kind, "controllerName", controller.Name)
				err := MarkOldReportForImmediateDeletion(ctx, or, resource.GetNamespace(), resource.GetName())
				if err != nil {
					return true, fmt.Errorf("failed marking old reports for immediate deletion : %w", err)
				}
				return true, nil
			}
		}
	case *appsv1.StatefulSet:
		_, err := or.GetActivePodsMatchingLabels(ctx, resource.GetNamespace(), r.Spec.Selector.MatchLabels)
		if err != nil {
			if errors.Is(err, kube.ErrNoRunningPods) {
				log.V(1).Info("Ignoring StatefulSet with no active pods", "name", resource.GetName())
				return true, nil
			}
			return true, err
		}

	case *corev1.Pod:
		controller := metav1.GetControllerOf(resource)
		if kube.IsBuiltInWorkload(controller) {
			log.V(1).Info("Ignoring managed pod",
				"controllerKind", controller.Kind,
				"controllerName", controller.Name)
			return true, nil
		}
		annotations := resource.GetAnnotations()
		// Ignore scanning of system pod which is created for deploymentConfig
		if value, ok := annotations[kube.DeployerPodForDeploymentAnnotation]; ok {
			log.V(1).Info("Ignoring system pod created for deployment config",
				"deploymentConfigName", value)
			return true, nil
		}
	case *batchv1.Job:
		controller := metav1.GetControllerOf(resource)
		if controller != nil && controller.Kind == string(kube.KindCronJob) {
			log.V(1).Info("Ignoring managed job", "controllerKind", controller.Kind, "controllerName", controller.Name)
			return true, nil
		}
	}
	return false, nil
}

// GetReportsByLabel fetch reports by matching labels
func GetReportsByLabel(ctx context.Context, resolver kube.ObjectResolver, objectList client.ObjectList, namespace string,
	labels map[string]string) error {
	err := resolver.Client.List(ctx, objectList,
		client.InNamespace(namespace),
		client.MatchingLabels(labels))
	if err != nil {
		return fmt.Errorf("listing reports in namespace %s matching labels %v: %w", namespace,
			labels, err)
	}
	return err
}

// MarkOldReportForImmediateDeletion set old (historical replicaSets) reports with TTL = 0 for immediate deletion
func MarkOldReportForImmediateDeletion(ctx context.Context, resolver kube.ObjectResolver, namespace string, resourceName string) error {
	annotation := map[string]string{
		v1alpha1.TTLReportAnnotation: time.Duration(0).String(),
	}
	resourceNameLabels := map[string]string{trivyoperator.LabelResourceName: resourceName}
	err := markOldVulnerabilityReports(ctx, resolver, namespace, resourceNameLabels, annotation)
	if err != nil {
		return err
	}
	err = markOldConfigAuditReports(ctx, resolver, namespace, resourceNameLabels, annotation)
	if err != nil {
		return err
	}
	err = markOldExposeSecretsReport(ctx, resolver, namespace, resourceNameLabels, annotation)
	if err != nil {
		return err
	}
	return nil
}

func markOldVulnerabilityReports(ctx context.Context, resolver kube.ObjectResolver, namespace string, resourceNameLabels map[string]string, annotation map[string]string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var vulnerabilityReportList v1alpha1.VulnerabilityReportList
		err := GetReportsByLabel(ctx, resolver, &vulnerabilityReportList, namespace, resourceNameLabels)
		if err != nil {
			return err
		}
		for _, report := range vulnerabilityReportList.Items {
			err := markReportTTL(ctx, resolver, report.DeepCopy(), annotation)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func markOldConfigAuditReports(ctx context.Context, resolver kube.ObjectResolver, namespace string, resourceNameLabels map[string]string, annotation map[string]string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var configAuditReportList v1alpha1.ConfigAuditReportList
		err := GetReportsByLabel(ctx, resolver, &configAuditReportList, namespace, resourceNameLabels)
		if err != nil {
			return err
		}
		for _, report := range configAuditReportList.Items {
			err := markReportTTL(ctx, resolver, report.DeepCopy(), annotation)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func markOldExposeSecretsReport(ctx context.Context, resolver kube.ObjectResolver, namespace string, resourceNameLabels map[string]string, annotation map[string]string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var exposeSecretReportList v1alpha1.ExposedSecretReportList
		err := GetReportsByLabel(ctx, resolver, &exposeSecretReportList, namespace, resourceNameLabels)
		if err != nil {
			return err
		}
		for _, report := range exposeSecretReportList.Items {
			err := markReportTTL(ctx, resolver, report.DeepCopy(), annotation)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func markReportTTL[T client.Object](ctx context.Context, resolver kube.ObjectResolver, report T, annotation map[string]string) error {
	report.SetAnnotations(annotation)
	err := resolver.Client.Update(ctx, report)
	if err != nil {
		return err
	}
	return nil
}
