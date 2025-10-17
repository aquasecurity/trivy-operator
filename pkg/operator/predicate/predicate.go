package predicate

import (
	"path/filepath"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

// InstallModePredicate is a predicate.Predicate that determines whether to
// reconcile the specified client.Object based on the give etc.InstallMode.
//
// In etc.SingleNamespace install mode we're configuring client.Client cache
// to watch the operator namespace, in which the operator runs scan jobs.
// However, we do not want to scan the workloads that might run in the
// operator namespace.
//
// Similarly, in etc.MultiNamespace install mode we're configuring
// client.Client cache to watch the operator namespace, in which the operator
// runs scan jobs. However, we do not want to scan the workloads that might run
// in the operator namespace unless the operator namespace is added to the list
// of target namespaces.
var InstallModePredicate = func(config etc.Config) (predicate.Predicate, error) {
	mode, operatorNamespace, targetNamespaces, err := config.ResolveInstallMode()
	if err != nil {
		return nil, err
	}
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if mode == etc.SingleNamespace {
			return targetNamespaces[0] == obj.GetNamespace() &&
				operatorNamespace != obj.GetNamespace()
		}

		if mode == etc.MultiNamespace {
			return ext.SliceContainsString(targetNamespaces, obj.GetNamespace())
		}

		if mode == etc.AllNamespaces && strings.TrimSpace(config.ExcludeNamespaces) != "" {
			namespaces := strings.Split(config.ExcludeNamespaces, ",")
			for _, namespace := range namespaces {
				matched, err := filepath.Match(strings.TrimSpace(namespace), obj.GetNamespace())
				if err != nil {
					return true
				}
				if matched {
					return false
				}
			}
		}
		return true
	}), nil
}

// HasName is predicate.Predicate that returns true if the
// specified client.Object has the desired name.
var HasName = func(name string) predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return name == obj.GetName()
	})
}

// InNamespace is a predicate.Predicate that returns true if the
// specified client.Object is in the desired namespace.
var InNamespace = func(namespace string) predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return namespace == obj.GetNamespace()
	})
}

// ManagedByTrivyOperator is a predicate.Predicate that returns true if the
// specified client.Object is managed by Trivy-Operator.
//
// For example, pods controlled by jobs scheduled by Trivy-Operator Operator are
// labeled with `app.kubernetes.io/managed-by=trivyoperator`.
var ManagedByTrivyOperator = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	if managedBy, ok := obj.GetLabels()[trivyoperator.LabelK8SAppManagedBy]; ok {
		return managedBy == trivyoperator.AppTrivyOperator
	}
	return false
})

var ManagedByKubeEnforcer = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	if managedBy, ok := obj.GetLabels()["app.kubernetes.io/managed-by"]; ok {
		return managedBy == "KubeEnforcer"
	}
	if app, ok := obj.GetLabels()["app"]; ok {
		return app == "kube-bench"
	}
	return false
})

// IsBeingTerminated is a predicate.Predicate that returns true if the specified
// client.Object is being terminated, i.e. its DeletionTimestamp property is set to non nil value.
var IsBeingTerminated = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	return obj.GetDeletionTimestamp() != nil
})

// JobHasAnyCondition is a predicate.Predicate that returns true if the
// specified client.Object is a v1.Job with any v1.JobConditionType.
var JobHasAnyCondition = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	if job, ok := obj.(*batchv1.Job); ok {
		return len(job.Status.Conditions) > 0
	}
	return false
})

var IsVulnerabilityReportScan = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	if _, ok := obj.GetLabels()[trivyoperator.LabelVulnerabilityReportScanner]; ok {
		return true
	}
	return false
})

var IsNodeInfoCollector = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	if _, ok := obj.GetLabels()[trivyoperator.LabelNodeInfoCollector]; ok {
		return true
	}
	return false
})

var IsLinuxNode = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	if os, exists := obj.GetLabels()[corev1.LabelOSStable]; exists && os == "linux" {
		return true
	}
	return false
})

var ExcludeNode = func(config trivyoperator.ConfigData) (predicate.Predicate, error) {
	excludeNodes, err := config.GetNodeCollectorExcludeNodes()
	if err != nil {
		return nil, err
	}
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if len(excludeNodes) == 0 {
			return false
		}
		var matchingLabels int
		for key, val := range excludeNodes {
			if lVal, ok := obj.GetLabels()[key]; ok && lVal == val {
				matchingLabels++
			}
		}
		return matchingLabels == len(excludeNodes)
	}), nil
}

// IsLeaderElectionResource returns true for resources used in leader election, means resources
// annotated with resourcelock.LeaderElectionRecordAnnotationKey.
var IsLeaderElectionResource = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	if _, ok := obj.GetAnnotations()[resourcelock.LeaderElectionRecordAnnotationKey]; ok {
		return true
	}
	return false
})

func Not(p predicate.Predicate) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(event event.CreateEvent) bool {
			return !p.Create(event)
		},
		DeleteFunc: func(event event.DeleteEvent) bool {
			return !p.Delete(event)
		},
		UpdateFunc: func(event event.UpdateEvent) bool {
			return !p.Update(event)
		},
		GenericFunc: func(event event.GenericEvent) bool {
			return !p.Generic(event)
		},
	}
}

var IsCoreComponents = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	switch v := obj.(type) {
	case *corev1.Pod:
		if _, ok := v.GetLabels()[trivyoperator.LabelCoreComponent]; ok {
			return true
		} else if _, ok := v.GetLabels()[trivyoperator.LabelAddon]; ok {
			return true
		} else if _, ok := v.GetLabels()[trivyoperator.LabelOpenShiftAPIServer]; ok {
			return true
		} else if _, ok := v.GetLabels()[trivyoperator.LabelOpenShiftControllerManager]; ok {
			return true
		} else if _, ok := v.GetLabels()[trivyoperator.LabelOpenShiftScheduler]; ok {
			return true
		} else if _, ok := v.GetLabels()[trivyoperator.LabelOpenShiftEtcd]; ok {
			return true
		}
		return false
	case *corev1.Node:
		return true
	}
	return false
})

var IsKbom = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	if _, ok := obj.GetLabels()[trivyoperator.LabelKbom]; ok {
		return true
	}
	return false
})

// isWorkloadInitializing detects if any workload is in its initialization phase
// Uses ObservedGeneration lag as the primary signal
func isWorkloadInitializing(_, newObj client.Object) bool {
	logger := log.Log.WithName("predicate").WithValues(
		"kind", newObj.GetObjectKind().GroupVersionKind().Kind,
		"name", newObj.GetName(),
		"namespace", newObj.GetNamespace(),
	)

	// Check if controller hasn't caught up with spec changes
	switch obj := newObj.(type) {
	case *appsv1.ReplicaSet:
		isInitializing := obj.Status.ObservedGeneration < obj.Generation
		if isInitializing {
			logger.V(1).Info("Workload initializing: ObservedGeneration lag",
				"generation", obj.Generation,
				"observedGeneration", obj.Status.ObservedGeneration)
		}
		return isInitializing
	case *appsv1.Deployment:
		isInitializing := obj.Status.ObservedGeneration < obj.Generation
		if isInitializing {
			logger.V(1).Info("Workload initializing: ObservedGeneration lag",
				"generation", obj.Generation,
				"observedGeneration", obj.Status.ObservedGeneration)
		}
		return isInitializing
	case *appsv1.StatefulSet:
		isInitializing := obj.Status.ObservedGeneration < obj.Generation
		if isInitializing {
			logger.V(1).Info("Workload initializing: ObservedGeneration lag",
				"generation", obj.Generation,
				"observedGeneration", obj.Status.ObservedGeneration)
		}
		return isInitializing
	case *appsv1.DaemonSet:
		isInitializing := obj.Status.ObservedGeneration < obj.Generation
		if isInitializing {
			logger.V(1).Info("Workload initializing: ObservedGeneration lag",
				"generation", obj.Generation,
				"observedGeneration", obj.Status.ObservedGeneration)
		}
		return isInitializing
	default:
		// For workloads without ObservedGeneration (Jobs, CronJobs, Pods, custom resources),
		// use a conservative time window to handle initialization scenarios
		age := time.Since(newObj.GetCreationTimestamp().Time)
		isInitializing := age < 30*time.Second
		if isInitializing {
			logger.V(1).Info("Workload initializing: time window fallback",
				"age", age.String(),
				"window", "30s")
		}
		return isInitializing
	}
}

// WorkloadPodSpecChangedPredicate creates a predicate that only triggers reconciliation
// when the workload's podSpec actually changes, not just metadata updates.
func WorkloadPodSpecChangedPredicate() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			logger := log.Log.WithName("predicate").WithValues(
				"kind", e.ObjectNew.GetObjectKind().GroupVersionKind().Kind,
				"name", e.ObjectNew.GetName(),
				"namespace", e.ObjectNew.GetNamespace(),
			)

			if e.ObjectOld == nil || e.ObjectNew == nil {
				return true // Always process creation/deletion
			}

			// Generation-based detection
			// Kubernetes increments generation when spec fields change
			if e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration() {
				logger.V(1).Info("Allowing reconciliation: generation changed",
					"oldGeneration", e.ObjectOld.GetGeneration(),
					"newGeneration", e.ObjectNew.GetGeneration())
				return true // Definite spec change
			}

			// Detect workload initialization state
			if isWorkloadInitializing(e.ObjectOld, e.ObjectNew) {
				logger.V(1).Info("Allowing reconciliation: workload initializing")
				return true
			}

			// Fallback to podSpec comparison for edge cases
			oldPodSpec, err := kube.GetPodSpec(e.ObjectOld)
			if err != nil {
				logger.V(1).Info("Allowing reconciliation: cannot get old podSpec", "error", err)
				return true // If we can't get podSpec, process it
			}

			newPodSpec, err := kube.GetPodSpec(e.ObjectNew)
			if err != nil {
				logger.V(1).Info("Allowing reconciliation: cannot get new podSpec", "error", err)
				return true // If we can't get podSpec, process it
			}

			// Compare podSpec hashes
			oldHash := kube.ComputeHash(oldPodSpec)
			newHash := kube.ComputeHash(newPodSpec)

			// Only reconcile if podSpec actually changed
			if oldHash != newHash {
				logger.V(1).Info("Allowing reconciliation: podSpec changed",
					"oldHash", oldHash, "newHash", newHash)
				return true
			}

			// If we reach here, this is just a metadata/status update
			logger.V(1).Info("Filtering reconciliation: metadata-only update",
				"oldGeneration", e.ObjectOld.GetGeneration(),
				"newGeneration", e.ObjectNew.GetGeneration(),
				"podSpecHash", oldHash)
			return false
		},
		CreateFunc: func(_ event.CreateEvent) bool {
			return true // Always process new workloads
		},
		DeleteFunc: func(_ event.DeleteEvent) bool {
			return true // Always process deletions (for cleanup)
		},
		GenericFunc: func(_ event.GenericEvent) bool {
			return true // Process generic events
		},
	}
}
