package predicate

import (
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
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
				matches, err := filepath.Match(strings.TrimSpace(namespace), obj.GetNamespace())
				if err != nil {
					// In case of error we'd assume the resource should be scanned
					return true
				}
				if matches {
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
