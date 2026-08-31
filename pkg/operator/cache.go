package operator

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"

	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

const lastAppliedConfigurationAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

// CacheTransform returns the transform applied to every object entering the
// operator's shared informer cache. It strips managed fields, the
// last-applied-configuration annotation, and the contents of every ConfigMap
// other than the operator's own two, all of which keep the cache small.
//
// ConfigMaps that config-audit actually scans have their contents read straight
// from the API server when they are reconciled, so stripping them here does not
// hide them from Rego - see
// (*configauditreport/controller.ResourceController).restoreConfigMapData.
func CacheTransform() toolscache.TransformFunc {
	stripManagedFields := cache.TransformStripManagedFields()

	return func(obj any) (any, error) {
		obj, err := stripManagedFields(obj)
		if err != nil {
			return obj, err
		}

		if metaObj, ok := obj.(metav1.ObjectMetaAccessor); ok {
			annotations := metaObj.GetObjectMeta().GetAnnotations()
			if annotations != nil {
				delete(annotations, lastAppliedConfigurationAnnotation)
				metaObj.GetObjectMeta().SetAnnotations(annotations)
			}
		}

		if cm, ok := obj.(*corev1.ConfigMap); ok {
			// Strip data from ALL ConfigMaps except the two operator ConfigMaps,
			// which the operator reads through the cached client.
			if cm.Name != trivyoperator.PoliciesConfigMapName && cm.Name != trivyoperator.TrivyConfigMapName {
				cm.Data = nil
				cm.BinaryData = nil
			}
		}

		return obj, nil
	}
}
