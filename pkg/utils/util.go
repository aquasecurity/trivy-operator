package utils

import (
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/emirpasic/gods/sets/hashset"
)

// MapKinds map resource data
func MapKinds(kinds []string) []string {
	set := hashset.New()
	updatedKinds := make([]string, 0)
	for _, kind := range kinds {
		if !kube.IsValidK8sKind(kind) {
			continue
		}
		if kind == "Workload" {
			set.Add(string(kube.KindPod), string(kube.KindReplicationController),
				string(kube.KindReplicaSet), string(kube.KindStatefulSet),
				string(kube.KindDaemonSet), string(kube.KindCronJob),
				string(kube.KindJob), string(kube.KindDeployment))
		} else {
			set.Add(kind)
		}
	}
	for _, setResource := range set.Values() {
		updatedKinds = append(updatedKinds, setResource.(string))
	}
	return updatedKinds
}
