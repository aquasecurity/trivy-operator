package kube

import (
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ScopeResolver struct {
	clusterScopeKinds map[string]bool
}

func NewScopeResolver(c client.Client) *ScopeResolver {
	sr := &ScopeResolver{clusterScopeKinds: make(map[string]bool)}

	// add pre-defined cluster-scoped kinds
	sr.clusterScopeKinds["clusterrole"] = true
	sr.clusterScopeKinds["clusterrolebinding"] = true
	sr.clusterScopeKinds["customresourcedefinition"] = true

	scm := c.Scheme()
	if scm == nil {
		return sr
	}
	mapper := c.RESTMapper()
	for gvk := range scm.AllKnownTypes() {
		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			continue
		}
		if mapping.Scope.Name() == meta.RESTScopeNameRoot {
			sr.clusterScopeKinds[strings.ToLower(gvk.Kind)] = true
		}
	}

	return sr
}

func (sr *ScopeResolver) IsClusterScope(kind string) bool {
	return sr.clusterScopeKinds[strings.ToLower(kind)]
}
