package kube

import (
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type K8sScope struct {
	clusterScopeKinds map[string]bool
	gvkByKind         map[string]schema.GroupVersionKind
}

func NewK8sScopeResolver(c client.Client) K8sScope {
	sr := K8sScope{
		clusterScopeKinds: make(map[string]bool),
		gvkByKind:         make(map[string]schema.GroupVersionKind),
	}

	// add pre-defined cluster-scoped kinds
	sr.clusterScopeKinds["clusterrole"] = true
	sr.clusterScopeKinds["clusterrolebinding"] = true
	sr.clusterScopeKinds["customresourcedefinition"] = true

	scm := c.Scheme()
	if scm == nil {
		return sr
	}
	mapper := c.RESTMapper()
	allKinds := scm.AllKnownTypes()
	for gvk := range allKinds {
		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			continue
		}
		kind := strings.ToLower(gvk.Kind)
		sr.gvkByKind[kind] = gvk
		if mapping.Scope.Name() == meta.RESTScopeNameRoot {
			sr.clusterScopeKinds[kind] = true
		}
	}

	return sr
}

func (sr K8sScope) IsClusterScope(kind string) bool {
	return sr.clusterScopeKinds[strings.ToLower(kind)]
}

func (sr K8sScope) GVKbyKind(kind string) (schema.GroupVersionKind, bool) {
	gvk, ok := sr.gvkByKind[strings.ToLower(kind)]
	return gvk, ok
}
