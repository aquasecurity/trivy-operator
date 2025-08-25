package kube

import (
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNewK8sScopeResolver(t *testing.T) {
	sch := runtime.NewScheme()

	if err := corev1.AddToScheme(sch); err != nil {
		t.Fatalf("add core to scheme: %v", err)
	}
	if err := rbacv1.AddToScheme(sch); err != nil {
		t.Fatalf("add rbac to scheme: %v", err)
	}
	if err := apiextv1.AddToScheme(sch); err != nil {
		t.Fatalf("add apiext to scheme: %v", err)
	}

	rm := meta.NewDefaultRESTMapper([]schema.GroupVersion{
		corev1.SchemeGroupVersion,
		rbacv1.SchemeGroupVersion,
		apiextv1.SchemeGroupVersion,
	})
	rm.Add(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}, meta.RESTScopeNamespace)
	rm.Add(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"}, meta.RESTScopeNamespace)
	rm.Add(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Node"}, meta.RESTScopeRoot)
	rm.Add(schema.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRole"}, meta.RESTScopeRoot)
	rm.Add(schema.GroupVersionKind{Group: "apiextensions.k8s.io", Version: "v1", Kind: "CustomResourceDefinition"}, meta.RESTScopeRoot)

	c := fake.NewClientBuilder().WithScheme(sch).WithRESTMapper(rm).Build()
	sr := NewK8sScopeResolver(c)

	tests := []struct {
		name         string
		kind         string
		wantCluster  bool
		wantGVK      schema.GroupVersionKind
		wantGVKFound bool
	}{
		{
			name:         "predefined only (ClusterRoleBinding)",
			kind:         "ClUsTeRrOlEbInDiNg",
			wantCluster:  true,
			wantGVKFound: false, // not registered in mapper
		},
		{
			name:         "mapped cluster-scoped CRD",
			kind:         "CustomResourceDefinition",
			wantCluster:  true,
			wantGVK:      schema.GroupVersionKind{Group: "apiextensions.k8s.io", Version: "v1", Kind: "CustomResourceDefinition"},
			wantGVKFound: true,
		},
		{
			name:         "mapped namespaced Pod",
			kind:         "pOd",
			wantCluster:  false,
			wantGVK:      schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
			wantGVKFound: true,
		},
		{
			name:         "mapped namespaced ConfigMap",
			kind:         "CoNfIgMaP",
			wantCluster:  false,
			wantGVK:      schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
			wantGVKFound: true,
		},
		{
			name:         "mapped cluster-scoped Node",
			kind:         "Node",
			wantCluster:  true,
			wantGVK:      schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Node"},
			wantGVKFound: true,
		},
		{
			name:         "mapped cluster-scoped ClusterRole",
			kind:         "ClUsTeRrOlE",
			wantCluster:  true,
			wantGVK:      schema.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRole"},
			wantGVKFound: true,
		},
		{
			name:         "unknown kind",
			kind:         "SomeUnknown",
			wantCluster:  false,
			wantGVKFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sr.IsClusterScope(tt.kind); got != tt.wantCluster {
				t.Fatalf("IsClusterScope(%q)=%v want %v", tt.kind, got, tt.wantCluster)
			}
			gotGVK, ok := sr.GVKbyKind(tt.kind)
			if ok != tt.wantGVKFound {
				t.Fatalf("GVKbyKind(%q) found=%v want %v (gvk=%#v)", tt.kind, ok, tt.wantGVKFound, gotGVK)
			}
			if ok && gotGVK != tt.wantGVK {
				t.Fatalf("GVKbyKind(%q)=%#v want %#v", tt.kind, gotGVK, tt.wantGVK)
			}
			// Sanity: keys are case-insensitive
			if sr.IsClusterScope(strings.ToLower(tt.kind)) != sr.IsClusterScope(strings.ToUpper(tt.kind)) {
				t.Fatalf("expected case-insensitive cluster scope lookup for %q", tt.kind)
			}
		})
	}
}
