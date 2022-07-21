package reports_test

import (
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/reports"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// This name is longer than the allowed max label value length (63 chars)
	longName = "wFnr9RzD3ELAtP18V0yxlOEQU4zFPzLi0BPPSBhYq8dHjm1rDKipV3yaZDP9H8EaSJmhlBRXoIc7niDp"
	// Some initial K8s types allow any character except unsafe ones
	uppercaseName = "cluster-crd-clusterRole"
	// Underscores are allowed in label values, but not in names
	underscoreName = "some_strange_resource"
)

func TestNameFromController(t *testing.T) {
	type args struct {
		controller client.Object
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{name: "standard name", args: args{controller: newClusterRole("admin")}, want: "clusterrole-admin"},
		{name: "uppercase name", args: args{controller: newClusterRole(uppercaseName)}, want: "clusterrole-5bdb67fb96"},
		{name: "underscore name", args: args{controller: newClusterRole(underscoreName)}, want: "clusterrole-77f8d84c9f"},
		{name: "long name", args: args{controller: newClusterRole(longName)}, want: "clusterrole-7b4cdd687c"},
		{name: "other kind", args: args{controller: newPod("my-pod")}, want: "pod-my-pod"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reports.NameFromController(tt.args.controller); got != tt.want {
				t.Errorf("NameFromController() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNameFromControllerContainer(t *testing.T) {
	type args struct {
		controller client.Object
		container  string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{name: "standard name", args: args{controller: newPod("pod-123"), container: "app"}, want: "pod-pod-123-app"},
		{name: "uppercase name", args: args{controller: newPod(uppercaseName), container: "nginx"}, want: "pod-57fbbcc98f"},
		{name: "underscore name", args: args{controller: newPod(underscoreName), container: "bin"}, want: "pod-94c47cb9f"},
		{name: "long name", args: args{controller: newPod(longName), container: "hello"}, want: "pod-f78f5c56"},
		{name: "other kind", args: args{controller: newClusterRole("my-other-resource"), container: "foo"}, want: "clusterrole-my-other-resource-foo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reports.NameFromControllerContainer(tt.args.controller, tt.args.container); got != tt.want {
				t.Errorf("NameFromControllerContainer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func newClusterRole(name string) *rbacv1.ClusterRole {
	cr := &rbacv1.ClusterRole{}
	cr.Name = name
	cr.Kind = string(kube.KindClusterRole)
	return cr
}

func newPod(name string) *corev1.Pod {
	pod := &corev1.Pod{}
	pod.Name = name
	pod.Kind = string(kube.KindPod)
	return pod
}
