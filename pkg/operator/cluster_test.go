package operator

import (
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestMapResources(t *testing.T) {
	tests := []struct {
		name string
		obj  client.Object
		want string
	}{
		{name: "core component", obj: &corev1.Pod{
			ObjectMeta: v1.ObjectMeta{
				Labels: map[string]string{trivyoperator.LabelCoreComponent: ""},
			},
		}, want: "component"},
		{name: "addon", obj: &corev1.Pod{
			ObjectMeta: v1.ObjectMeta{
				Labels: map[string]string{trivyoperator.LabelAddon: ""},
			},
		}, want: "k8s-app"},

		{name: "openshift apiserver", obj: &corev1.Pod{
			ObjectMeta: v1.ObjectMeta{
				Labels: map[string]string{trivyoperator.LabelOpenShiftAPIServer: ""},
			},
		}, want: "apiserver"},
		{name: "openshift controller manager", obj: &corev1.Pod{
			ObjectMeta: v1.ObjectMeta{
				Labels: map[string]string{trivyoperator.LabelOpenShiftControllerManager: ""},
			},
		}, want: "kube-controller-manager"},
		{name: "openshift scheduler", obj: &corev1.Pod{
			ObjectMeta: v1.ObjectMeta{
				Labels: map[string]string{trivyoperator.LabelOpenShiftScheduler: ""},
			},
		}, want: "scheduler"},
		{name: "openshift etcd", obj: &corev1.Pod{
			ObjectMeta: v1.ObjectMeta{
				Labels: map[string]string{trivyoperator.LabelOpenShiftEtcd: ""},
			},
		}, want: "etcd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getLabelSelector(tt.obj)
			assert.Equal(t, got, tt.want)
		})
	}
}
