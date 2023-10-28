package trivy

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/aquasecurity/trivy-operator/pkg/docker"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type GetPodSpecFunc func(ctx trivyoperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext, p *plugin) (corev1.PodSpec, []*corev1.Secret, error)

type PodSpecMgr interface {
	GetPodSpec(ctx trivyoperator.PluginContext, config Config, workload client.Object, credentials map[string]docker.Auth, securityContext *corev1.SecurityContext, p *plugin) (corev1.PodSpec, []*corev1.Secret, error)
}

func NewPodSpecMgr(ctx trivyoperator.PluginContext) (PodSpecMgr, error) {
	pluginConfig, err := ctx.GetConfig()
	if err != nil {
		return nil, err
	}
	config := Config{PluginConfig: pluginConfig}

	mode, err := config.GetMode()
	if err != nil {
		return nil, err
	}
	command, err := config.GetCommand()
	if err != nil {
		return nil, err
	}

	if command == Image {
		switch mode {
		case Standalone:
			return &ImageJobSpecMgr{
				getPodSpecFunc: GetPodSpecForStandaloneMode,
			}, nil
		case ClientServer:
			return &ImageJobSpecMgr{
				getPodSpecFunc: GetPodSpecForClientServerMode,
			}, nil
		default:

		}
	}

	if command == Filesystem || command == Rootfs {
		switch mode {
		case Standalone:
			return &ImageJobSpecMgr{
				getPodSpecFunc: GetPodSpecForStandaloneFSMode,
			}, nil
		case ClientServer:
			return &ImageJobSpecMgr{
				getPodSpecFunc: GetPodSpecForClientServerFSMode,
			}, nil
		}
	}
	return nil, fmt.Errorf("unrecognized trivy mode %q for command %q", mode, command)
}
