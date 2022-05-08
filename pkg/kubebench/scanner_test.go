package kubebench_test

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/kubebench"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
)

var (
	fixedTime  = time.Now()
	fixedClock = ext.NewFixedClock(fixedTime)
)

func TestKubeBenchPlugin_GetScanJobSpec(t *testing.T) {
	config := trivyoperator.ConfigData{
		"kube-bench.imageRef": "docker.io/aquasec/kube-bench:v0.6.6",
	}
	node := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "control-plane",
		},
	}
	instance := kubebench.NewKubeBenchPlugin(fixedClock, config)

	podSpec, err := instance.GetScanJobSpec(node)

	require.NoError(t, err)
	assert.Equal(t, corev1.PodSpec{
		ServiceAccountName:           trivyoperator.ServiceAccountName,
		AutomountServiceAccountToken: pointer.BoolPtr(true),
		RestartPolicy:                corev1.RestartPolicyNever,
		HostPID:                      true,
		NodeName:                     node.Name,
		SecurityContext: &corev1.PodSecurityContext{
			RunAsUser:  pointer.Int64Ptr(0),
			RunAsGroup: pointer.Int64Ptr(0),
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
		},
		Volumes: []corev1.Volume{
			{
				Name: "var-lib-etcd",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/lib/etcd",
					},
				},
			},
			{
				Name: "var-lib-kubelet",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/lib/kubelet",
					},
				},
			},
			{
				Name: "etc-systemd",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/etc/systemd",
					},
				},
			},
			{
				Name: "etc-kubernetes",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/etc/kubernetes",
					},
				},
			},
			{
				Name: "usr-bin",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/usr/bin",
					},
				},
			},
		},
		Containers: []corev1.Container{
			{
				Name:                     "kube-bench",
				Image:                    "docker.io/aquasec/kube-bench:v0.6.6",
				ImagePullPolicy:          corev1.PullIfNotPresent,
				TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
				Command:                  []string{"sh"},
				Args:                     []string{"-c", "kube-bench --json 2> /dev/null"},
				SecurityContext: &corev1.SecurityContext{
					Privileged:               pointer.BoolPtr(false),
					AllowPrivilegeEscalation: pointer.BoolPtr(false),
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"all"},
					},
					ReadOnlyRootFilesystem: pointer.BoolPtr(true),
				},
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("300m"),
						corev1.ResourceMemory: resource.MustParse("300M"),
					},
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("50m"),
						corev1.ResourceMemory: resource.MustParse("50M"),
					},
				},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "var-lib-etcd",
						MountPath: "/var/lib/etcd",
						ReadOnly:  true,
					},
					{
						Name:      "var-lib-kubelet",
						MountPath: "/var/lib/kubelet",
						ReadOnly:  true,
					},
					{
						Name:      "etc-systemd",
						MountPath: "/etc/systemd",
						ReadOnly:  true,
					},
					{
						Name:      "etc-kubernetes",
						MountPath: "/etc/kubernetes",
						ReadOnly:  true,
					},
					{
						Name:      "usr-bin",
						MountPath: "/usr/local/mount-from-host/bin",
						ReadOnly:  true,
					},
				},
			},
		},
	}, podSpec)
}

func TestKubeBenchPlugin_ParseCISKubeBenchOutput(t *testing.T) {
	config := trivyoperator.ConfigData{
		"kube-bench.imageRef": "docker.io/aquasec/kube-bench:v0.6.6",
	}
	var testCases = []struct {
		name string
		in   string // input File
		op   string // golden file
		err  error  // expected error
	}{
		{
			name: "Valid single json object in array",
			in:   "testdata/valid.json",
			op:   "testdata/goldenSingle.json",
			err:  nil,
		},
		{
			name: "invalid json object",
			in:   "testdata/invalid.json",
			err:  errors.New("invalid character 'I' looking for beginning of value"),
		},
		{
			name: "Valid multiple json object in array",
			in:   "testdata/multiObjects.json",
			op:   "testdata/goldenMultiple.json",
			err:  nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			inFile, err := os.Open(tc.in)
			require.NoError(t, err)
			defer func() {
				_ = inFile.Close()
			}()

			instance := kubebench.NewKubeBenchPlugin(fixedClock, config)
			output, err := instance.ParseCISKubeBenchReportData(inFile)

			switch {
			case tc.err == nil:
				require.NoError(t, err)
				expectedOutput := expectedOutputFrom(t, tc.op)
				assert.Equal(t, expectedOutput, output, "Converted report does not match expected report")
			default:
				assert.EqualError(t, err, tc.err.Error())
			}
		})
	}
}

func expectedOutputFrom(t *testing.T, fileName string) v1alpha1.CISKubeBenchReportData {
	t.Helper()

	file, err := os.Open(fileName)
	require.NoError(t, err)
	defer file.Close()

	var expectedOutput v1alpha1.CISKubeBenchReportData
	err = json.NewDecoder(file).Decode(&expectedOutput)
	require.NoError(t, err)

	// Override time read from file
	expectedOutput.UpdateTimestamp = metav1.NewTime(fixedTime)

	return expectedOutput
}
