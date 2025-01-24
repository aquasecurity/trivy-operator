package sbomreport_test

import (
	"testing"

	"github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/sbomreport"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

func TestReportBuilder(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	report, _, err := sbomreport.NewReportBuilder(scheme.Scheme).
		Controller(&appsv1.ReplicaSet{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ReplicaSet",
				APIVersion: "apps/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "some-owner",
				Namespace: "qa",
				Labels:    labels.Set{"tier": "tier-1", "owner": "team-a"},
			},
		}).
		Container("my-container").
		PodSpecHash("xyz").
		Data(v1alpha1.SbomReportData{}).
		ResourceLabelsToInclude([]string{"tier"}).
		Get()

	g.Expect(err).ToNot(gomega.HaveOccurred())
	g.Expect(report).To(gomega.Equal(v1alpha1.SbomReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replicaset-some-owner-my-container",
			Namespace: "qa",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "apps/v1",
					Kind:               "ReplicaSet",
					Name:               "some-owner",
					Controller:         ptr.To[bool](true),
					BlockOwnerDeletion: ptr.To[bool](false),
				},
			},
			Labels: map[string]string{
				trivyoperator.LabelResourceKind:      "ReplicaSet",
				trivyoperator.LabelResourceName:      "some-owner",
				trivyoperator.LabelResourceNamespace: "qa",
				trivyoperator.LabelContainerName:     "my-container",
				trivyoperator.LabelResourceSpecHash:  "xyz",
				"tier":                               "tier-1",
			},
		},
		Report: v1alpha1.SbomReportData{},
	}))
}

func TestArtifactRef(t *testing.T) {
	testCases := []struct {
		name string
		data v1alpha1.SbomReportData
		want string
	}{
		{
			name: "get image ref with library",
			data: v1alpha1.SbomReportData{
				Registry: v1alpha1.Registry{
					Server: "index.docker.io",
				},
				Artifact: v1alpha1.Artifact{
					Repository: "library/alpine",
					Tag:        "3.12.0",
				},
			},
			want: "56bcdb7c95",
		},
		{
			name: "get image ref without library",
			data: v1alpha1.SbomReportData{
				Registry: v1alpha1.Registry{
					Server: "index.docker.io",
				},
				Artifact: v1alpha1.Artifact{
					Repository: "alpine",
					Tag:        "3.12.0",
				},
			},
			want: "56bcdb7c95",
		},
		{
			name: "get image ref without index",
			data: v1alpha1.SbomReportData{
				Registry: v1alpha1.Registry{
					Server: "index.docker.io",
				},
				Artifact: v1alpha1.Artifact{
					Repository: "rancher/local-path-provisioner",
					Tag:        "v0.0.14",
				},
			},
			want: "79b568748c",
		},
		{
			name: "get image ref non docker registry",
			data: v1alpha1.SbomReportData{
				Registry: v1alpha1.Registry{
					Server: "k8s.gcr.io",
				},
				Artifact: v1alpha1.Artifact{
					Repository: "kube-apiserver",
					Tag:        "v1.21.1",
				},
			},
			want: "6857f776bb",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ref := sbomreport.ArtifactRef(tc.data)
			assert.Equal(t, tc.want, ref)
		})

	}
}
