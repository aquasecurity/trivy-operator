package compliance

import (
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

func TestMapResources(t *testing.T) {
	tests := []struct {
		name  string
		kinds []string
		want  int
	}{
		{name: "with workload", kinds: []string{"Workload"}, want: 7},
		{name: "dup kinds", kinds: []string{"Workload", "Pod", "Job"}, want: 7},
		{name: "empty kinds", kinds: []string{}, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapKinds(v1alpha1.Control{Kinds: tt.kinds})
			assert.Equal(t, len(got), tt.want)
		})
	}
}
