package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapResources(t *testing.T) {
	tests := []struct {
		name  string
		kinds []string
		want  int
	}{
		{name: "with workload", kinds: []string{"Workload"}, want: 8},
		{name: "dup kinds", kinds: []string{"Workload", "Pod", "Job"}, want: 8},
		{name: "empty kinds", kinds: []string{}, want: 0},
		{name: "non valid kinds", kinds: []string{"Pod", "Koko"}, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MapKinds(tt.kinds)
			assert.Equal(t, len(got), tt.want)
		})
	}
}
