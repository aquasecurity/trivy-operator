package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeLabelName(t *testing.T) {
	tests := []struct {
		name  string
		label string
		want  string
	}{
		{name: "valid label", label: "owner", want: "owner"},
		{name: "label with slash", label: "app/name", want: "app_name"},
		{name: "label with dot", label: "app.name", want: "app_name"},
		{name: "label with dot and slash", label: "app.kubernetes.io/name", want: "app_kubernetes_io_name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeLabelName(tt.label)
			assert.Equal(t, got, tt.want)
		})
	}
}
