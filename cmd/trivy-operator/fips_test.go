package main

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFIPSBuildModule(t *testing.T) {
	tests := []struct {
		name     string
		settings []debug.BuildSetting
		want     string
	}{
		{
			name: "built with FIPS module",
			settings: []debug.BuildSetting{
				{Key: "CGO_ENABLED", Value: "0"},
				{Key: "GOFIPS140", Value: "v1.0.0-c2097c7c"},
			},
			want: "v1.0.0-c2097c7c",
		},
		{
			name:     "built with GOFIPS140=off",
			settings: []debug.BuildSetting{{Key: "GOFIPS140", Value: "off"}},
			want:     "",
		},
		{
			name:     "built without GOFIPS140",
			settings: []debug.BuildSetting{{Key: "CGO_ENABLED", Value: "0"}},
			want:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, fipsBuildModule(&debug.BuildInfo{Settings: tt.settings}))
		})
	}
}
