package main

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestFIPSEnabledMessage(t *testing.T) {
	t.Run("built with FIPS module", func(t *testing.T) {
		assert.Equal(t, "FIPS 140-3 mode enabled", fipsEnabledMessage("v1.0.0-c2097c7c"))
	})
	t.Run("built without FIPS module", func(t *testing.T) {
		msg := fipsEnabledMessage("")
		assert.Contains(t, msg, "WARNING")
		assert.Contains(t, msg, "non-validated module")
	})
}

func TestFIPSDisabledError(t *testing.T) {
	t.Run("built with FIPS module", func(t *testing.T) {
		err := fipsDisabledError("v1.0.0-c2097c7c")
		require.ErrorContains(t, err, "FIPS 140-3 mode is disabled")
		assert.ErrorContains(t, err, "v1.0.0-c2097c7c")
	})
	t.Run("built without FIPS module", func(t *testing.T) {
		assert.NoError(t, fipsDisabledError(""))
	})
}
