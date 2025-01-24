package trivy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-operator/pkg/plugins/trivy"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

func TestSlow(t *testing.T) {
	testCases := []struct {
		name       string
		configData trivyoperator.ConfigData
		want       string
	}{{

		name: "slow param set to true",
		configData: map[string]string{
			"trivy.tag":  "0.35.0",
			"trivy.slow": "true",
		},
		want: "--slow",
	},
		{
			name: "slow param set to false",
			configData: map[string]string{
				"trivy.tag":  "0.35.0",
				"trivy.slow": "false",
			},
			want: "",
		},
		{
			name: "slow param set to no valid value",
			configData: map[string]string{
				"trivy.tag":  "0.35.0",
				"trivy.slow": "false2",
			},
			want: "--slow",
		},
		{
			name: "slow param set to true and trivy tag is less then 0.35.0",
			configData: map[string]string{
				"trivy.slow": "true",
				"trivy.tag":  "0.33.0",
			},
			want: "",
		},

		{
			name: "slow param set to true and trivy tag is bigger then 0.35.0",
			configData: map[string]string{
				"trivy.slow": "true",
				"trivy.tag":  "0.36.0",
			},
			want: "--slow",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := trivy.Slow(trivy.Config{PluginConfig: trivyoperator.PluginConfig{Data: tc.configData}})
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestScanner(t *testing.T) {
	testCases := []struct {
		name       string
		configData trivyoperator.ConfigData
		want       string
	}{{

		name: "scanner with trivy tag lower then v0.37.0",
		configData: map[string]string{
			"trivy.tag": "0.36.0",
		},
		want: "--security-checks",
	},
		{
			name: "scanner with trivy tag equal then v0.37.0",
			configData: map[string]string{
				"trivy.tag": "0.37.0",
			},
			want: "--scanners",
		},
		{
			name: "scanner with trivy tag higher then v0.38.0",
			configData: map[string]string{
				"trivy.tag": "0.38.0",
			},
			want: "--scanners",
		},
		{
			name:       "scanner with no trivy tag lower",
			configData: make(map[string]string),
			want:       "--scanners",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := trivy.Scanners(trivy.Config{PluginConfig: trivyoperator.PluginConfig{Data: tc.configData}})
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSkipDBUpdate(t *testing.T) {
	testCases := []struct {
		name       string
		configData trivyoperator.ConfigData
		want       string
	}{{

		name: "skip update DB with trivy tag lower then v0.37.0",
		configData: map[string]string{
			"trivy.tag": "0.36.0",
		},
		want: "--skip-update",
	},
		{
			name: "skip update DB with trivy tag equal then v0.37.0",
			configData: map[string]string{
				"trivy.tag": "0.37.0",
			},
			want: "--skip-db-update",
		},
		{
			name: "skip update DB with trivy tag higher then v0.37.0",
			configData: map[string]string{
				"trivy.tag": "0.38.0",
			},
			want: "--skip-db-update",
		},
		{
			name:       "skip update DB with no trivy tag lower",
			configData: make(map[string]string),
			want:       "--skip-db-update",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := trivy.SkipDBUpdate(trivy.Config{PluginConfig: trivyoperator.PluginConfig{Data: tc.configData}})
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSkipJavaDBUpdate(t *testing.T) {
	testCases := []struct {
		name       string
		configData trivyoperator.ConfigData
		want       string
	}{
		{
			name: "skip update Java DB with trivy tag lower then v0.37.0",
			configData: map[string]string{
				"trivy.skipJavaDBUpdate": "true",
				"trivy.tag":              "0.36.0",
			},
			want: "",
		},
		{
			name: "skip update Java DB with trivy tag equal to v0.37.0",
			configData: map[string]string{
				"trivy.skipJavaDBUpdate": "true",
				"trivy.tag":              "0.37.0",
			},
			want: "--skip-java-db-update",
		},
		{
			name: "skip update Java DB with trivy tag higher then v0.37.0",
			configData: map[string]string{
				"trivy.skipJavaDBUpdate": "true",
				"trivy.tag":              "0.38.0",
			},
			want: "--skip-java-db-update",
		},
		{
			name: "skip update Java DB with no trivy tag",
			configData: map[string]string{
				"trivy.skipJavaDBUpdate": "true",
			},
			want: "--skip-java-db-update",
		},
		{
			name: "skip update Java DB with skip false",
			configData: map[string]string{
				"trivy.skipJavaDBUpdate": "false",
			},
			want: "",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := trivy.SkipJavaDBUpdate(trivy.Config{PluginConfig: trivyoperator.PluginConfig{Data: tc.configData}})
			assert.Equal(t, tc.want, got)
		})
	}
}
