package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
	if testing.Short() {
		t.Skip("Run this test manually")
	}

	c, _ := NewClient("http://aqua.domain", Authorization{
		Basic: &UsernameAndPassword{"administrator", "Password12345"}})

	t.Run("Should list registries", func(t *testing.T) {
		registries, err := c.Registries().List()
		require.NoError(t, err)
		for _, registry := range registries {
			t.Logf("registry: %+v", registry)
		}
	})

	t.Run("Should get vulnerabilities from Ad Hoc Scans registry", func(t *testing.T) {
		resp, err := c.Images().Vulnerabilities("Ad Hoc Scans", "core.harbor.domain/library/nginx", "1.17")
		require.NoError(t, err)
		for _, vulnerability := range resp.Results {
			t.Logf("vulnerability: %+v", vulnerability)
		}
	})

	t.Run("Should return error when vulnerabilities report cannot be found", func(t *testing.T) {
		_, err := c.Images().Vulnerabilities("Ad Hoc Scans", "core.harbor.domain/library/nginx", "unknown")
		assert.EqualError(t, err, ErrNotFound.Error())
	})

	t.Run("Should get vulnerabilities from Harbor registry", func(t *testing.T) {
		vr, err := c.Images().Vulnerabilities("Harbor", "library/nginx", "1.16")
		require.NoError(t, err)
		for _, vulnerability := range vr.Results {
			t.Logf("vulnerability: %+v", vulnerability)
		}
	})

}
