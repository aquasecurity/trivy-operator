package ext_test

import (
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/stretchr/testify/assert"
)

func TestGoogleUUIDGenerator_GenerateID(t *testing.T) {
	t.Run("Should return unique identifiers", func(t *testing.T) {
		N := 100 // If you don't trust the uniqueness, bump up this number :-)

		generator := ext.NewGoogleUUIDGenerator()
		identifiers := make(map[string]bool)

		for i := 0; i < N; i++ {
			identifiers[generator.GenerateID()] = true
		}
		assert.Equal(t, N, len(identifiers))
	})
}

func TestSimpleIDGenerator_GenerateID(t *testing.T) {
	generator := ext.NewSimpleIDGenerator()
	assert.Equal(t, "00000000-0000-0000-0000-000000000001", generator.GenerateID())
	assert.Equal(t, "00000000-0000-0000-0000-000000000002", generator.GenerateID())
	assert.Equal(t, "00000000-0000-0000-0000-000000000003", generator.GenerateID())
	assert.Equal(t, "00000000-0000-0000-0000-000000000004", generator.GenerateID())
	assert.Equal(t, "00000000-0000-0000-0000-000000000005", generator.GenerateID())
}
