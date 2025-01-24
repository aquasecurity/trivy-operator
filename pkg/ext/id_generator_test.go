package ext_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-operator/pkg/ext"
)

func TestGoogleUUIDGenerator_GenerateID(t *testing.T) {
	t.Run("Should return unique identifiers", func(t *testing.T) {
		N := 100 // If you don't trust the uniqueness, bump up this number :-)

		generator := ext.NewGoogleUUIDGenerator()
		identifiers := make(map[string]bool)

		for i := 0; i < N; i++ {
			identifiers[generator.GenerateID()] = true
		}
		assert.Len(t, identifiers, N)
	})
}

func TestSimpleIDGenerator_GenerateID(t *testing.T) {
	generator := ext.NewSimpleIDGenerator()
	for i := 1; i < 5; i++ {
		id := generator.GenerateID()
		assert.Equal(t, fmt.Sprintf("00000000-0000-0000-0000-00000000000%d", i), id)
	}
}
