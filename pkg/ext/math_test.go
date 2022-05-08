package ext

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMinInt(t *testing.T) {
	testCases := []struct {
		a      int
		b      int
		result int
	}{
		{
			a:      2,
			b:      3,
			result: 2,
		},
		{
			a:      5,
			b:      4,
			result: 4,
		},
		{
			a:      4,
			b:      4,
			result: 4,
		},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("(%d, %d): %d", tc.a, tc.b, tc.result), func(t *testing.T) {
			assert.Equal(t, tc.result, MinInt(tc.a, tc.b))
		})
	}
}
