package shared_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/shared"
)

func TestStringToSeverity(t *testing.T) {
	testCases := []struct {
		name             string
		expectedSeverity shared.Severity
		expectedError    string
	}{
		{
			name:          "xxx",
			expectedError: "unrecognized name literal: xxx",
		},
		{
			name:             "CRITICAL",
			expectedSeverity: shared.SeverityCritical,
		},
		{
			name:             "HIGH",
			expectedSeverity: shared.SeverityHigh,
		},
		{
			name:             "MEDIUM",
			expectedSeverity: shared.SeverityMedium,
		},
		{
			name:             "LOW",
			expectedSeverity: shared.SeverityLow,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			severity, err := shared.StringToSeverity(tc.name)
			if tc.expectedError != "" {
				assert.EqualError(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedSeverity, severity)
			}
		})
	}

}
