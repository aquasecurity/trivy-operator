package v1alpha1_test

import (
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/stretchr/testify/assert"
)

func TestStringToSeverity(t *testing.T) {
	testCases := []struct {
		name             string
		expectedSeverity v1alpha1.Severity
		expectedError    string
	}{
		{
			name:          "xxx",
			expectedError: "unrecognized name literal: xxx",
		},
		{
			name:             "CRITICAL",
			expectedSeverity: v1alpha1.SeverityCritical,
		},
		{
			name:             "HIGH",
			expectedSeverity: v1alpha1.SeverityHigh,
		},
		{
			name:             "MEDIUM",
			expectedSeverity: v1alpha1.SeverityMedium,
		},
		{
			name:             "LOW",
			expectedSeverity: v1alpha1.SeverityLow,
		},
		{
			name:             "danger",
			expectedSeverity: v1alpha1.SeverityCritical,
		},
		{
			name:             "warning",
			expectedSeverity: v1alpha1.SeverityLow,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			severity, err := v1alpha1.StringToSeverity(tc.name)
			if tc.expectedError != "" {
				assert.EqualError(t, err, tc.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedSeverity, severity)
			}
		})
	}

}
