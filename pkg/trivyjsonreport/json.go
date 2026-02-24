package trivyjsonreport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// ExtractJSON extracts valid JSON from raw log data.
// The raw logs may contain non-JSON content (timestamps, log prefixes, etc.)
// before the actual JSON output from Trivy.
func ExtractJSON(data []byte) ([]byte, error) {
	// Trim any leading/trailing whitespace
	data = bytes.TrimSpace(data)

	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	// Find the start of JSON - look for '{' or '['
	jsonStart := -1
	for i, b := range data {
		if b == '{' || b == '[' {
			jsonStart = i
			break
		}
	}

	if jsonStart == -1 {
		return nil, errors.New("no JSON object or array found in data")
	}

	// Extract from the JSON start to the end
	jsonData := data[jsonStart:]

	// Find the matching end bracket
	startChar := jsonData[0]
	var endChar byte
	if startChar == '{' {
		endChar = '}'
	} else {
		endChar = ']'
	}

	// Find the last occurrence of the end character
	var jsonEnd int
	for i := len(jsonData) - 1; i >= 0; i-- {
		if jsonData[i] == endChar {
			jsonEnd = i + 1
			break
		}
	}

	if jsonEnd == 0 {
		return nil, errors.New("no matching end bracket found for JSON")
	}

	jsonData = jsonData[:jsonEnd]

	// Validate the JSON by unmarshaling into a generic interface
	var obj any
	if err := json.Unmarshal(jsonData, &obj); err != nil {
		// Try to find valid JSON by trimming trailing garbage
		for i := len(jsonData) - 1; i > 0; i-- {
			if jsonData[i] == endChar {
				testData := jsonData[:i+1]
				if err := json.Unmarshal(testData, &obj); err == nil {
					jsonData = testData
					break
				}
			}
		}
		// Final validation
		if err := json.Unmarshal(jsonData, &obj); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
	}

	return jsonData, nil
}
