package trivyjsonreport

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractJSON_EmptyData(t *testing.T) {
	_, err := ExtractJSON([]byte{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")

	_, err = ExtractJSON([]byte("   \n\t  "))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestExtractJSON_NoJSON(t *testing.T) {
	_, err := ExtractJSON([]byte("no json here"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no JSON object or array")

	_, err = ExtractJSON([]byte("2024-01-01T00:00:00Z some log line"))
	require.Error(t, err)
}

func TestExtractJSON_ValidObject(t *testing.T) {
	payload := []byte(`{"key":"value","nested":{"a":1}}`)
	out, err := ExtractJSON(payload)
	require.NoError(t, err)
	assert.Equal(t, payload, out)
	// Verify it's valid JSON
	var m map[string]any
	err = json.Unmarshal(out, &m)
	require.NoError(t, err)
	assert.Equal(t, "value", m["key"])
}

func TestExtractJSON_ValidObjectWithPrefix(t *testing.T) {
	logLine := []byte("2024-01-01T00:00:00Z INFO  \n  {\"artifact\":\"nginx:latest\",\"results\":[]}")
	out, err := ExtractJSON(logLine)
	require.NoError(t, err)
	var m map[string]any
	err = json.Unmarshal(out, &m)
	require.NoError(t, err)
	assert.Equal(t, "nginx:latest", m["artifact"])
}

func TestExtractJSON_ValidArray(t *testing.T) {
	payload := []byte(`[1,2,3]`)
	out, err := ExtractJSON(payload)
	require.NoError(t, err)
	assert.Equal(t, payload, out)
	var s []int
	err = json.Unmarshal(out, &s)
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2, 3}, s)
}

func TestExtractJSON_ObjectWithTrailingGarbage(t *testing.T) {
	// Trivy might emit extra text after the JSON
	data := []byte(`{"done":true} trailing log line`)
	out, err := ExtractJSON(data)
	require.NoError(t, err)
	var m map[string]any
	err = json.Unmarshal(out, &m)
	require.NoError(t, err)
	assert.Equal(t, true, m["done"])
}

func TestExtractJSON_NoMatchingEndBracket(t *testing.T) {
	data := []byte(`{"unclosed":true`)
	_, err := ExtractJSON(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no matching end bracket")
}

func TestExtractJSON_InvalidJSON(t *testing.T) {
	data := []byte(`{invalid}`)
	_, err := ExtractJSON(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON")
}
