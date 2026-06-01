package utils

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteCompressData_RoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{name: "json report", payload: `{"SchemaVersion":2,"ArtifactName":"nginx:1.25","Results":[]}`},
		{name: "empty", payload: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var encoded bytes.Buffer
			require.NoError(t, WriteCompressData(&encoded, strings.NewReader(tc.payload)))

			for _, b := range encoded.Bytes() {
				assert.True(t, isBase64Char(b), "non-base64 byte %q in encoded output", b)
			}

			dec := ReadCompressData(bytes.NewReader(encoded.Bytes()))
			defer dec.Close()
			got, err := io.ReadAll(dec)
			require.NoError(t, err)
			assert.Equal(t, tc.payload, string(got))
		})
	}
}

func isBase64Char(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z',
		b >= 'a' && b <= 'z',
		b >= '0' && b <= '9',
		b == '+', b == '/', b == '=', b == '\n':
		return true
	}
	return false
}

func TestReadCompressData_TolerantOfWhitespace(t *testing.T) {
	tests := []struct {
		name     string
		dataPath string
	}{
		{name: "base64 illegal char before", dataPath: "illegal_char_before.txt"},
		{name: "base64 illegal char after", dataPath: "illegal_char_after.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open("./testdata/fixture/" + tt.dataPath)
			require.NoError(t, err)
			defer f.Close()
			dec := ReadCompressData(f)
			defer dec.Close()
			_, err = io.ReadAll(dec)
			require.NoError(t, err)
		})
	}
}
