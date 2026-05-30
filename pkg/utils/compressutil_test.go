package utils

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
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

			dec, err := ReadCompressData(io.NopCloser(bytes.NewReader(encoded.Bytes())))
			require.NoError(t, err)
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

func TestBase64Decode(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "decode basic data", data: base64.StdEncoding.EncodeToString([]byte("text for decode")), want: "text for decode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := base64Decode(strings.NewReader(tt.data))
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestDecompressBzip2(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		hasError bool
		want     string
	}{
		{name: "decompress basic data", data: mustDecodeHex(t, "425a68393141592653594eece83600000251800010400006449080200031064c4101a7a9a580bb9431f8bb9229c28482776741b0"), want: "hello world\n", hasError: false},
		{name: "decompress basic bad data", data: mustDecodeHex(t, "425a68393141592653594eece83600000251800010400ds06449080200031064c4101a7a9a580bb9431f8bb9229c28482776741b0"), hasError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decompressBzip2(tt.data)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				b, err := io.ReadAll(got)
				require.NoError(t, err)
				assert.Equal(t, tt.want, string(b))
			}
		})
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		assert.Error(t, err)
	}
	return b
}

func TestIllegalChar(t *testing.T) {
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
			b, err := base64Decode(f)
			require.NoError(t, err)
			_, err = decompressBzip2(b)
			require.NoError(t, err)
		})
	}
}
