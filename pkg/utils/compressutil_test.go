package utils

import (
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
			assert.NoError(t, err)
			assert.Equal(t, string(got), tt.want)
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
				assert.NoError(t, err)
				assert.Equal(t, string(b), tt.want)
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
			assert.NoError(t, err)
			defer f.Close()
			b, err := base64Decode(f)
			assert.NoError(t, err)
			_, err = decompressBzip2(b)
			assert.NoError(t, err)
		})
	}
}
