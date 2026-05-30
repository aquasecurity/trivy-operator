package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/utils"
)

func TestEncodeBzip2Base64_RoundTripsThroughOperatorDecoder(t *testing.T) {
	payload := `{"SchemaVersion":2,"ArtifactName":"nginx:1.25","Results":[]}`
	var encoded bytes.Buffer

	if err := encodeBzip2Base64(&encoded, strings.NewReader(payload)); err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	for _, b := range encoded.Bytes() {
		if !isBase64Char(b) {
			t.Fatalf("encoded output contains non-base64 byte %q", b)
		}
	}

	dec, err := utils.ReadCompressData(io.NopCloser(bytes.NewReader(encoded.Bytes())))
	if err != nil {
		t.Fatalf("operator-side decode failed: %v", err)
	}
	defer dec.Close()
	got, err := io.ReadAll(dec)
	if err != nil {
		t.Fatalf("read decoded: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("round-trip mismatch:\n want=%q\n got =%q", payload, got)
	}
}

func TestEncodeBzip2Base64_EmptyInput(t *testing.T) {
	var encoded bytes.Buffer
	if err := encodeBzip2Base64(&encoded, strings.NewReader("")); err != nil {
		t.Fatalf("encode empty: %v", err)
	}
	dec, err := utils.ReadCompressData(io.NopCloser(bytes.NewReader(encoded.Bytes())))
	if err != nil {
		t.Fatalf("decode empty: %v", err)
	}
	defer dec.Close()
	got, _ := io.ReadAll(dec)
	if len(got) != 0 {
		t.Fatalf("empty round-trip produced %d bytes", len(got))
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
