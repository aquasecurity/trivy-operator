package main

import (
	"encoding/base64"
	"io"

	"github.com/dsnet/compress/bzip2"
)

// encodeBzip2Base64 streams src through bzip2 compression and then
// base64 encoding, writing the result to dst. The wire format
// matches what pkg/utils.ReadCompressData expects to decode.
func encodeBzip2Base64(dst io.Writer, src io.Reader) error {
	b64 := base64.NewEncoder(base64.StdEncoding, dst)
	bz, err := bzip2.NewWriter(b64, &bzip2.WriterConfig{Level: bzip2.DefaultCompression})
	if err != nil {
		_ = b64.Close()
		return err
	}
	if _, err := io.Copy(bz, src); err != nil {
		_ = bz.Close()
		_ = b64.Close()
		return err
	}
	if err := bz.Close(); err != nil {
		_ = b64.Close()
		return err
	}
	return b64.Close()
}
