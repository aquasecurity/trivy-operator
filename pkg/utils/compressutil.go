package utils

import (
	"bytes"
	"compress/bzip2"
	"encoding/base64"
	"io"

	dsnetbzip2 "github.com/dsnet/compress/bzip2"
)

// WriteCompressData streams src through bzip2 compression and then
// base64 encoding to dst. The wire format is the inverse of what
// ReadCompressData accepts, so callers can pair the two safely.
// The stdlib's compress/bzip2 only provides a Reader, so the
// encoder side uses github.com/dsnet/compress/bzip2.
func WriteCompressData(dst io.Writer, src io.Reader) error {
	b64 := base64.NewEncoder(base64.StdEncoding, dst)
	bz, err := dsnetbzip2.NewWriter(b64, &dsnetbzip2.WriterConfig{Level: dsnetbzip2.DefaultCompression})
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

// decompressBzip2 accept bzip2 compressed bytes and decompress it
// #nosec
func decompressBzip2(compressedBytes []byte) (io.Reader, error) {
	bz2Reader := bzip2.NewReader(bytes.NewReader(compressedBytes))
	uncompressedWriter := new(bytes.Buffer)
	_, err := io.Copy(uncompressedWriter, bz2Reader)
	if err != nil {
		return nil, err
	}
	return uncompressedWriter, nil
}

// base64Decode accept encoded reader and base64 decode it
func base64Decode(encodedReader io.Reader) ([]byte, error) {
	encodedBytes, err := io.ReadAll(encodedReader)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(string(bytes.TrimSpace(encodedBytes)))
}

func ReadCompressData(encodedReader io.ReadCloser) (io.ReadCloser, error) {
	// base64 decode logs
	compressedLogsBytes, err := base64Decode(encodedReader)
	if err != nil {
		return nil, err
	}
	// bzip2 decompress logs
	unCompressedLogsReader, err := decompressBzip2(compressedLogsBytes)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(unCompressedLogsReader), nil
}
