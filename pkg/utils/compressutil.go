package utils

import (
	"bytes"
	"compress/bzip2"
	"encoding/base64"
	"io"
	"io/ioutil"
)

//DecompressBzip2 accept bzip2 compressed bytes and decompress it
//#nosec
func DecompressBzip2(compressedBytes []byte) (io.Reader, error) {
	bz2Reader := bzip2.NewReader(bytes.NewReader(compressedBytes))
	uncompressedWriter := new(bytes.Buffer)
	_, err := io.Copy(uncompressedWriter, bz2Reader)
	if err != nil {
		return nil, err
	}
	return uncompressedWriter, nil
}

// Base64Decode accept encoded reader and base64 decode it
func Base64Decode(EncodedReader io.Reader) ([]byte, error) {
	EncodedBytes, err := ioutil.ReadAll(EncodedReader)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(string(EncodedBytes))
}
