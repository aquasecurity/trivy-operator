package utils

import (
	"compress/bzip2"
	"encoding/base64"
	"io"
)

//DecompressBzip2ToReader accept bzip2 compressed reader and decompress it and return reader
func DecompressBzip2ToReader(compressedReader io.Reader) (io.Reader, error) {
	bz2Reader := bzip2.NewReader(compressedReader)
	pr, pw := io.Pipe()
	go func() {
		_, err := io.Copy(pw, bz2Reader)
		if err != nil {
			pw.CloseWithError(err)
		} else {
			pw.Close()
		}
	}()
	return pr, nil
}

// Base64DecodeToReader accept encoded reader , decode it and return reader
func Base64DecodeToReader(EncodedReader io.Reader) io.Reader {
	pr, pw := io.Pipe()
	decoder := base64.NewDecoder(base64.StdEncoding, EncodedReader)
	go func() {
		_, err := io.Copy(pw, decoder)
		if err != nil {
			pw.CloseWithError(err)
		} else {
			pw.Close()
		}
	}()
	return pr
}
