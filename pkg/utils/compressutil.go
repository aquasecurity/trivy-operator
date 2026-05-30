package utils

import (
	"bufio"
	"compress/bzip2"
	"encoding/base64"
	"io"

	dsnetbzip2 "github.com/dsnet/compress/bzip2"
	"go.uber.org/multierr"
)

// WriteCompressData streams src through bzip2 compression and then
// base64 encoding to dst. The wire format is the inverse of what
// ReadCompressData accepts. The stdlib's compress/bzip2 only
// provides a Reader, so the encoder side uses
// github.com/dsnet/compress/bzip2.
func WriteCompressData(dst io.Writer, src io.Reader) (err error) {
	b64 := base64.NewEncoder(base64.StdEncoding, dst)
	defer multierr.AppendInvoke(&err, multierr.Close(b64))
	bz, err := dsnetbzip2.NewWriter(b64, &dsnetbzip2.WriterConfig{Level: dsnetbzip2.DefaultCompression})
	if err != nil {
		return err
	}
	defer multierr.AppendInvoke(&err, multierr.Close(bz))
	_, err = io.Copy(bz, src)
	return err
}

// ReadCompressData returns a reader that base64-decodes then bzip2-
// decompresses src on the fly. It is the streaming inverse of
// WriteCompressData and never materializes the full payload in
// memory. ASCII whitespace surrounding or interleaved in the base64
// payload (e.g. from kubectl log framing) is tolerated.
//
// The returned ReadCloser does not own src; callers retain
// responsibility for closing the source reader.
func ReadCompressData(src io.Reader) io.ReadCloser {
	// base64.NewDecoder reads in small (4–1024 byte) chunks; a bufio
	// layer amortizes that into one syscall per ~4 KiB of source.
	buffered := bufio.NewReader(src)
	b64 := base64.NewDecoder(base64.StdEncoding, skipWhitespaceReader{r: buffered})
	return io.NopCloser(bzip2.NewReader(b64))
}

// skipWhitespaceReader drops ASCII whitespace from the underlying
// stream so base64.NewDecoder — which only tolerates '\n' and '\r' —
// can also accept payloads padded with spaces or tabs.
type skipWhitespaceReader struct{ r io.Reader }

func (s skipWhitespaceReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	j := 0
	for i := 0; i < n; i++ {
		if c := p[i]; c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		p[j] = p[i]
		j++
	}
	return j, err
}
