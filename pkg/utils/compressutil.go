package utils

import (
	"bufio"
	"encoding/base64"
	"io"

	"github.com/klauspost/compress/zstd"
	"go.uber.org/multierr"
)

// WriteCompressData streams src through zstd compression and then
// base64 encoding to dst. The wire format is the inverse of what
// ReadCompressData accepts.
func WriteCompressData(dst io.Writer, src io.Reader) (err error) {
	b64 := base64.NewEncoder(base64.StdEncoding, dst)
	defer multierr.AppendInvoke(&err, multierr.Close(b64))
	z, err := zstd.NewWriter(b64)
	if err != nil {
		return err
	}
	defer multierr.AppendInvoke(&err, multierr.Close(z))
	_, err = io.Copy(z, src)
	return err
}

// ReadCompressData returns a reader that base64-decodes then zstd-
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
	// zstd.NewReader only errors on bad options; with none passed it
	// cannot fail.
	z, _ := zstd.NewReader(b64)
	return z.IOReadCloser()
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
