// Command scan-wrapper executes trivy inside a scan Job container and
// post-processes its output, so the scan image itself does not need
// /bin/sh, cat, bzip2, or base64. The trivy-operator ships this
// binary inside its own image and mounts it into the (potentially
// distroless) scan container via an emptyDir + initContainer.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/aquasecurity/trivy-operator/pkg/utils"
)

const stderrCaptureLimit = 1 << 20

// 127 follows POSIX "command not found" so operators can distinguish
// a missing trivy binary from a scan that ran and failed.
const (
	exitInternal  = 1
	exitUsage     = 2
	exitExecError = 127
)

// execCommand is the os/exec seam stubFakeTrivy swaps in tests; the
// real binary always uses exec.Command.
var execCommand = exec.Command

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

type options struct {
	compress   bool
	resultPath string
	trivyArgs  []string
}

// parseArgs splits scan-wrapper's own flags from the trailing trivy
// command. flag.Parse stops at the first non-flag token *or* at a `--`
// separator, so the operator can invoke us either way.
func parseArgs(args []string, errOut io.Writer) (options, error) {
	var opts options
	fs := flag.NewFlagSet("scan-wrapper", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.BoolVar(&opts.compress, "compress", false, "bzip2+base64 encode the result on stdout")
	fs.StringVar(&opts.resultPath, "result", "", "path to the file trivy writes its report to (required)")
	if err := fs.Parse(args[1:]); err != nil {
		return opts, err
	}
	if opts.resultPath == "" {
		return opts, errors.New("--result is required")
	}
	opts.trivyArgs = fs.Args()
	if len(opts.trivyArgs) == 0 {
		return opts, errors.New("no trivy command provided")
	}
	return opts, nil
}

// cappedBuffer buffers up to limit bytes then silently drops the rest.
// Write returns len(p) even when bytes are dropped so the producer
// (os/exec's stderr copier) doesn't see io.ErrShortWrite and abort.
type cappedBuffer struct {
	buf   []byte
	limit int
}

var _ io.Writer = (*cappedBuffer)(nil)

func newCappedBuffer(limit int) *cappedBuffer {
	return &cappedBuffer{limit: limit}
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if remaining := b.limit - len(b.buf); remaining > 0 {
		b.buf = append(b.buf, p[:min(len(p), remaining)]...)
	}
	return len(p), nil
}

func (b *cappedBuffer) Bytes() []byte { return b.buf }

func run(args []string, stdout, stderr io.Writer) int {
	opts, err := parseArgs(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "scan-wrapper: %v\n", err)
		return exitUsage
	}

	cmd := execCommand(opts.trivyArgs[0], opts.trivyArgs[1:]...)
	cmd.Stdout = io.Discard
	stderrBuf := newCappedBuffer(stderrCaptureLimit)
	cmd.Stderr = stderrBuf

	runErr := cmd.Run()
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			fmt.Fprintf(stderr, "scan-wrapper: failed to invoke trivy: %v\n", runErr)
			return exitExecError
		}
		// Surface captured stderr on stdout so pod logs show why trivy failed.
		_, _ = stdout.Write(stderrBuf.Bytes())
		return exitErr.ExitCode()
	}

	f, err := os.Open(opts.resultPath)
	if err != nil {
		fmt.Fprintf(stderr, "scan-wrapper: result file missing after successful scan: %v\n", err)
		return exitInternal
	}
	defer f.Close()
	if opts.compress {
		if err := utils.WriteCompressData(stdout, f); err != nil {
			fmt.Fprintf(stderr, "scan-wrapper: encode result: %v\n", err)
			return exitInternal
		}
		return 0
	}
	if _, err := io.Copy(stdout, f); err != nil {
		fmt.Fprintf(stderr, "scan-wrapper: copy result to stdout: %v\n", err)
		return exitInternal
	}
	return 0
}
