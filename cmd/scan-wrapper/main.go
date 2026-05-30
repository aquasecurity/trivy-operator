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
)

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

type options struct {
	compress   bool
	resultPath string
	trivyArgs  []string
}

// parseArgs splits args around a literal `--` separator, parses the
// scan-wrapper flags on the left, and returns the trivy command and
// its args on the right.
func parseArgs(args []string) (options, error) {
	var opts options
	fs := flag.NewFlagSet("scan-wrapper", flag.ContinueOnError)
	fs.BoolVar(&opts.compress, "compress", false, "bzip2+base64 encode the result on stdout")
	fs.StringVar(&opts.resultPath, "result", "", "path to the file trivy writes its report to (required)")

	var beforeSep, afterSep []string
	sepFound := false
	for _, a := range args[1:] {
		if !sepFound && a == "--" {
			sepFound = true
			continue
		}
		if sepFound {
			afterSep = append(afterSep, a)
		} else {
			beforeSep = append(beforeSep, a)
		}
	}
	if !sepFound {
		return opts, errors.New("missing `--` separator between scan-wrapper flags and trivy command")
	}
	if err := fs.Parse(beforeSep); err != nil {
		return opts, err
	}
	if len(afterSep) == 0 {
		return opts, errors.New("no trivy command provided after `--`")
	}
	if opts.resultPath == "" {
		return opts, errors.New("--result is required")
	}
	opts.trivyArgs = afterSep
	return opts, nil
}

// cappedBuffer is an io.Writer that buffers up to cap bytes then
// silently drops further writes. Used to bound memory for trivy's
// stderr chatter so a chatty failure cannot exhaust the wrapper.
type cappedBuffer struct {
	buf []byte
	cap int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	remaining := b.cap - len(b.buf)
	if remaining <= 0 {
		return len(p), nil
	}
	if len(p) > remaining {
		b.buf = append(b.buf, p[:remaining]...)
	} else {
		b.buf = append(b.buf, p...)
	}
	return len(p), nil
}

func (b *cappedBuffer) Bytes() []byte { return b.buf }

func run(args []string, stdout, stderr io.Writer) int {
	opts, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "scan-wrapper: %v\n", err)
		return 2
	}

	cmd := exec.Command(opts.trivyArgs[0], opts.trivyArgs[1:]...)
	cmd.Stdout = io.Discard
	stderrBuf := &cappedBuffer{cap: 1 << 20}
	cmd.Stderr = stderrBuf

	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			fmt.Fprintf(stderr, "scan-wrapper: failed to invoke trivy: %v\n", runErr)
			return 127
		}
	}

	if exitCode != 0 {
		// Diagnostic path: dump captured stderr to our stdout so the
		// operator/user reading pod logs sees what went wrong.
		_, _ = stdout.Write(stderrBuf.Bytes())
		return exitCode
	}

	// Success path: emit the report file to stdout.
	f, err := os.Open(opts.resultPath)
	if err != nil {
		fmt.Fprintf(stderr, "scan-wrapper: result file missing after successful scan: %v\n", err)
		return 1
	}
	defer f.Close()
	if _, err := io.Copy(stdout, f); err != nil {
		fmt.Fprintf(stderr, "scan-wrapper: copy result to stdout: %v\n", err)
		return 1
	}
	return 0
}
