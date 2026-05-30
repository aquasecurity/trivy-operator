package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// fakeTrivy writes a tiny shell script that emulates trivy: it
// recognises --output <path>, writes outputContent there, writes
// stderrContent to stderr, and exits with exitCode. Returned path is
// the script the caller passes as the trivy command.
func fakeTrivy(t *testing.T, outputContent, stderrContent string, exitCode int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fakeTrivy uses /bin/sh; skipping on windows")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "trivy")
	body := fmt.Sprintf(`#!/bin/sh
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [ -n "$out" ]; then
  printf '%%s' '%s' > "$out"
fi
if [ -n "%s" ]; then
  printf '%%s' '%s' >&2
fi
exit %d
`, outputContent, stderrContent, stderrContent, exitCode)
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake trivy: %v", err)
	}
	return script
}

func TestRun_NoSeparator_ReturnsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan-wrapper", "--compress"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit code, got 0")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("--")) {
		t.Fatalf("expected stderr to mention `--`, got: %q", stderr.String())
	}
}

func TestRun_MissingResult_ReturnsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan-wrapper", "--", "trivy", "image", "nginx"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit code, got 0")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("--result")) {
		t.Fatalf("expected stderr to mention `--result`, got: %q", stderr.String())
	}
}

func TestRun_PlainPath_EmitsReportToStdout(t *testing.T) {
	trivy := fakeTrivy(t, `{"hello":"world"}`, "", 0)
	resultPath := filepath.Join(t.TempDir(), "result.json")

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"scan-wrapper", "--result", resultPath, "--", trivy, "--output", resultPath},
		&stdout, &stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr: %s", code, stderr.String())
	}
	if got := stdout.String(); got != `{"hello":"world"}` {
		t.Fatalf("expected report on stdout, got %q", got)
	}
}

func TestRun_TrivyFails_EmitsStderrAndPropagatesExitCode(t *testing.T) {
	trivy := fakeTrivy(t, "", "boom: scan failed", 1)
	resultPath := filepath.Join(t.TempDir(), "result.json")

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"scan-wrapper", "--result", resultPath, "--", trivy, "--output", resultPath},
		&stdout, &stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if !bytes.Contains(stdout.Bytes(), []byte("boom: scan failed")) {
		t.Fatalf("expected stdout to contain captured stderr, got %q", stdout.String())
	}
}

func TestRun_TrivyNotFound_ReturnsExecError(t *testing.T) {
	resultPath := filepath.Join(t.TempDir(), "result.json")
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"scan-wrapper", "--result", resultPath, "--", "/nonexistent/trivy", "--output", resultPath},
		&stdout, &stderr,
	)
	if code == 0 {
		t.Fatalf("expected non-zero exit, got 0")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("failed to invoke trivy")) {
		t.Fatalf("expected stderr to mention invoke failure, got: %q", stderr.String())
	}
}

func TestRun_SuccessButResultMissing_ReturnsError(t *testing.T) {
	// trivy "succeeds" but doesn't write the file.
	trivy := fakeTrivy(t, "", "", 0)
	resultPath := filepath.Join(t.TempDir(), "missing.json")
	// Pass --output to a different path so trivy doesn't create resultPath.
	wrongPath := filepath.Join(t.TempDir(), "elsewhere.json")

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"scan-wrapper", "--result", resultPath, "--", trivy, "--output", wrongPath},
		&stdout, &stderr,
	)
	if code == 0 {
		t.Fatalf("expected non-zero exit when result file is missing, got 0")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("result file missing")) {
		t.Fatalf("expected stderr to mention missing result, got: %q", stderr.String())
	}
}
