package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/utils"
)

// Env-var contract between stubFakeTrivy (parent) and TestHelperProcess
// (child re-exec). Both sides must agree on these names — they cross a
// process boundary.
const (
	envHelperMarker  = "GO_WANT_HELPER_PROCESS"
	envFakeStdoutKey = "FAKE_TRIVY_STDOUT"
	envFakeStderrKey = "FAKE_TRIVY_STDERR"
	envFakeExitKey   = "FAKE_TRIVY_EXIT"
)

func stubFakeTrivy(t *testing.T, stdoutContent, stderrContent string, exitCode int) {
	t.Helper()
	orig := execCommand
	t.Cleanup(func() { execCommand = orig })
	execCommand = func(name string, args ...string) *exec.Cmd {
		passthrough := slices.Concat([]string{"-test.run=TestHelperProcess", "--", name}, args)
		cmd := exec.Command(os.Args[0], passthrough...)
		cmd.Env = append(os.Environ(),
			envHelperMarker+"=1",
			envFakeStdoutKey+"="+stdoutContent,
			envFakeStderrKey+"="+stderrContent,
			envFakeExitKey+"="+strconv.Itoa(exitCode),
		)
		return cmd
	}
}

// TestHelperProcess is not a real test — it's the re-exec target for
// stubFakeTrivy. The early return makes it a no-op in normal `go test`
// runs; the helper-process flow only fires when GO_WANT_HELPER_PROCESS
// is set on the child. Pattern borrowed from os/exec's own tests.
func TestHelperProcess(t *testing.T) {
	if os.Getenv(envHelperMarker) != "1" {
		return
	}
	args := os.Args
	if i := slices.Index(args, "--"); i >= 0 {
		args = args[i+1:]
	}
	if i := slices.Index(args, "--output"); i >= 0 && i+1 < len(args) {
		if v := os.Getenv(envFakeStdoutKey); v != "" {
			if err := os.WriteFile(args[i+1], []byte(v), 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "fake-trivy: write output: %v\n", err)
				os.Exit(2)
			}
		}
	}
	if errMsg := os.Getenv(envFakeStderrKey); errMsg != "" {
		fmt.Fprint(os.Stderr, errMsg)
	}
	code, err := strconv.Atoi(os.Getenv(envFakeExitKey))
	if err != nil {
		fmt.Fprintf(os.Stderr, "fake-trivy: invalid %s: %v\n", envFakeExitKey, err)
		os.Exit(2)
	}
	os.Exit(code)
}

func TestRun_NoTrivyCommand_ReturnsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan-wrapper", "--compress", "--result", "/tmp/x"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit code, got 0")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("no trivy command")) {
		t.Fatalf("expected stderr to mention missing trivy command, got: %q", stderr.String())
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
	stubFakeTrivy(t, `{"hello":"world"}`, "", 0)
	resultPath := filepath.Join(t.TempDir(), "result.json")

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"scan-wrapper", "--result", resultPath, "--", "trivy", "--output", resultPath},
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
	stubFakeTrivy(t, "", "boom: scan failed", 1)
	resultPath := filepath.Join(t.TempDir(), "result.json")

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"scan-wrapper", "--result", resultPath, "--", "trivy", "--output", resultPath},
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
	// Intentionally NOT stubbed: we want the real exec.Command to
	// fail with "no such file or directory" so the wrapper takes
	// its "failed to invoke trivy" path.
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

func TestRun_CompressPath_RoundTrip(t *testing.T) {
	payload := `{"SchemaVersion":2,"Results":[]}`
	stubFakeTrivy(t, payload, "", 0)
	resultPath := filepath.Join(t.TempDir(), "result.json")

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"scan-wrapper", "--compress", "--result", resultPath, "--", "trivy", "--output", resultPath},
		&stdout, &stderr,
	)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr: %s", code, stderr.String())
	}
	dec := utils.ReadCompressData(bytes.NewReader(stdout.Bytes()))
	defer dec.Close()
	got, _ := io.ReadAll(dec)
	if string(got) != payload {
		t.Fatalf("round-trip mismatch:\n want=%q\n got =%q", payload, got)
	}
}

func TestRun_SuccessButResultMissing_ReturnsError(t *testing.T) {
	stubFakeTrivy(t, "", "", 0)
	resultPath := filepath.Join(t.TempDir(), "missing.json")
	// trivy is told to write to a different path, so resultPath
	// never gets created — wrapper's open must fail.
	wrongPath := filepath.Join(t.TempDir(), "elsewhere.json")

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"scan-wrapper", "--result", resultPath, "--", "trivy", "--output", wrongPath},
		&stdout, &stderr,
	)
	if code == 0 {
		t.Fatalf("expected non-zero exit when result file is missing, got 0")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("result file missing")) {
		t.Fatalf("expected stderr to mention missing result, got: %q", stderr.String())
	}
}
