package trivyjsonreport

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleanupService_Start_NoBaseDir(t *testing.T) {
	log := logr.Discard()
	svc := NewCleanupService(log, "", time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		svc.Start(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancel")
	}
}

func TestCleanupService_CleanupRemovesOldFiles(t *testing.T) {
	dir := t.TempDir()
	log := logr.Discard()

	// Create a report file with old mtime
	reportPath := filepath.Join(dir, "namespaced", "default", "Deployment-app-c.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(reportPath), 0o750))
	require.NoError(t, os.WriteFile(reportPath, []byte(`{}`), 0o600))
	// Set mtime to 2 hours ago
	past := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(reportPath, past, past))

	// Create a recent file (should not be removed)
	recentPath := filepath.Join(dir, "namespaced", "default", "Deployment-app2-c.json")
	require.NoError(t, os.WriteFile(recentPath, []byte(`{}`), 0o600))

	svc := NewCleanupService(log, dir, 1*time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		svc.Start(ctx)
		close(done)
	}()
	// Allow first cleanup to run
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	_, err := os.Stat(reportPath)
	require.True(t, os.IsNotExist(err), "old report file should be removed")

	_, err = os.Stat(recentPath)
	require.NoError(t, err, "recent file should remain")
}

func TestCleanupService_TTLZero_NoCleanup(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.json")
	require.NoError(t, os.WriteFile(reportPath, []byte(`{}`), 0o600))
	past := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(reportPath, past, past))

	log := logr.Discard()
	svc := NewCleanupService(log, dir, 0) // TTL 0 means cleanup() returns early
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		svc.Start(ctx)
		close(done)
	}()
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done

	_, err := os.Stat(reportPath)
	require.NoError(t, err, "with TTL 0, file should not be removed")
}

func TestNewCleanupService(t *testing.T) {
	log := logr.Discard()
	svc := NewCleanupService(log, "/tmp/reports", 24*time.Hour)
	assert.Equal(t, "/tmp/reports", svc.BaseDir)
	assert.Equal(t, 24*time.Hour, svc.TTL)
}
