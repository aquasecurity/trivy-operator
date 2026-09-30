package reportstorage_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-operator/pkg/reportstorage"
)

func TestFilesystemStore_Put(t *testing.T) {
	dir := t.TempDir()
	store := reportstorage.NewFilesystem(dir)
	path := filepath.Join(dir, "vulnerability_reports", "ReplicaSet-nginx-nginx.json")

	long := map[string]string{"name": "nginx", "padding": "a long value that the next report does not have"}
	require.NoError(t, store.Put(context.Background(), "vulnerability_reports/ReplicaSet-nginx-nginx.json", long, reportstorage.Meta{}))

	short := map[string]string{"name": "nginx"}
	require.NoError(t, store.Put(context.Background(), "vulnerability_reports/ReplicaSet-nginx-nginx.json", short, reportstorage.Meta{}))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	var got map[string]string
	require.NoError(t, json.Unmarshal(content, &got), "overwrite must truncate the previous report")
	assert.Equal(t, short, got)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestFilesystemStore_PutUnencodableReport(t *testing.T) {
	store := reportstorage.NewFilesystem(t.TempDir())

	err := store.Put(context.Background(), "report.json", map[string]any{"invalid": make(chan int)}, reportstorage.Meta{})

	require.ErrorContains(t, err, "failed to encode report")
}

func TestFilesystemStore_Stat(t *testing.T) {
	store := reportstorage.NewFilesystem(t.TempDir())
	labeled := map[string]any{"metadata": map[string]any{"labels": map[string]string{"resource-spec-hash": "abc123"}}}
	require.NoError(t, store.Put(context.Background(), "vulnerability_reports/report.json", labeled, reportstorage.Meta{}))
	require.NoError(t, store.Put(context.Background(), "secret_reports/report.json", []any{labeled}, reportstorage.Meta{}))

	for _, key := range []string{"vulnerability_reports/report.json", "secret_reports/report.json"} {
		meta, found, err := store.Stat(context.Background(), key)
		require.NoError(t, err, key)
		assert.True(t, found, key)
		assert.Equal(t, "abc123", meta.SpecHash, key)
		assert.WithinDuration(t, time.Now(), meta.ModTime, time.Minute, key)
	}

	_, found, err := store.Stat(context.Background(), "vulnerability_reports/missing.json")
	require.NoError(t, err)
	assert.False(t, found)
}
