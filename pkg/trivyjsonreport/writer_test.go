package trivyjsonreport

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriter_WriteReport_EmptyBaseDir(t *testing.T) {
	w := NewWriter("")
	_, err := w.WriteReport("ns", "Deployment", "app", "c", "img:tag", "container_image", []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage directory not configured")
}

func TestWriter_WriteReport_Success(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)
	rawJSON := []byte(`{"SchemaVersion":2,"ArtifactName":"nginx:latest"}`)

	meta, err := w.WriteReport("default", "Deployment", "nginx", "app", "nginx:latest", "container_image", rawJSON)
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Equal(t, "nginx:latest", meta.ArtifactName)
	assert.Equal(t, "container_image", meta.ArtifactType)
	assert.Equal(t, "default", meta.Namespace)
	assert.Equal(t, "Deployment", meta.WorkloadKind)
	assert.Equal(t, "nginx", meta.WorkloadName)
	assert.Equal(t, "app", meta.ContainerName)
	assert.False(t, meta.Delivered)
	assert.Contains(t, meta.ReportFile, "namespaced")
	assert.Contains(t, meta.ReportFile, "Deployment-nginx-app.json")

	reportPath := filepath.Join(dir, "namespaced", "default", "Deployment-nginx-app.json")
	content, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	assert.JSONEq(t, string(rawJSON), string(content))

	// Metadata file exists and is valid
	metaPath := filepath.Join(dir, "namespaced", "default", "Deployment-nginx-app.metadata.json")
	_, err = os.Stat(metaPath)
	require.NoError(t, err)
	readMeta, err := w.ReadMetadata(metaPath)
	require.NoError(t, err)
	assert.Equal(t, meta.ArtifactName, readMeta.ArtifactName)
}

func TestWriter_WriteClusterReport_EmptyBaseDir(t *testing.T) {
	w := NewWriter("")
	_, err := w.WriteClusterReport("Deployment", "app", "c", "img:tag", "container_image", []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage directory not configured")
}

func TestWriter_WriteClusterReport_Success(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)
	rawJSON := []byte(`{"SchemaVersion":2}`)

	meta, err := w.WriteClusterReport("Deployment", "global", "app", "img:tag", "container_image", rawJSON)
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Empty(t, meta.Namespace)
	assert.Equal(t, "global", meta.WorkloadName)

	reportPath := filepath.Join(dir, "cluster", "Deployment-global-app.json")
	content, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	assert.JSONEq(t, string(rawJSON), string(content))
}

func TestWriter_UpdateMetadata(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)
	meta, err := w.WriteReport("default", "Deployment", "x", "c", "img", "container_image", []byte(`{}`))
	require.NoError(t, err)

	meta.Delivered = true
	now := time.Now().UTC()
	meta.DeliveredAt = &now
	meta.DeliveryAttempts = 1
	meta.LastDeliveryError = ""

	err = w.UpdateMetadata(meta)
	require.NoError(t, err)

	metadataPath := meta.ReportFile[:len(meta.ReportFile)-5] + ".metadata.json"
	readMeta, err := w.ReadMetadata(metadataPath)
	require.NoError(t, err)
	assert.True(t, readMeta.Delivered)
	assert.NotNil(t, readMeta.DeliveredAt)
	assert.Equal(t, 1, readMeta.DeliveryAttempts)
}

func TestGetMetadataFilePath(t *testing.T) {
	assert.Equal(t, "/path/to/report.metadata.json", GetMetadataFilePath("/path/to/report.json"))
	assert.Equal(t, "foo.metadata.json", GetMetadataFilePath("foo.json"))
	assert.Equal(t, "foo.metadata.json", GetMetadataFilePath("foo")) // no .json suffix -> append
}

func TestWriter_WriteReport_RejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)
	raw := []byte(`{}`)

	_, err := w.WriteReport("ns/../etc", "Deployment", "app", "c", "img", "container_image", raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "namespace")

	_, err = w.WriteReport("default", "Deployment", "app/../other", "c", "img", "container_image", raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workloadName")

	_, err = w.WriteReport("default", "Deployment", "app", "c\\..\\x", "img", "container_image", raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "containerName")
}

func TestWriter_WriteClusterReport_RejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)
	raw := []byte(`{}`)

	_, err := w.WriteClusterReport("Deployment", "..", "c", "img", "container_image", raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workloadName")
}

func TestWriter_UpdateMetadata_InvalidReportFile(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)
	meta := &ReportMetadata{ReportFile: "not-a-json-path", ArtifactName: "img"}

	err := w.UpdateMetadata(meta)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must end with .json")
}
