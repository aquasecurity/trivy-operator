package reportstorage_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-operator/pkg/reportstorage"
)

var lastModified = time.Date(2026, 9, 29, 21, 0, 0, 0, time.UTC)

type storedObject struct {
	header http.Header
	body   []byte
}

// fakeS3 serves one bucket in path style. It keeps uploaded objects in memory
// and answers 403 for keys listed in forbidden, like S3 without s3:ListBucket.
type fakeS3 struct {
	bucket    string
	forbidden map[string]bool

	mu      sync.Mutex
	objects map[string]storedObject
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if r.URL.Path == "/"+f.bucket {
		if r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/"+f.bucket+"/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/"+f.bucket+"/")

	switch r.Method {
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		f.objects[key] = storedObject{header: r.Header.Clone(), body: body}
	case http.MethodHead:
		object, ok := f.objects[key]
		switch {
		case f.forbidden[key]:
			w.WriteHeader(http.StatusForbidden)
		case !ok:
			w.WriteHeader(http.StatusNotFound)
		default:
			for name, values := range object.header {
				if strings.HasPrefix(strings.ToLower(name), "x-amz-meta-") {
					w.Header()[name] = values
				}
			}
			w.Header().Set("Last-Modified", lastModified.Format(http.TimeFormat))
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func newS3Store(t *testing.T, prefix string, forbidden ...string) (reportstorage.Store, *fakeS3) {
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")

	fake := &fakeS3{bucket: "reports", forbidden: make(map[string]bool), objects: make(map[string]storedObject)}
	for _, key := range forbidden {
		fake.forbidden[key] = true
	}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)

	store, err := reportstorage.NewS3(context.Background(), reportstorage.S3Options{
		Bucket:       "reports",
		Prefix:       prefix,
		Endpoint:     server.URL,
		UsePathStyle: true,
	})
	require.NoError(t, err)
	return store, fake
}

func TestS3Store_PutAndStat(t *testing.T) {
	store, fake := newS3Store(t, "cluster-a")
	key := "vulnerability_reports/default/ReplicaSet-nginx-nginx.json"
	report := map[string]string{"name": "nginx"}

	require.NoError(t, store.Put(context.Background(), key, report, reportstorage.Meta{SpecHash: "abc123"}))

	object, ok := fake.objects["cluster-a/"+key]
	require.True(t, ok, "object is stored under the prefix")
	assert.Equal(t, "application/json", object.header.Get("Content-Type"))
	assert.Equal(t, "abc123", object.header.Get("X-Amz-Meta-Spec-Hash"))
	var got map[string]string
	require.NoError(t, json.Unmarshal(object.body, &got))
	assert.Equal(t, report, got)

	meta, found, err := store.Stat(context.Background(), key)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "abc123", meta.SpecHash)
	assert.True(t, lastModified.Equal(meta.ModTime), "ModTime comes from Last-Modified, got %s", meta.ModTime)
}

func TestS3Store_Stat(t *testing.T) {
	store, _ := newS3Store(t, "", "forbidden.json")

	_, found, err := store.Stat(context.Background(), "missing.json")
	require.NoError(t, err)
	assert.False(t, found)

	_, _, err = store.Stat(context.Background(), "forbidden.json")
	require.Error(t, err, "403 must not read as a missing report")
}

func TestNewS3_FailsWhenBucketIsUnreachable(t *testing.T) {
	_, fake := newS3Store(t, "")
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)

	_, err := reportstorage.NewS3(context.Background(), reportstorage.S3Options{
		Bucket:       "missing",
		Endpoint:     server.URL,
		UsePathStyle: true,
	})

	require.ErrorContains(t, err, `failed to access S3 bucket "missing"`)
}
