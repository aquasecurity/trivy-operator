package testdb

import (
	"archive/tar"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/samber/lo"

	fixtures "github.com/aquasecurity/bolt-fixtures"
	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	jdb "github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/db"
)

// initTestingDB creates a Trivy DB in a temporary cache directory using bolt fixtures (same approach as Trivy's internal tests).
// It returns the created cache directory path.
func initTestingDB(_ ginkgo.GinkgoTInterface, fixtureFiles []string) string {
	// Create a temp dir
	cacheDir, err := os.MkdirTemp("", "trivy-db-cache-")
	gomega.Expect(err).ToNot(gomega.HaveOccurred())

	dbDir := db.Dir(cacheDir)
	dbPath := trivydb.Path(dbDir)
	err = os.MkdirAll(dbDir, 0o700)
	gomega.Expect(err).ToNot(gomega.HaveOccurred())

	// Load testdata into BoltDB
	loader, err := fixtures.New(dbPath, fixtureFiles)
	gomega.Expect(err).ToNot(gomega.HaveOccurred())
	gomega.Expect(loader.Load()).To(gomega.Succeed())
	gomega.Expect(loader.Close()).To(gomega.Succeed())

	// Initialize DB (writes metadata files, etc.)
	gomega.Expect(db.Init(dbDir)).To(gomega.Succeed())

	return cacheDir
}

// initTestingJavaDB initializes a minimal Java DB in the cache directory. This allows us to set skip-java-db-update=true
// without needing an external repository.
func initTestingJavaDB(_ ginkgo.GinkgoTInterface, cacheDir string) {
	dbDir := filepath.Join(cacheDir, "java-db")
	javaDB, err := jdb.New(dbDir)
	gomega.Expect(err).ToNot(gomega.HaveOccurred())
	err = javaDB.Init()
	gomega.Expect(err).ToNot(gomega.HaveOccurred())

	meta := jdb.Metadata{
		Version:    jdb.SchemaVersion,
		NextUpdate: time.Now().Add(24 * time.Hour),
		UpdatedAt:  time.Now(),
	}
	metac := jdb.NewMetadata(dbDir)
	err = metac.Update(meta)
	gomega.Expect(err).ToNot(gomega.HaveOccurred())
}

// archiveDir tars the given directory without compression and returns a path to the tar file.
func archiveDir(_ ginkgo.GinkgoTInterface, dir string) string {
	tmpDBPath := filepath.Join(lo.Must(os.MkdirTemp("", "trivy-db-")), "db.tar")
	f, err := os.Create(tmpDBPath)
	gomega.Expect(err).ToNot(gomega.HaveOccurred())
	defer f.Close()

	tr := tar.NewWriter(f)
	defer tr.Close()

	err = tr.AddFS(os.DirFS(dir))
	gomega.Expect(err).ToNot(gomega.HaveOccurred())

	return tmpDBPath
}

// buildDBImage constructs an OCI image with a single layer containing the DB tarball.
// The layer is annotated with the expected title and media type that Trivy looks for.
func buildDBImage(_ ginkgo.GinkgoTInterface, dbTarPath string) v1.Image {
	// Create a layer from the DB tar; set Trivy DB layer media type
	layer, err := tarball.LayerFromFile(dbTarPath, tarball.WithMediaType(types.MediaType("application/vnd.aquasec.trivy.db.layer.v1.tar+gzip")))
	gomega.Expect(err).ToNot(gomega.HaveOccurred())

	// Start from empty image and append our single layer with annotations
	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer:       layer,
		Annotations: map[string]string{"org.opencontainers.image.title": "db.tar.gz"},
	})
	gomega.Expect(err).ToNot(gomega.HaveOccurred())
	return img
}

type Registry struct {
	URL     string // host:port
	srv     *http.Server
	cleanup func()
}

// StartRegistry starts an in-memory insecure local OCI registry bound to 127.0.0.1 on a random port.
func StartRegistry(_ ginkgo.GinkgoTInterface) *Registry {
	handler := registry.New()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	gomega.Expect(err).ToNot(gomega.HaveOccurred())

	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(l) }()

	return &Registry{
		URL: l.Addr().String(),
		srv: srv,
		cleanup: func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		},
	}
}

// Cleanup stops the registry server.
func (r *Registry) Cleanup() {
	if r != nil && r.cleanup != nil {
		r.cleanup()
	}
}

// PushDBImage pushes the provided DB image to the given registry under repository "trivy-db" with the schema tag.
// Returns the full reference (including the :<schema> tag) to be used as trivy.dbRepository.
func PushDBImage(ctx context.Context, _ ginkgo.GinkgoTInterface, reg *Registry, img v1.Image) string {
	// Compose ref like 127.0.0.1:port/trivy-db:<schema>
	tag := fmt.Sprintf("%s/trivy-db:%d", reg.URL, trivydb.SchemaVersion)
	ref, err := name.NewTag(tag, name.Insecure)
	gomega.Expect(err).ToNot(gomega.HaveOccurred())

	// Push the image to our insecure registry
	err = remote.Write(ref, img, remote.WithContext(ctx))
	gomega.Expect(err).ToNot(gomega.HaveOccurred())

	return ref.String()
}

// PrepareDeterministicDB starts a local registry, generates a deterministic Trivy DB from the provided fixtures,
// pushes it and returns the registry handle and the dbRepository reference to be configured in the plugin.
func PrepareDeterministicDB(t ginkgo.GinkgoTInterface, fixtureFiles []string) (*Registry, string) {
	// 1) init trivy DB and Java DB (Java DB optional; we will skip updating it in scans)
	cacheDir := initTestingDB(t, fixtureFiles)
	initTestingJavaDB(t, cacheDir)

	// 2) tar the DB directory
	dbDir := db.Dir(cacheDir)
	tarPath := archiveDir(t, dbDir)

	// 3) build OCI image with correct media type and annotations
	img := buildDBImage(t, tarPath)

	// 4) start local registry and push
	reg := StartRegistry(t)
	repo := PushDBImage(context.Background(), t, reg, img)

	return reg, repo
}

// BuildDBImageFromFixtures builds an OCI image containing a deterministic Trivy DB created from the provided fixtures.
// It does not start any registry or push the image.
func BuildDBImageFromFixtures(t ginkgo.GinkgoTInterface, fixtureFiles []string) v1.Image {
	cacheDir := initTestingDB(t, fixtureFiles)
	initTestingJavaDB(t, cacheDir)
	dbDir := db.Dir(cacheDir)
	tarPath := archiveDir(t, dbDir)
	return buildDBImage(t, tarPath)
}
