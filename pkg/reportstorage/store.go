// Package reportstorage writes reports to alternate storage instead of Kubernetes CRDs.
package reportstorage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
)

// Store persists a report as a JSON document under a slash-separated key,
// for example "vulnerability_reports/default/ReplicaSet-nginx-6d9676f5c4-nginx.json".
type Store interface {
	Put(ctx context.Context, key string, report any, meta Meta) error

	// Stat returns found=false for a missing key and an error for anything else.
	Stat(ctx context.Context, key string) (meta Meta, found bool, err error)
}

// Meta describes a stored report.
type Meta struct {
	// SpecHash is the resource-spec-hash of the scanned workload.
	SpecHash string
	ModTime  time.Time
}

// Key returns the key of a report about obj. Namespaced objects get a
// namespace directory, and container is appended to the name when set:
// "<dir>/<namespace>/<Kind>-<name>[-<container>].json".
func Key(dir string, obj kube.ObjectRef, container string) string {
	name := fmt.Sprintf("%s-%s", obj.Kind, obj.Name)
	if container != "" {
		name += "-" + container
	}
	return path.Join(dir, obj.Namespace, name+".json")
}

// New returns the Store selected by the alternate report storage settings.
func New(ctx context.Context, config etc.Config) (Store, error) {
	switch config.AltReportStorageType {
	case "", etc.AltReportStorageFilesystem:
		if config.AltReportDir == "" {
			return nil, errors.New("alternate report storage directory must be set")
		}
		return NewFilesystem(config.AltReportDir), nil
	case etc.AltReportStorageS3:
		return NewS3(ctx, S3Options{
			Bucket:       config.AltReportS3Bucket,
			Prefix:       config.AltReportS3Prefix,
			Endpoint:     config.AltReportS3Endpoint,
			Region:       config.AltReportS3Region,
			UsePathStyle: config.AltReportS3UsePathStyle,
		})
	default:
		return nil, fmt.Errorf("unsupported alternate report storage type %q", config.AltReportStorageType)
	}
}

func encode(w io.Writer, report any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("failed to encode report: %w", err)
	}
	return nil
}
