package reportstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
)

type filesystemStore struct {
	dir string
}

// NewFilesystem returns a Store that writes reports as files under dir.
// The spec hash is not stored separately. Stat reads it from the report labels.
func NewFilesystem(dir string) Store {
	return &filesystemStore{dir: dir}
}

func (s *filesystemStore) Put(_ context.Context, key string, report any, _ Meta) error {
	path := filepath.Join(s.dir, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("failed to make directory %s: %w", filepath.Dir(path), err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}
	if err := encode(file, report); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close file %s: %w", path, err)
	}
	return nil
}

func (s *filesystemStore) Stat(_ context.Context, key string) (Meta, bool, error) {
	path := filepath.Join(s.dir, filepath.FromSlash(key))
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Meta{}, false, nil
	}
	if err != nil {
		return Meta{}, false, fmt.Errorf("failed to stat report %s: %w", path, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Meta{}, false, fmt.Errorf("failed to read report %s: %w", path, err)
	}
	specHash, err := specHashLabel(data)
	if err != nil {
		return Meta{}, false, fmt.Errorf("failed to decode report %s: %w", path, err)
	}
	return Meta{SpecHash: specHash, ModTime: info.ModTime()}, true, nil
}

// specHashLabel reads the spec hash label of a report. Some keys hold a list
// of reports, one per container, and then the first report is used.
func specHashLabel(data []byte) (string, error) {
	type labeled struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}

	var report labeled
	if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 && trimmed[0] == '[' {
		var reports []labeled
		if err := json.Unmarshal(trimmed, &reports); err != nil {
			return "", err
		}
		if len(reports) == 0 {
			return "", nil
		}
		report = reports[0]
	} else if err := json.Unmarshal(data, &report); err != nil {
		return "", err
	}
	return report.Metadata.Labels[trivyoperator.LabelResourceSpecHash], nil
}
