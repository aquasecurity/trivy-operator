package trivyjsonreport

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/go-logr/logr"
)

// CleanupService handles TTL-based cleanup of old TrivyJSON reports
type CleanupService struct {
	BaseDir string
	TTL     time.Duration
	Logger  logr.Logger
}

// NewCleanupService creates a new CleanupService
func NewCleanupService(logger logr.Logger, baseDir string, ttl time.Duration) *CleanupService {
	return &CleanupService{
		BaseDir: baseDir,
		TTL:     ttl,
		Logger:  logger,
	}
}

// Start begins periodic cleanup of old reports
func (c *CleanupService) Start(ctx context.Context) {
	if c.BaseDir == "" {
		c.Logger.Info("TrivyJSON cleanup service not started: no storage directory configured")
		return
	}

	c.Logger.Info("Starting TrivyJSON cleanup service",
		"baseDir", c.BaseDir,
		"ttl", c.TTL.String())

	// Run cleanup immediately on start
	c.cleanup()

	// Then run periodically
	// TODO: inotify
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.Logger.Info("Stopping TrivyJSON cleanup service")
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

// cleanup removes reports older than TTL
func (c *CleanupService) cleanup() {
	if c.TTL <= 0 {
		return
	}

	cutoff := time.Now().Add(-c.TTL)
	removedCount := 0

	err := filepath.Walk(c.BaseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if info.IsDir() {
			return nil
		}

		// Only process .json files (both reports and metadata)
		if filepath.Ext(path) != ".json" {
			return nil
		}

		if info.ModTime().Before(cutoff) {
			c.Logger.V(1).Info("Removing old TrivyJSON file", "path", path, "age", time.Since(info.ModTime()))
			if err := os.Remove(path); err != nil {
				c.Logger.Error(err, "Failed to remove old file", "path", path)
			} else {
				removedCount++
			}
		}

		return nil
	})

	if err != nil {
		c.Logger.Error(err, "Error walking directory for cleanup")
	}

	if removedCount > 0 {
		c.Logger.Info("TrivyJSON cleanup completed", "removedFiles", removedCount)
	}

	// Clean up empty directories
	c.cleanupEmptyDirs()
}

// cleanupEmptyDirs removes empty directories
func (c *CleanupService) cleanupEmptyDirs() {
	// Walk in reverse order to handle nested empty dirs
	var dirs []string

	if err := filepath.Walk(c.BaseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() || path == c.BaseDir {
			return nil
		}
		dirs = append(dirs, path)
		return nil
	}); err != nil {
		c.Logger.Error(err, "Error walking directory for empty dir cleanup")
		return
	}

	// Remove empty directories (reverse order for nested)
	for i := len(dirs) - 1; i >= 0; i-- {
		entries, err := os.ReadDir(dirs[i])
		if err == nil && len(entries) == 0 {
			if removeErr := os.Remove(dirs[i]); removeErr != nil {
				c.Logger.V(1).Info("Failed to remove empty directory", "path", dirs[i], "error", removeErr)
			}
		}
	}
}
