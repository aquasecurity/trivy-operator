package utils

import (
	"encoding/json"
	"fmt"
	"os"
)

// StreamReportToFile writes a report directly to file using streaming JSON encoding
// This reduces memory usage by avoiding intermediate marshaling to byte arrays
func StreamReportToFile(report any, filePath string, perm os.FileMode, pretty bool) error {
	// remove existing file to refresh the inode
	err := os.Remove(filePath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false) // do not escape HTML for readability
	if pretty {
		encoder.SetIndent("", "  ") // Pretty print for readability
	}
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("failed to encode report: %w", err)
	}
	if err := os.Chmod(filePath, perm); err != nil {
		return fmt.Errorf("failed to set permissions on report: %w", err)
	}

	return nil
}
