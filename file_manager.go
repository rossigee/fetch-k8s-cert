package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// FileManager handles certificate file operations
type FileManager struct {
	config  Config
	logger  *logrus.Logger
	metrics *Metrics
}

// NewFileManager creates a new file manager
func NewFileManager(config Config, logger *logrus.Logger, metrics *Metrics) *FileManager {
	return &FileManager{config: config, logger: logger, metrics: metrics}
}

// UpdateCertificateFiles updates the local certificate files if they have changed
func (fm *FileManager) UpdateCertificateFiles(ctx context.Context, tlsBundle *TLSBundle) (bool, error) {
	// Note: We removed global obs, so tracing is disabled for now
	var span trace.Span

	certPermissions := os.FileMode(0600) // owner-readable
	keyPermissions := os.FileMode(0600)  // owner-readable

	// Update CA file
	caChanged, err := fm.updateFileIfDifferent(fm.config.LocalCAFile, tlsBundle.CAData, certPermissions, "ca")
	if err != nil {
		if fm.logger != nil {
			fm.logger.WithError(err).Error("Unable to update local CA file")
		}
		if span != nil {
			span.RecordError(err)
		}
		return false, fmt.Errorf("unable to update local CA file: %w", err)
	}

	// Update certificate file
	certChanged, err := fm.updateFileIfDifferent(fm.config.LocalCertFile, tlsBundle.CertData, certPermissions, "cert")
	if err != nil {
		if fm.logger != nil {
			fm.logger.WithError(err).Error("Unable to update local cert file")
		}
		if span != nil {
			span.RecordError(err)
		}
		return false, fmt.Errorf("unable to update local cert file: %w", err)
	}

	// Update key file
	keyChanged, err := fm.updateFileIfDifferent(fm.config.LocalKeyFile, tlsBundle.KeyData, keyPermissions, "key")
	if err != nil {
		if fm.logger != nil {
			fm.logger.WithError(err).Error("Unable to update local key file")
		}
		if span != nil {
			span.RecordError(err)
		}
		return false, fmt.Errorf("unable to update local key file: %w", err)
	}

	anyChanged := caChanged || certChanged || keyChanged

	if span != nil {
		span.SetAttributes(
			attribute.Bool("ca_changed", caChanged),
			attribute.Bool("cert_changed", certChanged),
			attribute.Bool("key_changed", keyChanged),
			attribute.Bool("any_changed", anyChanged),
		)
	}

	if fm.logger != nil {
		fm.logger.WithFields(map[string]interface{}{
			"ca_changed":   caChanged,
			"cert_changed": certChanged,
			"key_changed":  keyChanged,
			"any_changed":  anyChanged,
		}).Info("Certificate file update completed")
	}

	return anyChanged, nil
}

// updateFileIfDifferent updates a file only if its content is different
func (fm *FileManager) updateFileIfDifferent(filePath string, data []byte, permissions os.FileMode, fileType string) (bool, error) {
	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		if fm.metrics != nil {
			fm.metrics.RecordFileWriteError(fileType, "directory_creation")
		}
		return false, fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Read the current content of the file
	// #nosec G304
	currentData, err := readFile(filePath)
	if err != nil && os.IsNotExist(err) {
		// Handle case where local file doesn't exist
		if fm.logger != nil {
			fm.logger.WithField("file", filePath).Info("Local file doesn't exist, creating new file")
		}

		err = fm.writeToFile(data, filePath, permissions, fileType)
		if err != nil {
			if fm.logger != nil {
				fm.logger.WithError(err).WithField("file", filePath).Error("Error writing new file")
			}
			return false, err
		}

		if fm.metrics != nil {
			fm.metrics.RecordFileWrite(fileType, "created")
		}
		return true, nil
	} else if err != nil {
		// Handle other error reading local file
		if fm.logger != nil {
			fm.logger.WithError(err).WithField("file", filePath).Error("Error reading local file")
		}
		if fm.metrics != nil {
			fm.metrics.RecordFileWriteError(fileType, "read_error")
		}
		return false, fmt.Errorf("error reading local file %s: %w", filePath, err)
	}

	// Compare the current content with the new data
	if bytesEqual(currentData, data) {
		if fm.metrics != nil {
			fm.metrics.RecordFileWrite(fileType, "unchanged")
		}
		return false, nil // Content matches, no need to update
	}

	// Update the file with the new data
	err = fm.writeToFile(data, filePath, permissions, fileType)
	if err != nil {
		return false, err
	}

	if fm.metrics != nil {
		fm.metrics.RecordFileWrite(fileType, "updated")
	}

	if fm.logger != nil {
		fm.logger.WithFields(map[string]interface{}{
			"file":       filePath,
			"type":       fileType,
			"size_bytes": len(data),
		}).Info("File updated with new content")
	}

	return true, nil // Updated the file
}

// writeToFile writes data to a file with specified permissions
func (fm *FileManager) writeToFile(data []byte, filePath string, permissions os.FileMode, fileType string) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, permissions) // #nosec G304
	if err != nil {
		if fm.metrics != nil {
			fm.metrics.RecordFileWriteError(fileType, "open_failed")
		}
		return fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer func() { _ = file.Close() }()

	_, err = file.Write(data)
	if err != nil {
		if fm.metrics != nil {
			fm.metrics.RecordFileWriteError(fileType, "write_failed")
		}
		return fmt.Errorf("failed to write to file %s: %w", filePath, err)
	}

	return nil
}

// TriggerReload executes the reload command if specified
func (fm *FileManager) TriggerReload(ctx context.Context) error {
	if fm.config.ReloadCommand == "" {
		if fm.logger != nil {
			fm.logger.Info("No reload command specified, skipping reload")
		}
		return nil
	}

	// Note: We removed global obs, so tracing is disabled for now
	var span trace.Span

	start := time.Now()

	if fm.logger != nil {
		fm.logger.WithField("command", fm.config.ReloadCommand).Info("Certificate files updated, triggering reload")
	}

	reloadCmd := exec.CommandContext(ctx, "sh", "-c", fm.config.ReloadCommand) // #nosec G204
	reloadCmd.Stdout = os.Stdout
	reloadCmd.Stderr = os.Stderr

	if err := reloadCmd.Run(); err != nil {
		duration := time.Since(start)

		if fm.metrics != nil {
			fm.metrics.RecordReloadAttempt("failed")
			fm.metrics.RecordReloadError("command_failed")
		}

		if fm.logger != nil {
			fm.logger.WithError(err).WithFields(map[string]interface{}{
				"command":  fm.config.ReloadCommand,
				"duration": duration,
			}).Error("Error executing reload command")
		}

		if span != nil {
			span.RecordError(err)
			span.SetAttributes(
				attribute.Bool("success", false),
				attribute.Float64("duration_seconds", duration.Seconds()),
			)
		}

		return fmt.Errorf("error triggering reload command: %w", err)
	}

	duration := time.Since(start)

	if fm.metrics != nil {
		fm.metrics.RecordReloadAttempt("success")
	}

	if fm.logger != nil {
		fm.logger.WithFields(map[string]interface{}{
			"command":  fm.config.ReloadCommand,
			"duration": duration,
		}).Info("Reload command executed successfully")
	}

	if span != nil {
		span.SetAttributes(
			attribute.Bool("success", true),
			attribute.Float64("duration_seconds", duration.Seconds()),
		)
	}

	return nil
}

// bytesEqual compares two byte slices for equality
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
