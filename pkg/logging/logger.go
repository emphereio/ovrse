// Package logging provides zerolog-based structured logging for OVRSE.
package logging

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// Config holds logger configuration.
type Config struct {
	Level    string    // debug, info, warn, error
	Format   string    // text, json
	Output   io.Writer // defaults to os.Stderr
	FilePath string    // optional: also write to file
}

// Logger is the global logger instance.
var Logger zerolog.Logger

// initialized tracks whether Init has been called.
var initialized bool

// DefaultCLIConfig returns default config for CLI mode.
func DefaultCLIConfig() Config {
	return Config{
		Level:  "warn",
		Format: "text",
		Output: os.Stderr,
	}
}

// DefaultMCPConfig returns default config for MCP mode.
// MCP uses stdio for protocol, so logs must go to stderr as JSON.
func DefaultMCPConfig() Config {
	return Config{
		Level:  "info",
		Format: "json",
		Output: os.Stderr,
	}
}

// Init initializes the global logger with the given config.
func Init(cfg Config) error {
	// Parse level
	level, err := zerolog.ParseLevel(strings.ToLower(cfg.Level))
	if err != nil {
		level = zerolog.WarnLevel
	}

	// Configure output
	var output io.Writer = cfg.Output
	if output == nil {
		output = os.Stderr
	}

	// Add file output if specified
	if cfg.FilePath != "" {
		file, err := os.OpenFile(cfg.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		output = io.MultiWriter(output, file)
	}

	// Configure format
	if cfg.Format == "text" {
		output = zerolog.ConsoleWriter{
			Out:        output,
			TimeFormat: time.RFC3339,
			NoColor:    false,
		}
	}

	Logger = zerolog.New(output).
		Level(level).
		With().
		Timestamp().
		Logger()

	initialized = true
	return nil
}

// Initialized returns true if the logger has been initialized.
func Initialized() bool {
	return initialized
}

// WithComponent returns a child logger with component field.
func WithComponent(component string) zerolog.Logger {
	return Logger.With().Str("component", component).Logger()
}

// Debug logs a debug message. Convenience wrapper.
func Debug() *zerolog.Event {
	return Logger.Debug()
}

// Info logs an info message. Convenience wrapper.
func Info() *zerolog.Event {
	return Logger.Info()
}

// Warn logs a warning message. Convenience wrapper.
func Warn() *zerolog.Event {
	return Logger.Warn()
}

// Error logs an error message. Convenience wrapper.
func Error() *zerolog.Event {
	return Logger.Error()
}
