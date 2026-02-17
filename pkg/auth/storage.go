package auth

import (
	"os"
	"path/filepath"
	"runtime"
)

// ConfigDir returns the ovrse configuration directory path.
// Uses XDG_CONFIG_HOME on Linux/macOS, AppData on Windows.
func ConfigDir() string {
	var baseDir string

	switch runtime.GOOS {
	case "windows":
		baseDir = os.Getenv("APPDATA")
		if baseDir == "" {
			baseDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
		}
	default: // Linux, macOS, etc.
		baseDir = os.Getenv("XDG_CONFIG_HOME")
		if baseDir == "" {
			baseDir = filepath.Join(os.Getenv("HOME"), ".config")
		}
	}

	return filepath.Join(baseDir, "ovrse")
}

// CredentialsDir returns the path to store credentials.
func CredentialsDir() string {
	return filepath.Join(ConfigDir(), "credentials")
}

// DataDir returns the ovrse data directory path.
// Uses XDG_DATA_HOME on Linux/macOS, LocalAppData on Windows.
func DataDir() string {
	var baseDir string

	switch runtime.GOOS {
	case "windows":
		baseDir = os.Getenv("LOCALAPPDATA")
		if baseDir == "" {
			baseDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local")
		}
	default: // Linux, macOS, etc.
		baseDir = os.Getenv("XDG_DATA_HOME")
		if baseDir == "" {
			baseDir = filepath.Join(os.Getenv("HOME"), ".local", "share")
		}
	}

	return filepath.Join(baseDir, "ovrse")
}

// DatabasePath returns the path to the SQLite database file.
// Note: This matches store.DefaultDBPath() - both use XDG_DATA_HOME (~/.local/share/ovrse/).
func DatabasePath() string {
	return filepath.Join(DataDir(), "overseer.db")
}

// CacheDir returns the ovrse cache directory path.
func CacheDir() string {
	var baseDir string

	switch runtime.GOOS {
	case "windows":
		baseDir = os.Getenv("LOCALAPPDATA")
		if baseDir == "" {
			baseDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local")
		}
		baseDir = filepath.Join(baseDir, "Cache")
	default:
		baseDir = os.Getenv("XDG_CACHE_HOME")
		if baseDir == "" {
			baseDir = filepath.Join(os.Getenv("HOME"), ".cache")
		}
	}

	return filepath.Join(baseDir, "ovrse")
}

// EnsureDirectories creates all necessary directories.
func EnsureDirectories() error {
	dirs := []string{
		ConfigDir(),
		CredentialsDir(),
		DataDir(),
		CacheDir(),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	return nil
}

// DefaultCredentials loads or creates the default keypair.
func DefaultCredentials() (*Keypair, error) {
	if err := EnsureDirectories(); err != nil {
		return nil, err
	}
	return LoadOrCreate(CredentialsDir())
}
