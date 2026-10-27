package licensr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// CachedOfflineToken is the last-known-good offline token for one license.
// It holds no claims on purpose: anything on disk can be edited, so read
// the claims by verifying Token again (VerifyOptions.JWKS = JWKS).
type CachedOfflineToken struct {
	Token string `json:"token"`
	// The key set from FetchJWKS, so the token verifies with no network.
	JWKS json.RawMessage `json:"jwks"`
	// When this entry was cached.
	CachedAt time.Time `json:"cached_at"`
}

// TokenStore persists the last-known-good offline token per license, so an
// app can boot fully offline (no network at all) before its first
// successful Token call in a given session. Bring your own implementation
// for hosts with their own storage (an OS keychain, an app's config file) —
// Licensr only needs something implementing this interface.
type TokenStore interface {
	// Get returns nil, nil when nothing is cached for licenseKey.
	Get(licenseKey string) (*CachedOfflineToken, error)
	Set(licenseKey string, entry CachedOfflineToken) error
	Clear(licenseKey string) error
}

// MemoryTokenStore is a TokenStore that does not persist across process
// restarts. Safe for concurrent use.
type MemoryTokenStore struct {
	mu      sync.Mutex
	entries map[string]CachedOfflineToken
}

func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{entries: map[string]CachedOfflineToken{}}
}

func (s *MemoryTokenStore) Get(licenseKey string) (*CachedOfflineToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[licenseKey]
	if !ok {
		return nil, nil
	}
	return &entry, nil
}

func (s *MemoryTokenStore) Set(licenseKey string, entry CachedOfflineToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[licenseKey] = entry
	return nil
}

func (s *MemoryTokenStore) Clear(licenseKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, licenseKey)
	return nil
}

// FileTokenStore is a TokenStore with one JSON file per license key, under
// a per-plugin directory in the platform's app-data location (the same one
// the C++ SDK uses; the .json extension keeps it apart from C++'s .token files):
//
//	macOS:   ~/Library/Application Support/Licensr/<pluginSlug>/
//	Windows: %APPDATA%\Licensr\<pluginSlug>\
//	Linux:   $XDG_DATA_HOME/licensr/<pluginSlug>/ (falls back to ~/.local/share/licensr/<pluginSlug>/)
type FileTokenStore struct {
	dir string
}

// NewFileTokenStore stores tokens under baseDir/pluginSlug, or under the
// platform default above when baseDir is empty. The directory is created
// on the first Set.
func NewFileTokenStore(pluginSlug, baseDir string) *FileTokenStore {
	if baseDir == "" {
		baseDir = defaultAppDataRoot()
	}
	return &FileTokenStore{dir: filepath.Join(baseDir, pluginSlug)}
}

// Dir is the resolved directory tokens are written under.
func (s *FileTokenStore) Dir() string { return s.dir }

func (s *FileTokenStore) Get(licenseKey string) (*CachedOfflineToken, error) {
	data, err := os.ReadFile(s.pathFor(licenseKey))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entry CachedOfflineToken
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func (s *FileTokenStore) Set(licenseKey string, entry CachedOfflineToken) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	// Write then rename, so a crash mid-write never leaves a torn token
	// behind. The token is signed, not secret, but there's no reason to
	// leave it world-readable either (CreateTemp uses 0600).
	tmp, err := os.CreateTemp(s.dir, "*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.pathFor(licenseKey))
}

func (s *FileTokenStore) Clear(licenseKey string) error {
	err := os.Remove(s.pathFor(licenseKey))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// pathFor hashes licenseKey: it is caller-controlled and shouldn't be used
// as a raw path component — hashing sidesteps path separators, reserved
// filenames, and length limits in one step.
func (s *FileTokenStore) pathFor(licenseKey string) string {
	return filepath.Join(s.dir, sha256Hex(licenseKey)+".json")
}

func defaultAppDataRoot() string {
	switch runtime.GOOS {
	case "windows":
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "Licensr")
		}
		return "Licensr" // Unlikely: APPDATA is unset. Falls back to the working directory.
	case "darwin", "ios":
		if home := os.Getenv("HOME"); home != "" {
			return filepath.Join(home, "Library", "Application Support", "Licensr")
		}
		return "Licensr"
	default:
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			return filepath.Join(xdg, "licensr")
		}
		if home := os.Getenv("HOME"); home != "" {
			return filepath.Join(home, ".local", "share", "licensr")
		}
		return "licensr"
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
