package licensr

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func sampleEntry(token string) CachedOfflineToken {
	return CachedOfflineToken{
		Token:    token,
		JWKS:     json.RawMessage(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"kid-1","x":"abc"}]}`),
		CachedAt: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// Every TokenStore must behave the same way, so both implementations run
// the same checks.
func testTokenStore(t *testing.T, store TokenStore) {
	t.Run("round-trips get/set/clear for a license key", func(t *testing.T) {
		if got, err := store.Get("lic_a"); got != nil || err != nil {
			t.Fatalf("empty store Get = %v, %v", got, err)
		}
		if err := store.Set("lic_a", sampleEntry("token-a")); err != nil {
			t.Fatal(err)
		}
		got, err := store.Get("lic_a")
		if err != nil || !reflect.DeepEqual(*got, sampleEntry("token-a")) {
			t.Fatalf("Get = %+v, %v", got, err)
		}
		if err := store.Clear("lic_a"); err != nil {
			t.Fatal(err)
		}
		if got, err := store.Get("lic_a"); got != nil || err != nil {
			t.Fatalf("Get after Clear = %v, %v", got, err)
		}
		if err := store.Clear("lic_a"); err != nil {
			t.Errorf("clearing a missing entry should not fail: %v", err)
		}
	})

	t.Run("keeps entries for different license keys independent", func(t *testing.T) {
		_ = store.Set("lic_a", sampleEntry("token-a"))
		_ = store.Set("lic_b", sampleEntry("token-b"))
		_ = store.Set("lic_a", sampleEntry("token-a2"))
		_ = store.Clear("lic_b")

		a, _ := store.Get("lic_a")
		b, _ := store.Get("lic_b")
		if a == nil || a.Token != "token-a2" || b != nil {
			t.Errorf("a = %+v, b = %+v", a, b)
		}
	})
}

func TestMemoryTokenStore(t *testing.T) {
	testTokenStore(t, NewMemoryTokenStore())
}

func TestFileTokenStore(t *testing.T) {
	store := NewFileTokenStore("demo-plugin", t.TempDir())
	testTokenStore(t, store)

	t.Run("hashes the license key into the file name", func(t *testing.T) {
		_ = store.Set("../../etc/passwd", sampleEntry("token"))
		path := filepath.Join(store.Dir(), sha256Hex("../../etc/passwd")+".json")
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v, want 0600", info.Mode().Perm())
		}
		if leftovers, _ := filepath.Glob(filepath.Join(store.Dir(), "*.tmp")); len(leftovers) != 0 {
			t.Errorf("temp files left behind: %v", leftovers)
		}
	})

	t.Run("reports a corrupted file instead of returning garbage", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(store.Dir(), sha256Hex("lic_bad")+".json"), []byte("eyJhbGciOi"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := store.Get("lic_bad"); err == nil {
			t.Errorf("Get = %+v, want a decode error", got)
		}
	})
}

func TestFileTokenStoreUsesThePlatformAppDataDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData"))
	t.Setenv("XDG_DATA_HOME", "")

	want := map[string]string{
		"darwin":  filepath.Join(home, "Library", "Application Support", "Licensr", "demo-plugin"),
		"windows": filepath.Join(home, "AppData", "Licensr", "demo-plugin"),
		"linux":   filepath.Join(home, ".local", "share", "licensr", "demo-plugin"),
	}[runtime.GOOS]
	if want == "" {
		t.Skip("no expected default on " + runtime.GOOS)
	}
	if got := NewFileTokenStore("demo-plugin", "").Dir(); got != want {
		t.Errorf("Dir = %s, want %s", got, want)
	}

	if runtime.GOOS == "linux" {
		t.Setenv("XDG_DATA_HOME", filepath.Join(home, "xdg"))
		if got, want := NewFileTokenStore("demo-plugin", "").Dir(), filepath.Join(home, "xdg", "licensr", "demo-plugin"); got != want {
			t.Errorf("Dir with XDG_DATA_HOME = %s, want %s", got, want)
		}
	}
}
