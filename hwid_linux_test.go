package licensr

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadMachineIDFileTrimsLikeTheCppSDK(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"0123abcd\n":        "0123abcd",
		"0123abcd\r\n":      "0123abcd",
		"0123abcd  \n2nd\n": "0123abcd",
		"0123abcd":          "0123abcd",
		"\n":                "",
		" leading-space\n":  " leading-space", // C++ only trims trailing whitespace.
	}
	for contents, want := range cases {
		path := filepath.Join(dir, "machine-id")
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := readMachineIDFile(path); got != want {
			t.Errorf("readMachineIDFile(%q) = %q, want %q", contents, got, want)
		}
	}
	if got := readMachineIDFile(filepath.Join(dir, "missing")); got != "" {
		t.Errorf("missing file = %q, want empty", got)
	}
}
