package licensr

import (
	"regexp"
	"testing"
)

// The raw platform identifier is machine-specific and, by design, never
// observable through the public API, so these tests check the properties
// ComputeHardwareID promises instead: determinism, salt-sensitivity, and a
// well-formed SHA-256 hex digest — the same checks as the C++ SDK's
// test_hwid.cpp.

var sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestComputeHardwareIDSucceedsOnANormalMachine(t *testing.T) {
	id, err := ComputeHardwareID("test-salt")
	// Not a hard API guarantee (restricted sandboxes return an error), but
	// should hold on the machines this suite runs on.
	if err != nil {
		t.Fatal(err)
	}
	if !sha256HexPattern.MatchString(id) {
		t.Errorf("id = %q, want 64 lowercase hex chars", id)
	}
}

func TestComputeHardwareIDIsDeterministicForTheSameSalt(t *testing.T) {
	first, err1 := ComputeHardwareID("plugin-a")
	second, err2 := ComputeHardwareID("plugin-a")
	if err1 != nil || err2 != nil || first != second {
		t.Errorf("got %q (%v) then %q (%v)", first, err1, second, err2)
	}
}

func TestComputeHardwareIDDiffersAcrossSalts(t *testing.T) {
	// The whole point of salting: two unrelated integrations must not
	// produce a correlatable identifier for the same physical machine.
	a, _ := ComputeHardwareID("plugin-a")
	b, _ := ComputeHardwareID("plugin-b")
	if a == b {
		t.Errorf("both salts produced %q", a)
	}
}

func TestComputeHardwareIDHashesSaltThenRawID(t *testing.T) {
	// sha256("salt-" + "raw-id"), the derivation the C++ SDK's hash_hardware_id uses.
	if got, want := sha256Hex("salt-"+"raw-id"), "150987cba7d06edd2d3058fe6c6a773e20e88f44cceae4b9e3f7e4cfc052cc1a"; got != want {
		t.Errorf("sha256Hex = %s, want %s", got, want)
	}
	raw, err := readRawHardwareID()
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := ComputeHardwareID("salt-"); id != sha256Hex("salt-"+raw) {
		t.Errorf("ComputeHardwareID does not hash salt + raw ID")
	}
}
