package licensr

import "errors"

// ErrHardwareIDUnavailable is wrapped by ComputeHardwareID's error when the
// platform identifier couldn't be read.
var ErrHardwareIDUnavailable = errors.New("licensr: hardware ID unavailable")

// ComputeHardwareID reads a platform-specific hardware identifier —
// IOPlatformUUID on macOS, MachineGuid + system volume serial on Windows,
// /etc/machine-id on Linux — and returns sha256(salt + rawID) as a
// lowercase hex string, so the actual platform identifier never leaves the
// process and two different salts (e.g. two different plugins) never
// produce a correlatable identifier for the same machine. The result is
// identical to the C++ SDK's compute_hardware_id on the same machine.
//
// salt should be stable for your plugin (e.g. the plugin slug, or a
// constant baked into your build) — changing it changes every user's
// computed identifier, which for ActivateRequest.Identifier means their
// existing seat activation would appear to be a different machine.
//
// Returns an error wrapping ErrHardwareIDUnavailable if the platform
// identifier couldn't be read (rare: restricted permissions, an unusual
// container/sandbox, or an unsupported platform). Fall back to a
// self-generated, persisted UUID in that case — this never talks to the
// network, so there's nothing to retry.
func ComputeHardwareID(salt string) (string, error) {
	rawID, err := readRawHardwareID()
	if err != nil {
		return "", errors.Join(ErrHardwareIDUnavailable, err)
	}
	return sha256Hex(salt + rawID), nil
}
