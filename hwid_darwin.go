package licensr

import (
	"errors"
	"os/exec"
	"regexp"
)

// macOS: IOPlatformUUID, stable across reboots and OS reinstalls (it's tied
// to the logic board, not the boot volume). Read through ioreg rather than
// IOKit so the SDK builds without cgo; it is the same registry property the
// C++ SDK reads.
var platformUUIDPattern = regexp.MustCompile(`"IOPlatformUUID" = "([^"]+)"`)

func readRawHardwareID() (string, error) {
	out, err := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", err
	}
	match := platformUUIDPattern.FindSubmatch(out)
	if match == nil {
		return "", errors.New("IOPlatformUUID not found in ioreg output")
	}
	return string(match[1]), nil
}
