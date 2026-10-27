package licensr

import (
	"bufio"
	"errors"
	"os"
	"strings"
)

// Linux: /etc/machine-id, a systemd-maintained identifier stable across
// reboots and regenerated only on OS reinstall. Falls back to
// /var/lib/dbus/machine-id (the pre-systemd/non-systemd equivalent) for
// minimal/container images that lack the former.
func readRawHardwareID() (string, error) {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if id := readMachineIDFile(path); id != "" {
			return id, nil
		}
	}
	return "", errors.New("no readable machine-id")
}

// readMachineIDFile returns the first line with trailing whitespace
// trimmed exactly as the C++ SDK does, so both produce the same ID.
func readMachineIDFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	line, _ := bufio.NewReader(f).ReadString('\n')
	return strings.TrimRight(line, "\n\r ")
}
