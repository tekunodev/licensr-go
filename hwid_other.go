//go:build !darwin && !linux && !windows

package licensr

import (
	"errors"
	"runtime"
)

func readRawHardwareID() (string, error) {
	return "", errors.New("no hardware ID source on " + runtime.GOOS)
}
