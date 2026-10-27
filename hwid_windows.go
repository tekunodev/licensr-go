package licensr

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Windows: MachineGuid (a per-install GUID Windows Setup writes to the
// registry) combined with the system volume's serial number, formatted
// exactly as the C++ SDK does ("<guid>-<serial as %08lx>"). Uses only
// syscall so the SDK has no third-party dependencies.
var procGetVolumeInformationW = syscall.NewLazyDLL("kernel32.dll").NewProc("GetVolumeInformationW")

func readRawHardwareID() (string, error) {
	guid, err := readMachineGUID()
	if err != nil {
		return "", err
	}
	if serial, ok := readSystemVolumeSerial(); ok {
		guid += fmt.Sprintf("-%08x", serial)
	}
	return guid, nil
}

func readMachineGUID() (string, error) {
	path, _ := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Cryptography`)
	var key syscall.Handle
	// Default registry view, like the C++ SDK's RegGetValueW, so a 32-bit
	// build gets the same answer (or the same failure) as a 32-bit C++ build.
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, path, 0, syscall.KEY_QUERY_VALUE, &key); err != nil {
		return "", err
	}
	defer syscall.RegCloseKey(key)

	name, _ := syscall.UTF16PtrFromString("MachineGuid")
	buf := make([]uint16, 64)
	size := uint32(len(buf) * 2)
	var valueType uint32
	if err := syscall.RegQueryValueEx(key, name, nil, &valueType, (*byte)(unsafe.Pointer(&buf[0])), &size); err != nil {
		return "", err
	}
	if valueType != syscall.REG_SZ {
		return "", fmt.Errorf("MachineGuid has registry type %d, expected REG_SZ", valueType)
	}
	return syscall.UTF16ToString(buf[:size/2]), nil
}

func readSystemVolumeSerial() (uint32, bool) {
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		return 0, false
	}
	root, err := syscall.UTF16PtrFromString(drive + `\`)
	if err != nil {
		return 0, false
	}
	var serial uint32
	ok, _, _ := procGetVolumeInformationW.Call(uintptr(unsafe.Pointer(root)), 0, 0, uintptr(unsafe.Pointer(&serial)), 0, 0, 0, 0)
	return serial, ok != 0
}
