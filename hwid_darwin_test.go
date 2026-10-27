package licensr

import "testing"

func TestPlatformUUIDPatternMatchesIoregOutput(t *testing.T) {
	out := []byte(`+-o J316sAP  <class IOPlatformExpertDevice, id 0x100000254, registered, matched, active, busy 0 (0 ms), retain 30>
    {
      "IOPlatformSerialNumber" = "C02XXXXXXXXX"
      "IOPlatformUUID" = "2143E746-DE0E-59AD-B0BC-536FA723BC0A"
      "manufacturer" = <"Apple Inc.">
    }`)

	match := platformUUIDPattern.FindSubmatch(out)
	if match == nil || string(match[1]) != "2143E746-DE0E-59AD-B0BC-536FA723BC0A" {
		t.Fatalf("match = %q", match)
	}
}
