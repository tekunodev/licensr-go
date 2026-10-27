package licensr

import (
	"errors"
	"testing"
)

func TestAPIErrorMessageNamesTheCodeAndStatus(t *testing.T) {
	err := &APIError{Status: 429, Code: CodeRateLimitExceeded, Message: "Too many requests"}

	if got, want := err.Error(), "licensr: rate_limit_exceeded (HTTP 429): Too many requests"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestNetworkErrorPreservesTheCause(t *testing.T) {
	cause := errors.New("ECONNRESET")
	err := &NetworkError{Message: "request failed", Cause: cause}

	if !errors.Is(err, cause) {
		t.Error("errors.Is should find the cause")
	}
	if got, want := err.Error(), "licensr: request failed: ECONNRESET"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestTokenVerificationErrorMessage(t *testing.T) {
	err := &TokenVerificationError{Message: "signature invalid"}

	if got, want := err.Error(), "licensr: signature invalid"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
