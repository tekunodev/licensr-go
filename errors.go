package licensr

import (
	"fmt"
	"time"
)

// APIError means the API responded with a non-2xx status and a parsed
// detail.error body.
//
// Code is one of the documented error codes (the Code* constants, e.g.
// CodeLicenseInactive, CodeOriginNotAllowed, CodeRateLimitExceeded).
// Branch on Code, not on Message — the message is for humans and may
// change without notice.
type APIError struct {
	Status  int
	Code    string
	Message string
	// Set on 429 responses when the server sends Retry-After; zero otherwise.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("licensr: %s (HTTP %d): %s", e.Code, e.Status, e.Message)
}

// NetworkError means the request never got a response — network failure,
// timeout, or a cancelled context. Unwrap returns the underlying cause.
type NetworkError struct {
	Message string
	Cause   error
}

func (e *NetworkError) Error() string { return "licensr: " + e.Message + ": " + e.Cause.Error() }

func (e *NetworkError) Unwrap() error { return e.Cause }

// TokenVerificationError means an offline token failed EdDSA verification,
// was malformed, or has expired.
type TokenVerificationError struct {
	Message string
}

func (e *TokenVerificationError) Error() string { return "licensr: " + e.Message }
