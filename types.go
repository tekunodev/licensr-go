package licensr

// Request/response shapes for the Licensr public license API.
//
// Mirrors contract/openapi.json (generated from the FastAPI backend — see
// backend/services/models/license.py). Keep in sync manually: there is no
// codegen step, so any field added to the backend's response models should
// be mirrored here. The JSON tags are the wire names, so there is no
// separate wire layer; nullable fields are pointers.

// ActivationType is how a license is bound: one seat per machine, or one domain per website.
type ActivationType string

const (
	ActivationSeat   ActivationType = "seat"
	ActivationDomain ActivationType = "domain"
)

// LicenseStatus says why a license is or isn't valid.
type LicenseStatus string

const (
	StatusActive   LicenseStatus = "active"
	StatusInactive LicenseStatus = "inactive"
	StatusExpired  LicenseStatus = "expired"
)

// Entitlement is the level of access a license grants.
type Entitlement string

const (
	EntitlementFull    Entitlement = "full"
	EntitlementLimited Entitlement = "limited"
	EntitlementNone    Entitlement = "none"
)

type ValidateRequest struct {
	LicenseKey string
}

// LicenseDetails is information about the license. Nothing here decides access; safe to ignore.
type LicenseDetails struct {
	PlanID         *string         `json:"plan_id"`
	ActivationMode *ActivationType `json:"activation_mode"`
	// Devices or users allowed. nil means unlimited.
	MaxSeats *int `json:"max_seats"`
	// Websites allowed. nil means unlimited.
	MaxDomains *int `json:"max_domains"`
	SeatsInUse *int `json:"seats_in_use"`
	// When the license expires. nil means it never expires.
	ExpiresAt *string `json:"expires_at"`
}

type ValidateResponse struct {
	// The answer you gate on: true unlocks your product, false keeps it locked.
	Valid bool `json:"valid"`
	// Why: pick the message to show the customer. Do not gate access on it.
	Status LicenseStatus `json:"status"`
	// Optional. EntitlementLimited means expired but a fallback plan keeps reduced access.
	Entitlement Entitlement `json:"entitlement"`
	// Optional. Custom per-plan settings you defined.
	FeatureFlags map[string]any `json:"feature_flags"`
	// Plan, limits and expiry. Informational only.
	License LicenseDetails `json:"license"`
}

type ActivateRequest struct {
	LicenseKey     string
	ActivationType ActivationType
	// Stable per-install identifier: HWID for ActivationSeat (see ComputeHardwareID), hostname for ActivationDomain.
	Identifier string
	// Cosmetic, shown in admin/customer portals (e.g. "My MacBook Pro"). Empty sends null.
	Label string
}

// ActivationInfo is what was activated (an echo of your request). Informational only.
type ActivationInfo struct {
	Type       ActivationType `json:"type"`
	Identifier string         `json:"identifier"`
}

type ActivateResponse struct {
	// Save this: you need it to deactivate later.
	ActivationID string         `json:"activation_id"`
	FeatureFlags map[string]any `json:"feature_flags"`
	Activation   ActivationInfo `json:"activation"`
}

type DeactivateRequest struct {
	LicenseKey   string
	ActivationID string
}

type DeactivateResponse struct {
	Deactivated bool `json:"deactivated"`
}

type ActivationListItem struct {
	ActivationID   string         `json:"activation_id"`
	ActivationType ActivationType `json:"activation_type"`
	Identifier     string         `json:"identifier"`
	Label          *string        `json:"label"`
	FirstSeenAt    string         `json:"first_seen_at"`
	LastSeenAt     string         `json:"last_seen_at"`
}

type ActivationsRequest struct {
	LicenseKey string
}

type ActivationsResponse struct {
	LicenseID   string               `json:"license_id"`
	Activations []ActivationListItem `json:"activations"`
}

// TokenDetails says how to verify the offline token and when to refresh it.
type TokenDetails struct {
	Algorithm string `json:"algorithm"`
	Kid       string `json:"kid"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
	JWKSURL   string `json:"jwks_url"`
}

type TokenResponse struct {
	// EdDSA-signed JWT — verify with VerifyOfflineToken (pass Details.JWKSURL).
	Token   string       `json:"token"`
	Details TokenDetails `json:"details"`
}

// OfflineTokenClaims are the claims embedded in the offline token. Flat, as
// in any JWT; carries the same facts as ValidateResponse.
type OfflineTokenClaims struct {
	Sub              string          `json:"sub"`
	Iss              string          `json:"iss"`
	Iat              int64           `json:"iat"`
	Nbf              int64           `json:"nbf"`
	Exp              int64           `json:"exp"`
	PluginSlug       string          `json:"plugin_slug"`
	PlanID           *string         `json:"plan_id"`
	Status           LicenseStatus   `json:"status"`
	Valid            bool            `json:"valid"`
	Entitlement      Entitlement     `json:"entitlement"`
	Fallback         bool            `json:"fallback"`
	ActivationMode   *ActivationType `json:"activation_mode"`
	MaxSeats         *int            `json:"max_seats"`
	MaxDomains       *int            `json:"max_domains"`
	LicenseExpiresAt *int64          `json:"license_expires_at"`
	FeatureFlags     map[string]any  `json:"feature_flags"`
}

type CheckoutRequest struct {
	PlanID        string
	CustomerEmail string
	// Empty sends null (the plan's default redirect).
	SuccessURL string
	// Empty sends null (the plan's default redirect).
	CancelURL string
}

type CheckoutResponse struct {
	CheckoutURL string `json:"checkout_url"`
}

// Every documented detail.error code from the license API — see
// contract/conformance.yaml. Branch on APIError.Code, not on its message.
const (
	CodeMissingPluginAPIKey    = "missing_plugin_api_key"
	CodeInvalidPluginAPIKey    = "invalid_plugin_api_key"
	CodeOriginNotAllowed       = "origin_not_allowed"
	CodeOriginNotActivated     = "origin_not_activated"
	CodePluginMismatch         = "plugin_mismatch"
	CodeLicenseInactive        = "license_inactive"
	CodeLicenseNotValid        = "license_not_valid"
	CodeLicenseNotFound        = "license_not_found"
	CodeActivationNotFound     = "activation_not_found"
	CodeActivationModeMismatch = "activation_mode_mismatch"
	CodeActivationCapExceeded  = "activation_cap_exceeded"
	CodeJWKSPathDeprecated     = "jwks_path_deprecated"
	CodeRateLimitExceeded      = "rate_limit_exceeded"
	CodeInsufficientScope      = "insufficient_scope"
	// Client-side codes for error bodies with no detail.error.
	CodeValidationError = "validation_error"
	CodeUnknownError    = "unknown_error"
)
