package licensr

import (
	"context"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

// Config configures a Client. Only APIKey and PluginSlug are required.
type Config struct {
	// Plugin API key (pk_live_... / pk_test_...).
	// Admin → Catalog → your product → API keys. Issue a Client key to
	// embed in a shipped app (it cannot open checkout).
	APIKey string
	// Product slug from Admin → Catalog (the same value on the product row).
	// Sent as plugin_slug on every license call.
	PluginSlug string
	// Defaults to https://api.licensr.app. Override for self-hosted/staging.
	BaseURL string
	// Explicitly set the Origin header, for the domain-origin guard (see
	// docs/sdks). Desktop apps and services should instead set the
	// product's client type to "native" in the admin UI and leave this empty.
	Origin string
	// Stable per-install identifier, e.g. the same HWID used for Activate
	// (see ComputeHardwareID). Buckets rate limits per installation instead
	// of per key.
	DeviceID string
	// Defaults to a new http.Client. Override for proxies, custom TLS or testing.
	HTTPClient *http.Client
	// Per-attempt timeout. Zero means no timeout beyond the caller's context.
	Timeout time.Duration
	// Nil means DefaultRetry. A zero BaseDelay or MaxDelay keeps its default;
	// set MaxRetries to 0 to disable retries.
	Retry *RetryOptions
	// Optional lifecycle callbacks.
	Hooks Hooks
}

// Hooks are optional lifecycle callbacks. Each runs synchronously on the
// goroutine that made the call; leave unset if you don't need it.
type Hooks struct {
	OnValidated   func(*ValidateResponse)
	OnActivated   func(*ActivateResponse)
	OnDeactivated func(*DeactivateResponse)
	OnTokenIssued func(*TokenResponse)
	// Fired on every retried request, before the retry delay.
	OnRetry func(method string, attempt int, delay time.Duration)
	// Fired whenever a client method fails, right before the error is returned.
	OnError func(method string, err error)
}

// Client is a thin client for the Licensr public license API
// (/v1/license/*, /v1/billing/checkout). It is safe for concurrent use.
//
//	client := licensr.NewClient(licensr.Config{APIKey: "pk_live_...", PluginSlug: "my-plugin"})
//	result, err := client.Validate(ctx, licensr.ValidateRequest{LicenseKey: key})
//	if err == nil && result.Valid { ... }
type Client struct {
	cfg           Config
	retry         RetryOptions
	httpClient    *http.Client
	lastValidated atomic.Pointer[ValidateResponse]
}

func NewClient(cfg Config) *Client {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.licensr.app"
	}
	c := &Client{cfg: cfg, retry: DefaultRetry, httpClient: cfg.HTTPClient}
	if cfg.Retry != nil {
		c.retry.MaxRetries = cfg.Retry.MaxRetries
		if cfg.Retry.BaseDelay > 0 {
			c.retry.BaseDelay = cfg.Retry.BaseDelay
		}
		if cfg.Retry.MaxDelay > 0 {
			c.retry.MaxDelay = cfg.Retry.MaxDelay
		}
	}
	if c.httpClient == nil {
		c.httpClient = &http.Client{}
	}
	return c
}

// Validate checks whether a license is valid for this plugin, without minting an offline token.
func (c *Client) Validate(ctx context.Context, req ValidateRequest) (*ValidateResponse, error) {
	return call[ValidateResponse](ctx, c, "validate", requestSpec{
		method: http.MethodPost,
		path:   "v1/license/validate",
		body:   map[string]any{"license_key": req.LicenseKey, "plugin_slug": c.cfg.PluginSlug},
	}, func(res *ValidateResponse) {
		// Store first, so LastValidated inside OnValidated sees this result.
		c.lastValidated.Store(res)
		if c.cfg.Hooks.OnValidated != nil {
			c.cfg.Hooks.OnValidated(res)
		}
	})
}

// Token runs the same check as Validate, and on success mints a short-lived
// EdDSA-signed offline token. Verify it with VerifyOfflineToken — no
// network call needed after the first successful fetch of the plugin's JWKS.
func (c *Client) Token(ctx context.Context, req ValidateRequest) (*TokenResponse, error) {
	return call[TokenResponse](ctx, c, "token", requestSpec{
		method: http.MethodPost,
		path:   "v1/license/token",
		body:   map[string]any{"license_key": req.LicenseKey, "plugin_slug": c.cfg.PluginSlug},
	}, c.cfg.Hooks.OnTokenIssued)
}

// Activate activates a seat (per-machine HWID) or domain for a license.
func (c *Client) Activate(ctx context.Context, req ActivateRequest) (*ActivateResponse, error) {
	return call[ActivateResponse](ctx, c, "activate", requestSpec{
		method: http.MethodPost,
		path:   "v1/license/activate",
		body: map[string]any{
			"license_key":     req.LicenseKey,
			"plugin_slug":     c.cfg.PluginSlug,
			"activation_type": req.ActivationType,
			"identifier":      req.Identifier,
			"label":           nullIfEmpty(req.Label),
		},
	}, c.cfg.Hooks.OnActivated)
}

// Deactivate releases a previously created activation, freeing its seat/domain slot.
func (c *Client) Deactivate(ctx context.Context, req DeactivateRequest) (*DeactivateResponse, error) {
	return call[DeactivateResponse](ctx, c, "deactivate", requestSpec{
		method: http.MethodPost,
		path:   "v1/license/deactivate",
		body:   map[string]any{"license_key": req.LicenseKey, "activation_id": req.ActivationID},
	}, c.cfg.Hooks.OnDeactivated)
}

// Activations lists every current activation for a license (seats/domains in use).
func (c *Client) Activations(ctx context.Context, req ActivationsRequest) (*ActivationsResponse, error) {
	return call[ActivationsResponse](ctx, c, "activations", requestSpec{
		method: http.MethodGet,
		path:   "v1/license/activations",
		query:  url.Values{"license_key": {req.LicenseKey}, "plugin_slug": {c.cfg.PluginSlug}},
	}, nil)
}

// Checkout starts a hosted checkout session for a plan; redirect the user to the returned URL.
func (c *Client) Checkout(ctx context.Context, req CheckoutRequest) (*CheckoutResponse, error) {
	body := map[string]any{
		"plan_id":        req.PlanID,
		"customer_email": req.CustomerEmail,
		"success_url":    nullIfEmpty(req.SuccessURL),
		"cancel_url":     nullIfEmpty(req.CancelURL),
	}
	// Sent only when asked for, so servers without test clocks see the same body.
	if req.TestClock {
		body["test_clock"] = true
	}
	return call[CheckoutResponse](ctx, c, "checkout", requestSpec{
		method: http.MethodPost,
		path:   "v1/billing/checkout",
		body:   body,
	}, nil)
}

// LastValidated returns the most recent successful Validate result from
// this client, or nil if Validate hasn't succeeded yet. It never blocks or
// touches the network, so it is safe to call from any goroutine on a hot
// path. The result is shared: treat it as read-only.
func (c *Client) LastValidated() *ValidateResponse {
	return c.lastValidated.Load()
}

func call[T any](ctx context.Context, c *Client, method string, spec requestSpec, onSuccess func(*T)) (*T, error) {
	if hook := c.cfg.Hooks.OnRetry; hook != nil {
		spec.onRetry = func(attempt int, delay time.Duration) { hook(method, attempt, delay) }
	}
	var res T
	if err := c.do(ctx, spec, &res); err != nil {
		if c.cfg.Hooks.OnError != nil {
			c.cfg.Hooks.OnError(method, err)
		}
		return nil, err
	}
	if onSuccess != nil {
		onSuccess(&res)
	}
	return &res, nil
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
