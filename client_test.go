package licensr

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"
)

type recordedRequest struct {
	method string
	path   string
	query  string
	header http.Header
	body   map[string]any
}

// fakeAPI serves one canned response per request, in order (repeating the
// last one), and records every request it receives.
type fakeAPI struct {
	*httptest.Server
	mu        sync.Mutex
	requests  []recordedRequest
	responses []fakeResponse
}

type fakeResponse struct {
	status int
	body   string
	header map[string]string
	// Held before responding, e.g. to trip Config.Timeout; ends early if the client gives up.
	delay time.Duration
}

func newFakeAPI(t *testing.T, responses ...fakeResponse) *fakeAPI {
	t.Helper()
	api := &fakeAPI{responses: responses}
	api.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		rec := recordedRequest{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, header: r.Header}
		if len(data) > 0 {
			if err := json.Unmarshal(data, &rec.body); err != nil {
				t.Errorf("request body is not JSON: %s", data)
			}
		}
		api.mu.Lock()
		api.requests = append(api.requests, rec)
		resp := api.responses[min(len(api.requests), len(api.responses))-1]
		api.mu.Unlock()

		select {
		case <-time.After(resp.delay):
		case <-r.Context().Done():
			return
		}
		for k, v := range resp.header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(resp.status)
		_, _ = w.Write([]byte(resp.body))
	}))
	t.Cleanup(api.Close)
	return api
}

func (api *fakeAPI) last() recordedRequest {
	api.mu.Lock()
	defer api.mu.Unlock()
	return api.requests[len(api.requests)-1]
}

func (api *fakeAPI) count() int {
	api.mu.Lock()
	defer api.mu.Unlock()
	return len(api.requests)
}

func jsonResponse(status int, body string) fakeResponse {
	return fakeResponse{status: status, body: body, header: map[string]string{"Content-Type": "application/json"}}
}

func makeClient(api *fakeAPI, hooks Hooks) *Client {
	return NewClient(Config{
		APIKey:     "pk_live_test",
		PluginSlug: "demo-plugin",
		BaseURL:    api.URL,
		Retry:      &RetryOptions{MaxRetries: 0, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
		Hooks:      hooks,
	})
}

const validateBody = `{
	"valid": true, "status": "active", "entitlement": "full", "feature_flags": {"pro": true},
	"license": {"plan_id": "plan-1", "activation_mode": "seat", "max_seats": 5, "max_domains": null,
	            "seats_in_use": 1, "expires_at": null}
}`

func TestValidatePostsSnakeCaseFieldsAndDecodesResponse(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(200, validateBody))
	client := makeClient(api, Hooks{})

	res, err := client.Validate(context.Background(), ValidateRequest{LicenseKey: "lic_abc"})
	if err != nil {
		t.Fatal(err)
	}

	if !res.Valid || res.Status != StatusActive || res.Entitlement != EntitlementFull {
		t.Errorf("unexpected result %+v", res)
	}
	if *res.License.MaxSeats != 5 || *res.License.PlanID != "plan-1" || res.License.MaxDomains != nil {
		t.Errorf("unexpected license details %+v", res.License)
	}
	if res.FeatureFlags["pro"] != true {
		t.Errorf("feature flags not decoded: %v", res.FeatureFlags)
	}
	req := api.last()
	if req.method != http.MethodPost || req.path != "/v1/license/validate" {
		t.Errorf("got %s %s", req.method, req.path)
	}
	if want := map[string]any{"license_key": "lic_abc", "plugin_slug": "demo-plugin"}; !reflect.DeepEqual(req.body, want) {
		t.Errorf("body = %v, want %v", req.body, want)
	}
}

func TestTokenDecodesOfflineTokenResponse(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(200, `{"token": "jwt-value", "details": {"algorithm": "EdDSA", "kid": "kid-1",
		"issued_at": "2027-01-01T00:00:00Z", "expires_at": "2027-02-01T00:00:00Z",
		"jwks_url": "https://api.example.test/v1/license/jwks/acme/demo-plugin.json"}}`))
	client := makeClient(api, Hooks{})

	res, err := client.Token(context.Background(), ValidateRequest{LicenseKey: "lic_abc"})
	if err != nil {
		t.Fatal(err)
	}

	if res.Token != "jwt-value" || res.Details.JWKSURL != "https://api.example.test/v1/license/jwks/acme/demo-plugin.json" {
		t.Errorf("unexpected result %+v", res)
	}
	if api.last().path != "/v1/license/token" {
		t.Errorf("path = %s", api.last().path)
	}
}

func TestActivateSendsActivationFieldsAndDecodesResponse(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(200, `{"activation_id": "act-1", "feature_flags": null,
		"activation": {"type": "seat", "identifier": "hwid-1"}}`))
	client := makeClient(api, Hooks{})

	res, err := client.Activate(context.Background(), ActivateRequest{
		LicenseKey: "lic_abc", ActivationType: ActivationSeat, Identifier: "hwid-1", Label: "My Mac",
	})
	if err != nil {
		t.Fatal(err)
	}

	if res.ActivationID != "act-1" || res.Activation.Type != ActivationSeat || res.Activation.Identifier != "hwid-1" {
		t.Errorf("unexpected result %+v", res)
	}
	want := map[string]any{
		"license_key": "lic_abc", "plugin_slug": "demo-plugin", "activation_type": "seat",
		"identifier": "hwid-1", "label": "My Mac",
	}
	if !reflect.DeepEqual(api.last().body, want) {
		t.Errorf("body = %v, want %v", api.last().body, want)
	}
}

func TestActivateSendsAnEmptyLabelAsNull(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(200, `{"activation_id": "act-1", "feature_flags": null,
		"activation": {"type": "seat", "identifier": "hwid-1"}}`))
	client := makeClient(api, Hooks{})

	if _, err := client.Activate(context.Background(), ActivateRequest{
		LicenseKey: "lic_abc", ActivationType: ActivationSeat, Identifier: "hwid-1",
	}); err != nil {
		t.Fatal(err)
	}

	label, ok := api.last().body["label"]
	if !ok || label != nil {
		t.Errorf("label = %v (present %v), want null", label, ok)
	}
}

func TestDeactivateDoesNotSendPluginSlug(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(200, `{"deactivated": true}`))
	client := makeClient(api, Hooks{})

	res, err := client.Deactivate(context.Background(), DeactivateRequest{LicenseKey: "lic_abc", ActivationID: "act-1"})
	if err != nil {
		t.Fatal(err)
	}

	if !res.Deactivated {
		t.Error("Deactivated = false")
	}
	// Deactivate is scoped by activation_id alone.
	if want := map[string]any{"license_key": "lic_abc", "activation_id": "act-1"}; !reflect.DeepEqual(api.last().body, want) {
		t.Errorf("body = %v, want %v", api.last().body, want)
	}
}

func TestActivationsSendsAGetWithQueryParams(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(200, `{"license_id": "lic-1", "activations": [{"activation_id": "act-1",
		"activation_type": "seat", "identifier": "hwid-1", "label": null,
		"first_seen_at": "2027-01-01T00:00:00Z", "last_seen_at": "2027-01-02T00:00:00Z"}]}`))
	client := makeClient(api, Hooks{})

	res, err := client.Activations(context.Background(), ActivationsRequest{LicenseKey: "lic_abc"})
	if err != nil {
		t.Fatal(err)
	}

	if res.LicenseID != "lic-1" || len(res.Activations) != 1 || res.Activations[0].ActivationID != "act-1" {
		t.Errorf("unexpected result %+v", res)
	}
	req := api.last()
	if req.method != http.MethodGet || req.query != "license_key=lic_abc&plugin_slug=demo-plugin" || req.body != nil {
		t.Errorf("got %s ?%s body=%v", req.method, req.query, req.body)
	}
}

func TestCheckoutPostsPlanAndEmail(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(200, `{"checkout_url": "https://pay.example.test/session"}`))
	client := makeClient(api, Hooks{})

	res, err := client.Checkout(context.Background(), CheckoutRequest{PlanID: "plan-1", CustomerEmail: "a@example.test"})
	if err != nil {
		t.Fatal(err)
	}

	if res.CheckoutURL != "https://pay.example.test/session" {
		t.Errorf("CheckoutURL = %s", res.CheckoutURL)
	}
	if res.TestClockID != nil {
		t.Errorf("TestClockID = %v, want nil", *res.TestClockID)
	}
	want := map[string]any{"plan_id": "plan-1", "customer_email": "a@example.test", "success_url": nil, "cancel_url": nil}
	if !reflect.DeepEqual(api.last().body, want) || api.last().path != "/v1/billing/checkout" {
		t.Errorf("%s body = %v, want %v", api.last().path, api.last().body, want)
	}
}

func TestCheckoutSendsTestClockAndMapsID(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(200, `{"checkout_url": "https://pay.example.test/session", "test_clock_id": "clock_123"}`))
	client := makeClient(api, Hooks{})

	res, err := client.Checkout(context.Background(), CheckoutRequest{PlanID: "plan-1", CustomerEmail: "a@example.test", TestClock: true})
	if err != nil {
		t.Fatal(err)
	}

	if res.TestClockID == nil || *res.TestClockID != "clock_123" {
		t.Errorf("TestClockID = %v, want clock_123", res.TestClockID)
	}
	want := map[string]any{"plan_id": "plan-1", "customer_email": "a@example.test", "success_url": nil, "cancel_url": nil, "test_clock": true}
	if !reflect.DeepEqual(api.last().body, want) {
		t.Errorf("body = %v, want %v", api.last().body, want)
	}
}

func TestHooksFireOnSuccess(t *testing.T) {
	api := newFakeAPI(t,
		jsonResponse(200, validateBody),
		jsonResponse(200, `{"activation_id": "act-1", "feature_flags": null, "activation": {"type": "seat", "identifier": "x"}}`),
		jsonResponse(200, `{"deactivated": true}`),
		jsonResponse(200, `{"token": "jwt", "details": {"algorithm": "EdDSA", "kid": "k", "issued_at": "", "expires_at": "", "jwks_url": ""}}`))
	var fired []string
	var client *Client
	client = makeClient(api, Hooks{
		OnValidated: func(r *ValidateResponse) {
			if client.LastValidated() != r {
				t.Error("LastValidated inside OnValidated should already be this result")
			}
			fired = append(fired, "validated")
		},
		OnActivated:   func(*ActivateResponse) { fired = append(fired, "activated") },
		OnDeactivated: func(*DeactivateResponse) { fired = append(fired, "deactivated") },
		OnTokenIssued: func(*TokenResponse) { fired = append(fired, "tokenIssued") },
	})
	ctx := context.Background()

	_, err1 := client.Validate(ctx, ValidateRequest{LicenseKey: "lic_abc"})
	_, err2 := client.Activate(ctx, ActivateRequest{LicenseKey: "lic_abc", ActivationType: ActivationSeat, Identifier: "x"})
	_, err3 := client.Deactivate(ctx, DeactivateRequest{LicenseKey: "lic_abc", ActivationID: "act-1"})
	_, err4 := client.Token(ctx, ValidateRequest{LicenseKey: "lic_abc"})
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		t.Fatal(err)
	}

	if want := []string{"validated", "activated", "deactivated", "tokenIssued"}; !reflect.DeepEqual(fired, want) {
		t.Errorf("fired = %v, want %v", fired, want)
	}
}

func TestOnErrorFiresAndTheErrorIsReturned(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(403, `{"detail": {"error": "license_inactive", "message": "nope"}}`))
	var gotMethod string
	var gotErr error
	client := makeClient(api, Hooks{OnError: func(method string, err error) { gotMethod, gotErr = method, err }})

	_, err := client.Activate(context.Background(), ActivateRequest{LicenseKey: "lic_abc", ActivationType: ActivationSeat, Identifier: "x"})

	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != CodeLicenseInactive {
		t.Fatalf("err = %v", err)
	}
	if gotMethod != "activate" || gotErr != err {
		t.Errorf("OnError got (%q, %v)", gotMethod, gotErr)
	}
}

func TestLastValidatedTracksTheLatestSuccessfulValidate(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(200, validateBody), jsonResponse(500, `{}`))
	client := makeClient(api, Hooks{})

	if client.LastValidated() != nil {
		t.Fatal("LastValidated before any call should be nil")
	}
	res, err := client.Validate(context.Background(), ValidateRequest{LicenseKey: "lic_abc"})
	if err != nil {
		t.Fatal(err)
	}
	if client.LastValidated() != res {
		t.Error("LastValidated did not return the successful result")
	}
	if _, err := client.Validate(context.Background(), ValidateRequest{LicenseKey: "lic_abc"}); err == nil {
		t.Fatal("expected the second call to fail")
	}
	if client.LastValidated() != res {
		t.Error("a failed Validate must not clear LastValidated")
	}
}

func TestBaseURLDefaultsToTheHostedAPI(t *testing.T) {
	client := NewClient(Config{APIKey: "pk_live_test", PluginSlug: "demo-plugin"})

	if client.cfg.BaseURL != "https://api.licensr.app" {
		t.Errorf("BaseURL = %s", client.cfg.BaseURL)
	}
	if client.retry != DefaultRetry {
		t.Errorf("retry = %+v, want DefaultRetry", client.retry)
	}
}
