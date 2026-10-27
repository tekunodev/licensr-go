package licensr

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func retryingClient(api *fakeAPI, maxRetries int, hooks Hooks) *Client {
	return NewClient(Config{
		APIKey:     "pk_live_test",
		PluginSlug: "demo-plugin",
		BaseURL:    api.URL,
		Retry:      &RetryOptions{MaxRetries: maxRetries, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond},
		Hooks:      hooks,
	})
}

func validate(client *Client) error {
	_, err := client.Validate(context.Background(), ValidateRequest{LicenseKey: "lic_abc"})
	return err
}

func TestSendsAuthorizationAndJSONContentType(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(200, validateBody))

	if err := validate(makeClient(api, Hooks{})); err != nil {
		t.Fatal(err)
	}

	h := api.last().header
	if h.Get("Authorization") != "Bearer pk_live_test" || h.Get("Content-Type") != "application/json" {
		t.Errorf("headers = %v", h)
	}
	if h.Get(DeviceIDHeader) != "" || h.Get("Origin") != "" {
		t.Errorf("unset DeviceID/Origin should not be sent: %v", h)
	}
}

func TestGetSendsNoContentType(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(200, `{"license_id": "lic-1", "activations": []}`))

	if _, err := makeClient(api, Hooks{}).Activations(context.Background(), ActivationsRequest{LicenseKey: "lic_abc"}); err != nil {
		t.Fatal(err)
	}

	if ct := api.last().header.Get("Content-Type"); ct != "" {
		t.Errorf("Content-Type = %q on a GET", ct)
	}
}

func TestSendsDeviceIDAndOriginWhenConfigured(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(200, validateBody))
	client := NewClient(Config{
		APIKey: "pk_live_test", PluginSlug: "demo-plugin", BaseURL: api.URL + "/",
		DeviceID: "hwid-1", Origin: "https://app.example.test",
	})

	if err := validate(client); err != nil {
		t.Fatal(err)
	}

	h := api.last().header
	if h.Get(DeviceIDHeader) != "hwid-1" || h.Get("Origin") != "https://app.example.test" {
		t.Errorf("headers = %v", h)
	}
	if api.last().path != "/v1/license/validate" {
		t.Errorf("a trailing slash on BaseURL should not double up: %s", api.last().path)
	}
}

func TestReturnsAPIErrorWithTheDetailErrorCode(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(403, `{"detail": {"error": "origin_not_allowed", "message": "Origin not allowed"}}`))

	err := validate(makeClient(api, Hooks{}))

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v", err)
	}
	if apiErr.Status != 403 || apiErr.Code != CodeOriginNotAllowed || apiErr.Message != "Origin not allowed" {
		t.Errorf("got %+v", apiErr)
	}
}

func TestReturnsValidationErrorForAPydantic422Body(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(422, `{"detail": [{"msg": "field required", "loc": ["body", "license_key"]}]}`))

	var apiErr *APIError
	if err := validate(makeClient(api, Hooks{})); !errors.As(err, &apiErr) {
		t.Fatalf("err = %v", err)
	}
	if apiErr.Code != CodeValidationError || apiErr.Message != "field required" {
		t.Errorf("got %+v", apiErr)
	}
}

func TestFallsBackToAGenericErrorForUnrecognizedBodies(t *testing.T) {
	for name, body := range map[string]string{"no detail shape": `{"oops": true}`, "not JSON": `<html>bad gateway</html>`} {
		t.Run(name, func(t *testing.T) {
			api := newFakeAPI(t, fakeResponse{status: 418, body: body})

			var apiErr *APIError
			if err := validate(makeClient(api, Hooks{})); !errors.As(err, &apiErr) {
				t.Fatalf("err = %v", err)
			}
			if apiErr.Code != CodeUnknownError || apiErr.Message != "I'm a teapot" {
				t.Errorf("got %+v", apiErr)
			}
		})
	}
}

func TestRetriesA500AndSucceedsOnceTheServerRecovers(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(500, `{}`), jsonResponse(200, validateBody))

	if err := validate(retryingClient(api, 2, Hooks{})); err != nil {
		t.Fatal(err)
	}
	if api.count() != 2 {
		t.Errorf("requests = %d, want 2", api.count())
	}
}

func TestHonoursRetryAfterOnA429(t *testing.T) {
	api := newFakeAPI(t,
		fakeResponse{status: 429, body: `{}`, header: map[string]string{"Retry-After": "0.05"}},
		jsonResponse(200, validateBody))
	var delays []time.Duration
	client := retryingClient(api, 2, Hooks{OnRetry: func(_ string, _ int, d time.Duration) { delays = append(delays, d) }})

	start := time.Now()
	if err := validate(client); err != nil {
		t.Fatal(err)
	}

	if len(delays) != 1 || delays[0] != 50*time.Millisecond {
		t.Errorf("delays = %v, want [50ms]", delays)
	}
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
		t.Errorf("returned after %v, before the Retry-After delay", elapsed)
	}
}

func TestGivesUpAfterExhaustingRetriesOnRepeated5xx(t *testing.T) {
	api := newFakeAPI(t, fakeResponse{status: 503, body: `{}`, header: map[string]string{"Retry-After": "0"}})

	var apiErr *APIError
	if err := validate(retryingClient(api, 2, Hooks{})); !errors.As(err, &apiErr) || apiErr.Status != 503 {
		t.Fatalf("err = %v", err)
	}
	if api.count() != 3 {
		t.Errorf("requests = %d, want 3", api.count())
	}
}

func TestReportsRetryAfterOnTheFinal429(t *testing.T) {
	api := newFakeAPI(t, fakeResponse{status: 429, body: `{"detail": {"error": "rate_limit_exceeded"}}`,
		header: map[string]string{"Retry-After": "30"}})

	var apiErr *APIError
	if err := validate(makeClient(api, Hooks{})); !errors.As(err, &apiErr) {
		t.Fatalf("err = %v", err)
	}
	if apiErr.Code != CodeRateLimitExceeded || apiErr.RetryAfter != 30*time.Second || apiErr.Message != "Too Many Requests" {
		t.Errorf("got %+v", apiErr)
	}
}

func TestDoesNotRetryANonRetriable4xx(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(404, `{"detail": {"error": "activation_not_found"}}`))

	if err := validate(retryingClient(api, 2, Hooks{})); err == nil {
		t.Fatal("expected an error")
	}
	if api.count() != 1 {
		t.Errorf("requests = %d, want 1", api.count())
	}
}

func TestWrapsAPersistentNetworkFailureInNetworkError(t *testing.T) {
	api := newFakeAPI(t)
	api.Close() // Nothing listens on this URL any more.
	var attempts []int
	client := retryingClient(api, 2, Hooks{OnRetry: func(method string, attempt int, _ time.Duration) {
		if method != "validate" {
			t.Errorf("OnRetry method = %q", method)
		}
		attempts = append(attempts, attempt)
	}})

	err := validate(client)

	var netErr *NetworkError
	if !errors.As(err, &netErr) || netErr.Unwrap() == nil {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "failed after 3 attempt(s)") {
		t.Errorf("message = %q", err.Error())
	}
	if len(attempts) != 2 || attempts[0] != 1 || attempts[1] != 2 {
		t.Errorf("OnRetry attempts = %v, want [1 2]", attempts)
	}
}

func TestStopsRetryingWhenTheContextIsCancelled(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(500, `{}`))
	client := NewClient(Config{
		APIKey: "pk_live_test", PluginSlug: "demo-plugin", BaseURL: api.URL,
		Retry: &RetryOptions{MaxRetries: 5, BaseDelay: time.Hour, MaxDelay: time.Hour},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := client.Validate(ctx, ValidateRequest{LicenseKey: "lic_abc"})

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want a NetworkError wrapping context.DeadlineExceeded", err)
	}
}

func TestTimeoutAppliesPerAttempt(t *testing.T) {
	api := newFakeAPI(t, jsonResponse(200, validateBody))
	api.delay = 200 * time.Millisecond
	client := NewClient(Config{
		APIKey: "pk_live_test", PluginSlug: "demo-plugin", BaseURL: api.URL,
		Timeout: 10 * time.Millisecond, Retry: &RetryOptions{},
	})

	var netErr *NetworkError
	if err := validate(client); !errors.As(err, &netErr) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestJitterDelayStaysWithinTheBackoffCap(t *testing.T) {
	retry := RetryOptions{BaseDelay: 100 * time.Millisecond, MaxDelay: 250 * time.Millisecond}
	for attempt := 0; attempt < 6; attempt++ {
		limit := min(retry.MaxDelay, retry.BaseDelay<<attempt)
		for i := 0; i < 50; i++ {
			if d := jitterDelay(attempt, retry); d < 0 || d > limit {
				t.Fatalf("attempt %d: delay %v outside [0, %v]", attempt, d, limit)
			}
		}
	}
}
