package licensr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DeviceIDHeader carries Config.DeviceID. SDKs already compute a stable
// per-machine HWID for activation — send it here for free so the server
// buckets rate limits per installation rather than per API key (see
// backend/services/rate_limit_key.py).
const DeviceIDHeader = "X-Licensr-Device-Id"

// RetryOptions controls retries on network errors, 429 and 5xx responses.
type RetryOptions struct {
	// Extra attempts after the first. Default 2.
	MaxRetries int
	// Base delay for exponential backoff with full jitter. Default 300ms.
	BaseDelay time.Duration
	// Ceiling for the backoff delay. Default 5s.
	MaxDelay time.Duration
}

// DefaultRetry is used when Config.Retry is nil.
var DefaultRetry = RetryOptions{MaxRetries: 2, BaseDelay: 300 * time.Millisecond, MaxDelay: 5 * time.Second}

type requestSpec struct {
	method string
	path   string
	query  url.Values
	body   any
	// Called right before each retry's backoff delay — wired to Hooks.OnRetry.
	onRetry func(attempt int, delay time.Duration)
}

type response struct {
	status int
	header http.Header
	body   []byte
}

// jitterDelay is exponential backoff with full jitter (AWS-style): random(0, min(max, base * 2^attempt)).
func jitterDelay(attempt int, retry RetryOptions) time.Duration {
	limit := math.Min(float64(retry.MaxDelay), float64(retry.BaseDelay)*math.Pow(2, float64(attempt)))
	return time.Duration(rand.Float64() * limit)
}

func parseRetryAfter(header string) (time.Duration, bool) {
	if header == "" {
		return 0, false
	}
	seconds, err := strconv.ParseFloat(header, 64)
	if err != nil || seconds < 0 || math.IsInf(seconds, 0) || math.IsNaN(seconds) {
		return 0, false
	}
	return time.Duration(seconds * float64(time.Second)), true
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func parseErrorDetail(resp response) (code, message string) {
	fallback := http.StatusText(resp.status)
	if fallback == "" {
		fallback = fmt.Sprintf("HTTP %d", resp.status)
	}
	var body struct {
		Detail json.RawMessage `json:"detail"`
	}
	if json.Unmarshal(resp.body, &body) != nil {
		return CodeUnknownError, fallback
	}

	// {"detail": {"error": "...", "message": "..."}} — every hand-written
	// HTTPException in the license/billing routers uses this shape.
	var detail struct {
		Error   *string `json:"error"`
		Message *string `json:"message"`
	}
	if json.Unmarshal(body.Detail, &detail) == nil && detail.Error != nil {
		if detail.Message != nil {
			return *detail.Error, *detail.Message
		}
		return *detail.Error, fallback
	}

	// {"detail": [{"msg": "...", "loc": [...]}, ...]} — FastAPI/Pydantic's
	// own 422 shape for request validation errors, not a hand-written one.
	var list []struct {
		Msg *string `json:"msg"`
	}
	if json.Unmarshal(body.Detail, &list) == nil && len(list) > 0 {
		if list[0].Msg != nil {
			return CodeValidationError, *list[0].Msg
		}
		return CodeValidationError, "Request validation failed"
	}

	return CodeUnknownError, fallback
}

// do performs one logical API call, retrying network errors / 429 / 5xx
// with exponential backoff + jitter, and honouring a Retry-After header
// when present. Returns *APIError for any other non-2xx response, or
// *NetworkError once retries are exhausted or ctx is done.
func (c *Client) do(ctx context.Context, spec requestSpec, out any) error {
	u := strings.TrimSuffix(c.cfg.BaseURL, "/") + "/" + spec.path
	if len(spec.query) > 0 {
		u += "?" + spec.query.Encode()
	}
	var payload []byte
	if spec.body != nil {
		var err error
		if payload, err = json.Marshal(spec.body); err != nil {
			return err
		}
	}
	networkError := func(attempts int, cause error) error {
		return &NetworkError{Message: fmt.Sprintf("request to %s failed after %d attempt(s)", spec.path, attempts), Cause: cause}
	}

	for attempt := 0; ; attempt++ {
		resp, err := c.send(ctx, spec.method, u, payload)
		retriable := err != nil || resp.status == http.StatusTooManyRequests || resp.status >= 500
		if retriable && attempt < c.retry.MaxRetries && ctx.Err() == nil {
			delay, ok := time.Duration(0), false
			if err == nil {
				delay, ok = parseRetryAfter(resp.header.Get("Retry-After"))
			}
			if !ok {
				delay = jitterDelay(attempt, c.retry)
			}
			if spec.onRetry != nil {
				spec.onRetry(attempt+1, delay)
			}
			if sleepErr := sleep(ctx, delay); sleepErr != nil {
				return networkError(attempt+1, sleepErr)
			}
			continue
		}
		if err != nil {
			return networkError(attempt+1, err)
		}

		if resp.status >= 200 && resp.status < 300 {
			if out == nil || len(resp.body) == 0 {
				return nil
			}
			return json.Unmarshal(resp.body, out)
		}

		code, message := parseErrorDetail(resp)
		retryAfter, _ := parseRetryAfter(resp.header.Get("Retry-After"))
		return &APIError{Status: resp.status, Code: code, Message: message, RetryAfter: retryAfter}
	}
}

// send makes one attempt and reads the whole body, so Config.Timeout
// covers the response body as well as the headers.
func (c *Client) send(ctx context.Context, method, u string, payload []byte) (response, error) {
	if c.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.cfg.Timeout)
		defer cancel()
	}
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return response{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cfg.DeviceID != "" {
		req.Header.Set(DeviceIDHeader, c.cfg.DeviceID)
	}
	if c.cfg.Origin != "" {
		req.Header.Set("Origin", c.cfg.Origin)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return response{}, err
	}
	return response{status: resp.StatusCode, header: resp.Header, body: data}, nil
}
