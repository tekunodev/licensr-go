package licensr

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type signingKey struct {
	kid     string
	private ed25519.PrivateKey
}

func newSigningKey(t *testing.T, kid string) signingKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signingKey{kid: kid, private: private}
}

func (k signingKey) jwk() map[string]string {
	public := k.private.Public().(ed25519.PublicKey)
	return map[string]string{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": k.kid, "x": base64.RawURLEncoding.EncodeToString(public)}
}

func b64JSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func (k signingKey) sign(t *testing.T, alg string, claims map[string]any) string {
	t.Helper()
	input := b64JSON(t, map[string]string{"alg": alg, "kid": k.kid, "typ": "JWT"}) + "." + b64JSON(t, claims)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.private, []byte(input)))
}

func claimsFor(offset time.Duration) map[string]any {
	now := time.Now().Add(offset).Unix()
	return map[string]any{
		"sub": "lic-1", "iss": "https://api.licensr.app", "iat": now, "nbf": now, "exp": now + 3600,
		"plugin_slug": "demo-plugin", "plan_id": "plan-1", "status": "active", "valid": true,
		"entitlement": "full", "fallback": false, "activation_mode": "seat", "max_seats": 5,
		"max_domains": nil, "license_expires_at": nil, "feature_flags": map[string]any{"pro": true},
	}
}

// serveJWKS publishes keys at a fresh URL and counts fetches.
func serveJWKS(t *testing.T, keys ...signingKey) (string, *atomic.Int32) {
	t.Helper()
	t.Cleanup(ClearJWKSCache)
	var fetches atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		set := map[string]any{"keys": []map[string]string{}}
		for _, k := range keys {
			set["keys"] = append(set["keys"].([]map[string]string), k.jwk())
		}
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(server.Close)
	return server.URL + "/v1/license/jwks/acme/demo-plugin.json", &fetches
}

func expectVerificationError(t *testing.T, err error, contains string) {
	t.Helper()
	var verr *TokenVerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("err = %v, want *TokenVerificationError", err)
	}
	if !strings.Contains(verr.Message, contains) {
		t.Errorf("message = %q, want it to mention %q", verr.Message, contains)
	}
}

func TestVerifiesAGenuineEdDSAToken(t *testing.T) {
	key := newSigningKey(t, "kid-1")
	jwksURL, _ := serveJWKS(t, key)

	claims, err := VerifyOfflineToken(context.Background(), key.sign(t, "EdDSA", claimsFor(0)), jwksURL, nil)
	if err != nil {
		t.Fatal(err)
	}

	if claims.Sub != "lic-1" || !claims.Valid || claims.Status != StatusActive || *claims.MaxSeats != 5 {
		t.Errorf("unexpected claims %+v", claims)
	}
	if claims.FeatureFlags["pro"] != true || claims.MaxDomains != nil {
		t.Errorf("unexpected optional claims %+v", claims)
	}
}

func TestRejectsATokenSignedByAKeyNotInTheJWKS(t *testing.T) {
	jwksURL, _ := serveJWKS(t, newSigningKey(t, "kid-1"))
	stranger := newSigningKey(t, "kid-unknown")

	_, err := VerifyOfflineToken(context.Background(), stranger.sign(t, "EdDSA", claimsFor(0)), jwksURL, nil)

	expectVerificationError(t, err, `no key with kid "kid-unknown"`)
}

func TestRejectsAForgedSignatureUnderAKnownKid(t *testing.T) {
	jwksURL, _ := serveJWKS(t, newSigningKey(t, "kid-1"))
	forger := newSigningKey(t, "kid-1") // Same kid, different private key.

	_, err := VerifyOfflineToken(context.Background(), forger.sign(t, "EdDSA", claimsFor(0)), jwksURL, nil)

	expectVerificationError(t, err, "signature verification failed")
}

func TestRejectsATamperedPayload(t *testing.T) {
	key := newSigningKey(t, "kid-1")
	jwksURL, _ := serveJWKS(t, key)
	parts := strings.Split(key.sign(t, "EdDSA", claimsFor(0)), ".")
	forged := claimsFor(0)
	forged["max_seats"] = 500
	parts[1] = b64JSON(t, forged)

	_, err := VerifyOfflineToken(context.Background(), strings.Join(parts, "."), jwksURL, nil)

	expectVerificationError(t, err, "signature verification failed")
}

func TestRejectsAnExpiredToken(t *testing.T) {
	key := newSigningKey(t, "kid-1")
	jwksURL, _ := serveJWKS(t, key)

	_, err := VerifyOfflineToken(context.Background(), key.sign(t, "EdDSA", claimsFor(-2*time.Hour)), jwksURL, nil)

	expectVerificationError(t, err, "expired")
}

func TestRejectsANotYetValidTokenButToleratesClockSkew(t *testing.T) {
	key := newSigningKey(t, "kid-1")
	jwksURL, _ := serveJWKS(t, key)

	_, err := VerifyOfflineToken(context.Background(), key.sign(t, "EdDSA", claimsFor(10*time.Minute)), jwksURL, nil)
	expectVerificationError(t, err, "not yet valid")

	if _, err := VerifyOfflineToken(context.Background(), key.sign(t, "EdDSA", claimsFor(30*time.Second)), jwksURL, nil); err != nil {
		t.Errorf("30s of skew is within the default 60s tolerance: %v", err)
	}
	opts := &VerifyOptions{ClockTolerance: 15 * time.Minute}
	if _, err := VerifyOfflineToken(context.Background(), key.sign(t, "EdDSA", claimsFor(10*time.Minute)), jwksURL, opts); err != nil {
		t.Errorf("ClockTolerance should widen the window: %v", err)
	}
}

func TestRejectsANonEdDSAAlgorithm(t *testing.T) {
	key := newSigningKey(t, "kid-1")
	jwksURL, fetches := serveJWKS(t, key)

	_, err := VerifyOfflineToken(context.Background(), key.sign(t, "none", claimsFor(0)), jwksURL, nil)

	expectVerificationError(t, err, `unsupported alg "none"`)
	if fetches.Load() != 0 {
		t.Error("a wrong alg should be rejected before fetching the JWKS")
	}
}

func TestRejectsAMalformedToken(t *testing.T) {
	jwksURL, _ := serveJWKS(t)

	_, err := VerifyOfflineToken(context.Background(), "not-a-jwt", jwksURL, nil)

	expectVerificationError(t, err, "malformed compact JWS")
}

func TestReportsAJWKSFetchFailure(t *testing.T) {
	key := newSigningKey(t, "kid-1")
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	_, err := VerifyOfflineToken(context.Background(), key.sign(t, "EdDSA", claimsFor(0)), server.URL, nil)

	expectVerificationError(t, err, "HTTP 404")
}

func TestCachesTheJWKSAndRefetchesOnAnUnknownKid(t *testing.T) {
	key := newSigningKey(t, "kid-1")
	jwksURL, fetches := serveJWKS(t, key)
	token := key.sign(t, "EdDSA", claimsFor(0))

	for i := 0; i < 3; i++ {
		if _, err := VerifyOfflineToken(context.Background(), token, jwksURL, nil); err != nil {
			t.Fatal(err)
		}
	}
	if fetches.Load() != 1 {
		t.Errorf("fetches = %d after 3 verifications, want 1", fetches.Load())
	}

	_, _ = VerifyOfflineToken(context.Background(), newSigningKey(t, "kid-rotated").sign(t, "EdDSA", claimsFor(0)), jwksURL, nil)
	if fetches.Load() != 2 {
		t.Errorf("fetches = %d, an unknown kid should refetch once", fetches.Load())
	}

	ClearJWKSCache()
	if _, err := VerifyOfflineToken(context.Background(), token, jwksURL, nil); err != nil {
		t.Fatal(err)
	}
	if fetches.Load() != 3 {
		t.Errorf("fetches = %d, ClearJWKSCache should force a fresh fetch", fetches.Load())
	}
}

func TestRejectsATokenForAnotherProductWhenPluginSlugIsSet(t *testing.T) {
	// Every product in a store is signed with the same key, so only the
	// plugin_slug claim tells product A's token from product B's.
	key := newSigningKey(t, "kid-1")
	jwksURL, _ := serveJWKS(t, key)
	token := key.sign(t, "EdDSA", claimsFor(0)) // plugin_slug: demo-plugin

	_, err := VerifyOfflineToken(context.Background(), token, jwksURL, &VerifyOptions{PluginSlug: "pricier-plugin"})
	expectVerificationError(t, err, `token is for product "demo-plugin", not "pricier-plugin"`)

	if _, err := VerifyOfflineToken(context.Background(), token, jwksURL, &VerifyOptions{PluginSlug: "demo-plugin"}); err != nil {
		t.Errorf("matching PluginSlug should verify: %v", err)
	}
}

func TestVerifiesWithASavedJWKSAndNoNetwork(t *testing.T) {
	key := newSigningKey(t, "kid-1")
	jwksURL, fetches := serveJWKS(t, key)
	jwks, err := FetchJWKS(context.Background(), jwksURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	ClearJWKSCache() // A fresh launch: nothing cached in memory.

	claims, err := VerifyOfflineToken(context.Background(), key.sign(t, "EdDSA", claimsFor(0)), "http://127.0.0.1:1/unreachable.json",
		&VerifyOptions{JWKS: jwks})

	if err != nil || claims.Sub != "lic-1" {
		t.Fatalf("claims = %+v, err = %v", claims, err)
	}
	if fetches.Load() != 1 {
		t.Errorf("fetches = %d, a saved JWKS must not be downloaded again", fetches.Load())
	}
}

func TestFetchJWKSWarmsTheCache(t *testing.T) {
	key := newSigningKey(t, "kid-1")
	jwksURL, fetches := serveJWKS(t, key)

	if _, err := FetchJWKS(context.Background(), jwksURL, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOfflineToken(context.Background(), key.sign(t, "EdDSA", claimsFor(0)), jwksURL, nil); err != nil {
		t.Fatal(err)
	}
	if fetches.Load() != 1 {
		t.Errorf("fetches = %d, want 1", fetches.Load())
	}
}

func TestAJWKSDownloadFailureUnwrapsToItsCause(t *testing.T) {
	key := newSigningKey(t, "kid-1")
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := VerifyOfflineToken(ctx, key.sign(t, "EdDSA", claimsFor(0)), server.URL, nil)

	// An app can tell "couldn't reach Licensr" (keep the last state) from a forged token (lock).
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want it to unwrap to context.DeadlineExceeded", err)
	}
	if _, err := FetchJWKS(ctx, server.URL, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("FetchJWKS err = %v, want it to unwrap to context.DeadlineExceeded", err)
	}
}

func TestRejectsUnusableKeysAndHeaders(t *testing.T) {
	key := newSigningKey(t, "kid-1")
	token := key.sign(t, "EdDSA", claimsFor(0))
	good := key.jwk()
	cases := map[string]struct {
		jwk      map[string]string
		token    string
		contains string
	}{
		"not an Ed25519 key": {jwk: map[string]string{"kty": "RSA", "kid": "kid-1", "x": good["x"]}, token: token, contains: "expected OKP/Ed25519"},
		"short public key":   {jwk: map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": "kid-1", "x": "AAAA"}, token: token, contains: "not a 32-byte Ed25519 key"},
		"missing kid": {jwk: good, contains: "missing 'kid'",
			token: b64JSON(t, map[string]string{"alg": "EdDSA"}) + "." + b64JSON(t, claimsFor(0)) + ".sig"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			jwks, _ := json.Marshal(map[string]any{"keys": []map[string]string{tc.jwk}})

			_, err := VerifyOfflineToken(context.Background(), tc.token, "", &VerifyOptions{JWKS: jwks})

			expectVerificationError(t, err, tc.contains)
		})
	}
}

func TestVerifiesConcurrentlyAgainstOneCache(t *testing.T) {
	key := newSigningKey(t, "kid-1")
	jwksURL, _ := serveJWKS(t, key)
	token := key.sign(t, "EdDSA", claimsFor(0))

	errs := make(chan error, 8)
	for i := 0; i < cap(errs); i++ {
		go func() {
			_, err := VerifyOfflineToken(context.Background(), token, jwksURL, nil)
			errs <- err
		}()
	}
	for i := 0; i < cap(errs); i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
}
