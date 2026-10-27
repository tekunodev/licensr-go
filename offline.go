package licensr

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// VerifyOptions tunes VerifyOfflineToken. A nil *VerifyOptions uses the defaults.
type VerifyOptions struct {
	// Used for the JWKS lookup. Defaults to http.DefaultClient.
	HTTPClient *http.Client
	// Accept exp/nbf this far past/before now (clock skew tolerance). Zero means 60s.
	ClockTolerance time.Duration
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	// Base64url-encoded raw 32-byte Ed25519 public key.
	X   string `json:"x"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

// A plugin's signing key is essentially never rotated mid-process, so a
// process-lifetime cache (refreshed once on an unrecognized kid, in case it
// *was* rotated) avoids a JWKS fetch on every verification — mirrors the
// JS and C# SDKs' caches.
var jwksCache sync.Map // jwksURL → []jwk

// ClearJWKSCache drops cached JWKS lookups — call after rotating a plugin's
// signing key in tests, or to force a fresh fetch.
func ClearJWKSCache() {
	jwksCache.Range(func(key, _ any) bool {
		jwksCache.Delete(key)
		return true
	})
}

// VerifyOfflineToken verifies an offline license token (from Client.Token)
// fully offline: no network call beyond fetching (and caching) the
// plugin's public JWKS. Returns a *TokenVerificationError on a bad
// signature, wrong algorithm, or an expired/not-yet-valid token.
//
// Tokens carry no revocation signal — this only proves the token was
// genuinely issued by Licensr and hasn't expired, not that the license is
// still active right now. Re-validate online (Validate/Token) before the
// token's exp.
func VerifyOfflineToken(ctx context.Context, token, jwksURL string, opts *VerifyOptions) (*OfflineTokenClaims, error) {
	if opts == nil {
		opts = &VerifyOptions{}
	}
	claims, err := verifyOfflineToken(ctx, token, jwksURL, opts)
	if err != nil {
		return nil, &TokenVerificationError{Message: "offline token verification failed: " + err.Error()}
	}
	return claims, nil
}

func verifyOfflineToken(ctx context.Context, token, jwksURL string, opts *VerifyOptions) (*OfflineTokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed compact JWS (expected 3 dot-separated parts)")
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, fmt.Errorf("bad header: %w", err)
	}
	if header.Alg != "EdDSA" {
		return nil, fmt.Errorf("unsupported alg %q (expected EdDSA)", header.Alg)
	}
	if header.Kid == "" {
		return nil, errors.New("token header is missing 'kid'")
	}

	key, err := findKey(ctx, jwksURL, header.Kid, opts.HTTPClient)
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("bad signature encoding: %w", err)
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		return nil, errors.New("signature verification failed")
	}

	var claims OfflineTokenClaims
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, fmt.Errorf("bad payload: %w", err)
	}
	tolerance := int64(opts.ClockTolerance / time.Second)
	if opts.ClockTolerance == 0 {
		tolerance = 60
	}
	now := time.Now().Unix()
	if claims.Exp+tolerance < now {
		return nil, errors.New("token has expired")
	}
	if claims.Nbf-tolerance > now {
		return nil, errors.New("token is not yet valid ('nbf' is in the future)")
	}
	return &claims, nil
}

func decodeSegment(segment string, out any) error {
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func findKey(ctx context.Context, jwksURL, kid string, client *http.Client) (ed25519.PublicKey, error) {
	keys, _ := jwksCache.Load(jwksURL)
	match := findKid(keys, kid)
	if match == nil {
		// Unknown kid (first lookup, or a rotation since we last cached) — (re)fetch once.
		fetched, err := fetchJWKS(ctx, jwksURL, client)
		if err != nil {
			return nil, err
		}
		jwksCache.Store(jwksURL, fetched)
		match = findKid(fetched, kid)
	}
	if match == nil {
		return nil, fmt.Errorf("no key with kid %q in JWKS at %s", kid, jwksURL)
	}
	if match.Kty != "OKP" || match.Crv != "Ed25519" {
		return nil, fmt.Errorf("key %q is %s/%s, expected OKP/Ed25519", kid, match.Kty, match.Crv)
	}
	key, err := base64.RawURLEncoding.DecodeString(match.X)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("JWK 'x' for %q is not a %d-byte Ed25519 key", kid, ed25519.PublicKeySize)
	}
	return key, nil
}

func findKid(keys any, kid string) *jwk {
	list, _ := keys.([]jwk)
	for i := range list {
		if list[i].Kid == kid {
			return &list[i]
		}
	}
	return nil
}

func fetchJWKS(ctx context.Context, jwksURL string, client *http.Client) ([]jwk, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: HTTP %d", jwksURL, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("JWKS response from %s is not valid JSON: %w", jwksURL, err)
	}
	return set.Keys, nil
}
