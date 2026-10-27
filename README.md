# licensr-go

Official Go SDK for the [Licensr](https://licensr.app) license API: validation, seat/domain activation, offline EdDSA token verification, and hosted checkout — plus a hardware ID and a token store that saves to disk, for desktop tools that must unlock offline. Go 1.22+, no third-party dependencies (offline verification uses the standard library's `crypto/ed25519`; only the conformance test uses `gopkg.in/yaml.v3`).

See the [License calls guide](https://docs.licensr.app/plugin-integration) for the underlying API's concepts (activation modes, entitlement/fallback, rate limits, the embedded-key doctrine) and the [Go SDK guide](https://docs.licensr.app/sdks/go) for the full walkthrough — this README covers the Go-specific surface.

## Install

```bash
go get github.com/tekunodev/licensr-go@latest
```

## Quickstart

```go
import licensr "github.com/tekunodev/licensr-go"

client := licensr.NewClient(licensr.Config{
	APIKey:     "pk_live_...", // Client key from Admin → Catalog → product → API keys
	PluginSlug: "my-plugin",   // product slug on that same row
})

result, err := client.Validate(ctx, licensr.ValidateRequest{LicenseKey: userEnteredKey})
switch {
case err != nil:
	// Licensr could not answer (offline, rate limited, server error): keep the previous state.
case result.Valid:
	unlockFullFeatures()
case result.Entitlement == licensr.EntitlementLimited:
	unlockDegradedMode() // perpetual-fallback: expired, but the plan grants a limited tier
}
```

The result keeps what you act on at the top level: `Valid`, `Status` (why, for your message), `Entitlement` and `FeatureFlags`. Plan and limit details are grouped under `result.License`. They are for display only; never use them to decide whether to unlock.

Desktop tools and services never send an `Origin` header: set the product's client type to **Native** in the admin UI.

## API

Every method takes a `context.Context`, blocks until it has an answer, and returns an error on failure — see [Errors](#errors). A `*Client` is safe for concurrent use.

| Method                                      | Wraps                         | Notes                                                                                                                    |
| ------------------------------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `Validate(ctx, ValidateRequest{...})`       | `POST /v1/license/validate`   | Always read `Valid`/`Entitlement`; never branch on HTTP status — an unknown key returns `200 {valid: false}`, not `404`. |
| `Token(ctx, ValidateRequest{...})`          | `POST /v1/license/token`      | Same check as `Validate`, plus a short-lived signed offline token.                                                       |
| `Activate(ctx, ActivateRequest{...})`       | `POST /v1/license/activate`   | `ActivationSeat` (per-machine) or `ActivationDomain`, fixed by the product's mode. An empty `Label` sends `null`.        |
| `Deactivate(ctx, DeactivateRequest{...})`   | `POST /v1/license/deactivate` | Frees a seat/domain slot.                                                                                                |
| `Activations(ctx, ActivationsRequest{...})` | `GET /v1/license/activations` | Lists every current activation.                                                                                          |
| `Checkout(ctx, CheckoutRequest{...})`       | `POST /v1/billing/checkout`   | Returns `CheckoutURL`. Requires a key with the `checkout` scope.                                                         |
| `LastValidated()`                           | _(no request)_                | The last successful `Validate` result, or `nil`. Never blocks — safe on a hot path.                                      |

`Config` also takes `BaseURL`, `DeviceID` (buckets rate limits per installation — pass the hardware ID), `Origin`, `Timeout` (per attempt), `Retry` (network errors / 429 / 5xx, exponential backoff + full jitter, honors `Retry-After`; default 2 retries, and delays you leave at zero keep their 300ms/5s defaults), `HTTPClient`, and `Hooks` (`OnValidated`, `OnActivated`, `OnDeactivated`, `OnTokenIssued`, `OnRetry`, `OnError`).

### Offline verification and token storage

```go
token, err := client.Token(ctx, licensr.ValidateRequest{LicenseKey: licenseKey})
jwks, err := licensr.FetchJWKS(ctx, token.Details.JWKSURL, nil)
opts := &licensr.VerifyOptions{PluginSlug: "my-plugin", JWKS: jwks}
claims, err := licensr.VerifyOfflineToken(ctx, token.Token, "", opts)

store := licensr.NewFileTokenStore("my-plugin", "") // "" = the platform's app-data folder
err = store.Set(licenseKey, licensr.CachedOfflineToken{Token: token.Token, JWKS: jwks, CachedAt: time.Now()})
// Next launch, no network: VerifyOfflineToken(ctx, cached.Token, "", &licensr.VerifyOptions{PluginSlug: "my-plugin", JWKS: cached.JWKS})
```

- **Always set `VerifyOptions.PluginSlug`.** Every product in a store is signed with the same key, so without it one product's token also verifies for another.
- Without `VerifyOptions.JWKS`, the key set is downloaded from the URL (10s timeout), cached for the process lifetime, and downloaded again on an unknown `kid`; `ClearJWKSCache` forces a fresh download.
- Offline tokens carry no revocation signal — re-validate online before `claims.Exp`.
- `CachedOfflineToken` deliberately holds no claims (a file can be edited); re-verify to read them. `NewFileTokenStore` uses the same folders as the C++ SDK's `FileTokenStore` (with a `.json` extension, so the two never collide); `NewMemoryTokenStore` doesn't survive a restart; implement `TokenStore` for your own storage.

### Hardware IDs

`ComputeHardwareID(salt)` returns `sha256(salt + machine ID)` as lowercase hex — `IOPlatformUUID` on macOS, `MachineGuid` + system volume serial on Windows, `/etc/machine-id` on Linux. It matches the C++ SDK's `compute_hardware_id` byte for byte. On failure (a locked-down sandbox, an unsupported OS) it returns an error wrapping `ErrHardwareIDUnavailable`; fall back to a persisted random UUID.

### Errors

| Error                     | When                                                                                                                         |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `*APIError`               | Non-2xx response. `Status`, `Code` (the `Code*` constants), `Message`, `RetryAfter`. Branch on `Code`.                       |
| `*NetworkError`           | No response at all (network failure, timeout, cancelled context, retries exhausted). Unwraps to the cause.                   |
| `*TokenVerificationError` | The token was rejected (signature, algorithm, product, expiry), or the key set couldn't be downloaded. Unwraps to the cause. |

[`examples/cli`](examples/cli) puts it all together: unlock from a saved token when there is one, otherwise validate, activate this computer, and save a fresh token.

## Development

```bash
go test -race ./...
go vet ./...
gofmt -l .
go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 ./...
```

### Conformance suite

`conformance_test.go` runs every case in [`contract/conformance.yaml`](../../contract/README.md) against a real, running backend — the same contract `backend/tests/test_conformance_contract.py` and the other SDKs' runners enforce. It's skipped by default (no live backend in a normal `go test` run); to run it locally:

```bash
# 1. Start Postgres + migrate (from repo root)
docker compose up -d postgres
cd backend && APP_ENV=dev poetry run alembic upgrade head

# 2. Start the backend (BILLING_PROVIDER=mock avoids needing real Stripe creds)
APP_ENV=dev BILLING_PROVIDER=mock poetry run uvicorn main:app --port 8080

# 3. Seed fixtures for every case (in another shell)
poetry run python scripts/seed_conformance_fixtures.py --out /tmp/conformance_fixtures.json

# 4. Run the conformance suite (from sdks/go)
cd ../sdks/go
CONFORMANCE_BASE_URL=http://localhost:8080 \
CONFORMANCE_FIXTURES_PATH=/tmp/conformance_fixtures.json \
go test -run 'TestConformance$' -v ./...
```

The `rate_limit_exceeded` case additionally requires `CONFORMANCE_RUN_SLOW=1` (it fires 61 requests to trip the bucket) — a plain local run skips just that one case. See `.github/workflows/test-sdk-go.yaml` for how CI wires up the same four steps as one job.

## Releasing

There is no version file: tag `go/vX.Y.Z` on `main` and push the tag (mirrors to [github.com/tekunodev/licensr-go](https://github.com/tekunodev/licensr-go) as `vX.Y.Z`, which is what `go get` resolves). Never re-tag a published Go version — the Go checksum database pins it forever. Step-by-step: [`docs/SDK_PROGRAM.md` §2](../../docs/SDK_PROGRAM.md#2-releasing-an-sdk-update) or [`sdks/RELEASING.md`](../RELEASING.md).
