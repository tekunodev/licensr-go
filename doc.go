// Package licensr is the official Go SDK for the Licensr license API:
// validation, seat/domain activation, offline EdDSA token verification,
// hardware IDs and token caching.
//
//	client := licensr.NewClient(licensr.Config{APIKey: "pk_live_...", PluginSlug: "my-plugin"})
//	result, err := client.Validate(ctx, licensr.ValidateRequest{LicenseKey: key})
//	var apiErr *licensr.APIError
//	switch {
//	case errors.As(err, &apiErr): // The API said no — branch on apiErr.Code.
//	case err != nil: // *licensr.NetworkError: no response at all.
//	case result.Valid: // Unlock the product.
//	}
//
// See https://docs.licensr.app/sdks/go.
package licensr
