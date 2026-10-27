// Command cli is a minimal end-to-end Licensr integration for a Go CLI or
// service: boot from a cached offline token when there is one, otherwise
// validate online, activate this machine's seat, and cache a fresh token.
//
//	LICENSR_API_KEY=pk_live_... LICENSR_PLUGIN_SLUG=my-plugin go run ./examples/cli lic_...
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	licensr "github.com/tekunodev/licensr-go"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: cli <license-key>")
		os.Exit(2)
	}
	if err := run(context.Background(), os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, licenseKey string) error {
	slug := os.Getenv("LICENSR_PLUGIN_SLUG")
	hwid, err := licensr.ComputeHardwareID(slug)
	if err != nil {
		return err // A real app would fall back to a persisted random UUID.
	}
	client := licensr.NewClient(licensr.Config{
		APIKey:     os.Getenv("LICENSR_API_KEY"),
		PluginSlug: slug,
		BaseURL:    os.Getenv("LICENSR_BASE_URL"), // Empty means https://api.licensr.app.
		DeviceID:   hwid,
		Timeout:    10 * time.Second,
	})
	store := licensr.NewFileTokenStore(slug, os.Getenv("LICENSR_TOKEN_DIR"))

	// 1. Offline first: a cached token still inside its validity window
	// unlocks with no network at all — its key set was saved with it.
	if cached, err := store.Get(licenseKey); err == nil && cached != nil {
		opts := &licensr.VerifyOptions{PluginSlug: slug, JWKS: cached.JWKS}
		if claims, err := licensr.VerifyOfflineToken(ctx, cached.Token, "", opts); err == nil && claims.Valid {
			fmt.Printf("unlocked offline (%s, token cached %s)\n", claims.Entitlement, cached.CachedAt.Format(time.RFC3339))
			return nil
		}
	}

	// 2. Online: validate, then activate this machine's seat.
	result, err := client.Validate(ctx, licensr.ValidateRequest{LicenseKey: licenseKey})
	if err != nil {
		return err
	}
	if !result.Valid {
		return fmt.Errorf("license is %s", result.Status)
	}
	_, err = client.Activate(ctx, licensr.ActivateRequest{
		LicenseKey: licenseKey, ActivationType: licensr.ActivationSeat, Identifier: hwid, Label: "Go CLI example",
	})
	var apiErr *licensr.APIError
	if errors.As(err, &apiErr) && apiErr.Code == licensr.CodeActivationCapExceeded {
		return errors.New("all seats are in use — deactivate another machine first")
	}
	if err != nil {
		return err
	}

	// 3. Cache a fresh offline token for the next launch.
	token, err := client.Token(ctx, licensr.ValidateRequest{LicenseKey: licenseKey})
	if err != nil {
		return err
	}
	jwks, err := licensr.FetchJWKS(ctx, token.Details.JWKSURL, nil)
	if err != nil {
		return err
	}
	if _, err := licensr.VerifyOfflineToken(ctx, token.Token, "", &licensr.VerifyOptions{PluginSlug: slug, JWKS: jwks}); err != nil {
		return err
	}
	if err := store.Set(licenseKey, licensr.CachedOfflineToken{Token: token.Token, JWKS: jwks, CachedAt: time.Now()}); err != nil {
		return err
	}
	fmt.Printf("unlocked online (%s); offline token cached until %s\n", result.Entitlement, token.Details.ExpiresAt)
	return nil
}
