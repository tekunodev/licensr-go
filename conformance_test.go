package licensr

// Go conformance runner for contract/conformance.yaml.
//
// Mirrors backend/tests/test_conformance_contract.py case-for-case against
// a *running* backend (raw net/http, not Client — a few cases exercise
// things the client intentionally doesn't expose, like a missing
// Authorization header or a deprecated path). See contract/README.md for
// how to start the backend and produce the fixtures file this reads.
//
// Skipped by default: requires CONFORMANCE_BASE_URL (the running backend)
// and CONFORMANCE_FIXTURES_PATH (JSON from
// backend/scripts/seed_conformance_fixtures.py), matching the other
// runners' own opt-in.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type conformanceCase struct {
	ID      string `yaml:"id"`
	Request struct {
		Method string `yaml:"method"`
		Path   string `yaml:"path"`
		Auth   string `yaml:"auth"`
		Origin string `yaml:"origin"`
		Body   any    `yaml:"body"`
		Repeat int    `yaml:"repeat"`
	} `yaml:"request"`
	Expect struct {
		Status int            `yaml:"status"`
		JSON   map[string]any `yaml:"json"`
	} `yaml:"expect"`
}

type fixtureValues map[string]string

const conformanceYAMLPath = "../../contract/conformance.yaml"

func loadConformanceCases(t *testing.T) []conformanceCase {
	t.Helper()
	data, err := os.ReadFile(conformanceYAMLPath)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Cases []conformanceCase `yaml:"cases"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	return document.Cases
}

func loadFixtures(t *testing.T, path string) map[string]fixtureValues {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixtures map[string]fixtureValues
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}

// resolvePlaceholders recursively substitutes ${name} placeholders — mirrors _resolve in the Python runner.
func resolvePlaceholders(value any, values fixtureValues) any {
	switch v := value.(type) {
	case string:
		for key, replacement := range values {
			v = strings.ReplaceAll(v, "${"+key+"}", replacement)
		}
		return v
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = resolvePlaceholders(item, values)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = resolvePlaceholders(item, values)
		}
		return out
	}
	return value
}

// getPath reads a dotted path like detail.error or keys.0.kty out of a parsed JSON body.
func getPath(t *testing.T, obj any, dotted string) any {
	t.Helper()
	current := obj
	for _, part := range strings.Split(dotted, ".") {
		switch c := current.(type) {
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i >= len(c) {
				t.Fatalf("cannot index %s into %v (from path %s)", part, c, dotted)
			}
			current = c[i]
		case map[string]any:
			current = c[part]
		default:
			t.Fatalf("cannot descend into %s of %v (from path %s)", part, current, dotted)
		}
	}
	return current
}

// normalizeJSON round-trips a YAML-decoded value through JSON so ints
// compare equal to the float64s encoding/json produces.
func normalizeJSON(t *testing.T, v any) any {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func sendConformanceRequest(t *testing.T, baseURL string, c conformanceCase, values fixtureValues) *http.Response {
	t.Helper()
	path := resolvePlaceholders(c.Request.Path, values).(string)
	var body io.Reader
	if c.Request.Method == http.MethodPost {
		resolved := resolvePlaceholders(c.Request.Body, values)
		if resolved == nil {
			resolved = map[string]any{}
		}
		data, err := json.Marshal(resolved)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(c.Request.Method, strings.TrimSuffix(baseURL, "/")+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	switch c.Request.Auth {
	case "invalid":
		req.Header.Set("Authorization", "Bearer pk_live_00000000000000000000000000")
	case "valid_api_key", "revoked":
		req.Header.Set("Authorization", "Bearer "+values["api_key"])
	}
	switch c.Request.Origin {
	case "allowed":
		req.Header.Set("Origin", values["_allowed_origin"])
	case "disallowed":
		req.Header.Set("Origin", "https://evil.example")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestConformance(t *testing.T) {
	baseURL := os.Getenv("CONFORMANCE_BASE_URL")
	fixturesPath := os.Getenv("CONFORMANCE_FIXTURES_PATH")
	if baseURL == "" || fixturesPath == "" {
		t.Skip("set CONFORMANCE_BASE_URL and CONFORMANCE_FIXTURES_PATH to run against a live backend")
	}
	fixtures := loadFixtures(t, fixturesPath)
	runSlow := os.Getenv("CONFORMANCE_RUN_SLOW") != ""

	for _, c := range loadConformanceCases(t) {
		t.Run(c.ID, func(t *testing.T) {
			if c.ID == "rate_limit_exceeded" && !runSlow {
				t.Skip("slow: set CONFORMANCE_RUN_SLOW=1")
			}
			values, ok := fixtures[c.ID]
			if !ok {
				t.Fatalf("no seeded fixtures for case %s — re-run seed_conformance_fixtures.py", c.ID)
			}

			var resp *http.Response
			for i := 0; i < max(c.Request.Repeat, 1); i++ {
				if resp != nil {
					resp.Body.Close()
				}
				resp = sendConformanceRequest(t, baseURL, c, values)
			}
			defer resp.Body.Close()

			if resp.StatusCode != c.Expect.Status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, c.Expect.Status)
			}
			var body any
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			for dotted, expected := range c.Expect.JSON {
				if got, want := getPath(t, body, dotted), normalizeJSON(t, expected); !reflect.DeepEqual(got, want) {
					t.Errorf("%s = %v, want %v", dotted, got, want)
				}
			}
		})
	}
}

// The case list itself is checked on every monorepo run, live backend or
// not, so a conformance.yaml edit this runner can't parse fails fast. The
// public mirror ships without contract/, so it skips there.
func TestConformanceCasesParse(t *testing.T) {
	if _, err := os.Stat(conformanceYAMLPath); err != nil {
		t.Skip("contract/conformance.yaml is only in the monorepo")
	}
	cases := loadConformanceCases(t)
	if len(cases) == 0 {
		t.Fatal("no cases in contract/conformance.yaml")
	}
	for _, c := range cases {
		if c.ID == "" || c.Request.Method == "" || c.Request.Path == "" || c.Expect.Status == 0 {
			t.Errorf("incomplete case %+v", c)
		}
	}
}
