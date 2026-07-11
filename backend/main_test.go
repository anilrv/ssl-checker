package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"
)

func doCheck(t *testing.T, host string) CheckResult {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/checkssl?host="+host+"&force=1", nil)
	req.Header.Set("Origin", "chrome-extension://abcdefghijklmnopabcdefghijklmnop")
	rec := httptest.NewRecorder()
	checkSSLHandler(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "chrome-extension://abcdefghijklmnopabcdefghijklmnop" {
		t.Errorf("CORS header not echoed correctly, got %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}

	var result CheckResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("bad JSON for host %s: %v\nbody: %s", host, err, rec.Body.String())
	}
	t.Logf("%s -> org=%q issuerOrg=%q protocol=%q issues=%v error=%q",
		host, result.Org, result.IssuerOrg, result.Protocol, result.Issues, result.Error)
	return result
}

func TestHandlerRealSites(t *testing.T) {
	cases := []struct {
		host        string
		wantIssue   string
		wantNoIssue string
	}{
		{host: "github.com", wantNoIssue: "expired"},
		{host: "expired.badssl.com", wantIssue: "expired"},
		{host: "self-signed.badssl.com", wantIssue: "self-signed"},
		{host: "wrong.host.badssl.com", wantIssue: "hostname-mismatch"},
	}
	for _, c := range cases {
		result := doCheck(t, c.host)
		if result.Error != "" {
			t.Errorf("%s: unexpected error: %s", c.host, result.Error)
		}
		if c.wantIssue != "" && !contains(result.Issues, c.wantIssue) {
			t.Errorf("%s: expected issue %q, got %v", c.host, c.wantIssue, result.Issues)
		}
		if c.wantNoIssue != "" && contains(result.Issues, c.wantNoIssue) {
			t.Errorf("%s: unexpected issue %q present in %v", c.host, c.wantNoIssue, result.Issues)
		}
	}
}

func TestHandlerInvalidHost(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/checkssl?host="+url.QueryEscape("not a hostname!!"), nil)
	rec := httptest.NewRecorder()
	checkSSLHandler(rec, req)
	if rec.Code != 400 {
		t.Errorf("expected 400 for invalid host, got %d", rec.Code)
	}
}

func TestHandlerSSRFBlocked(t *testing.T) {
	result := doCheck(t, "localhost")
	if result.Error == "" {
		t.Errorf("expected localhost to be blocked/fail, got clean result: %+v", result)
	}
}

func TestRateLimit(t *testing.T) {
	rl := newRateLimiter()
	allowed := 0
	for i := 0; i < 25; i++ {
		if rl.Allow("1.2.3.4", 20, 60_000_000_000) { // 1 minute in ns
			allowed++
		}
	}
	if allowed != 20 {
		t.Errorf("expected exactly 20 allowed requests, got %d", allowed)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
