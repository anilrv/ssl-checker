package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"sslcheckerfunc/certprobe"
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

func TestClientIPFromXFF(t *testing.T) {
	cases := []struct {
		xff  string
		want string
	}{
		{"1.2.3.4", "1.2.3.4"},
		{"1.2.3.4:54321", "1.2.3.4"},             // Azure appends ip:port
		{"6.6.6.6, 1.2.3.4:54321", "1.2.3.4"},    // spoofed first entry must be ignored
		{"6.6.6.6, 7.7.7.7, 1.2.3.4", "1.2.3.4"}, // only the last (proxy-appended) entry counts
		{"[2001:db8::1]:443", "2001:db8::1"},     // bracketed IPv6 with port
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", c.xff)
		if got := clientIPFrom(req); got != c.want {
			t.Errorf("XFF %q: got %q, want %q", c.xff, got, c.want)
		}
	}
}

func TestClientIPPrefersCloudflareHeader(t *testing.T) {
	// Proxied through Cloudflare, XFF's last entry is a CF edge IP — CF-Connecting-IP
	// must win over it.
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("CF-Connecting-IP", "1.2.3.4")
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 172.71.0.99:44321")
	if got := clientIPFrom(req); got != "1.2.3.4" {
		t.Errorf("expected CF-Connecting-IP to win, got %q", got)
	}
}

func TestComputeIssuesNoSANs(t *testing.T) {
	now := time.Now()
	probe := &certprobe.Result{
		NotBefore:     now.Add(-24 * time.Hour),
		NotAfter:      now.Add(24 * time.Hour),
		ChainComplete: true,
		ChainVerified: true,
		// DNSNames deliberately empty: browsers ignore CN, so a SAN-less cert covers nothing.
	}
	issues := computeIssues("example.com", probe, false)
	if !contains(issues, "hostname-mismatch") {
		t.Errorf("expected hostname-mismatch for a SAN-less cert, got %v", issues)
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
