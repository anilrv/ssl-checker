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
		host         string
		wantIssue    string
		wantNoIssues []string
	}{
		{host: "github.com", wantNoIssues: []string{"expired", "recently-registered", "young-domain", "revoked"}},
		{host: "expired.badssl.com", wantIssue: "expired"},
		{host: "self-signed.badssl.com", wantIssue: "self-signed"},
		{host: "wrong.host.badssl.com", wantIssue: "hostname-mismatch"},
		{host: "revoked.badssl.com", wantIssue: "revoked"},
	}
	for _, c := range cases {
		result := doCheck(t, c.host)
		if result.Error != "" {
			t.Errorf("%s: unexpected error: %s", c.host, result.Error)
		}
		if c.wantIssue != "" && !contains(result.Issues, c.wantIssue) {
			t.Errorf("%s: expected issue %q, got %v", c.host, c.wantIssue, result.Issues)
		}
		for _, no := range c.wantNoIssues {
			if contains(result.Issues, no) {
				t.Errorf("%s: unexpected issue %q present in %v", c.host, no, result.Issues)
			}
		}
		// IssueDetails must mirror Issues 1:1 — the extension renders from it.
		if len(result.IssueDetails) != len(result.Issues) {
			t.Errorf("%s: %d issueDetails for %d issues", c.host, len(result.IssueDetails), len(result.Issues))
		} else {
			for i, code := range result.Issues {
				if result.IssueDetails[i].Code != code {
					t.Errorf("%s: issueDetails[%d].code = %q, want %q", c.host, i, result.IssueDetails[i].Code, code)
				}
			}
		}
		if c.host == "expired.badssl.com" {
			found := false
			for _, d := range result.IssueDetails {
				if d.Code == "expired" && d.Level == "critical" && d.Label != "" {
					found = true
				}
			}
			if !found {
				t.Errorf("expired.badssl.com: no critical 'expired' issueDetail in %+v", result.IssueDetails)
			}
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
	issues := computeIssues(&CheckResult{Hostname: "example.com"}, probe, false)
	if !contains(issues, "hostname-mismatch") {
		t.Errorf("expected hostname-mismatch for a SAN-less cert, got %v", issues)
	}
}

// healthyProbe is a cert that trips none of the rules: valid dates well clear of the
// expiring-soon window, verified chain, SAN covering example.com.
func healthyProbe(now time.Time) *certprobe.Result {
	return &certprobe.Result{
		NotBefore:     now.Add(-30 * 24 * time.Hour),
		NotAfter:      now.Add(60 * 24 * time.Hour),
		ChainComplete: true,
		ChainVerified: true,
		DNSNames:      []string{"example.com"},
	}
}

func TestComputeIssuesDomainAge(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name       string
		created    int64
		wantRed    bool // recently-registered (critical)
		wantYellow bool // young-domain (warning)
	}{
		{"5 days old", now.Add(-5 * 24 * time.Hour).Unix(), true, false},
		{"just under 10 days", now.Add(-10*24*time.Hour + time.Hour).Unix(), true, false},
		{"just over 10 days", now.Add(-10*24*time.Hour - time.Hour).Unix(), false, true},
		{"29 days old", now.Add(-29 * 24 * time.Hour).Unix(), false, true},
		{"just over 30 days", now.Add(-30*24*time.Hour - time.Hour).Unix(), false, false},
		{"no whois data", 0, false, false},
		{"future-dated creation", now.Add(time.Hour).Unix(), true, false},
	}
	for _, c := range cases {
		result := &CheckResult{Hostname: "example.com", DomainCreated: c.created}
		issues := computeIssues(result, healthyProbe(now), false)
		if got := contains(issues, "recently-registered"); got != c.wantRed {
			t.Errorf("%s: recently-registered=%v, want %v (issues %v)", c.name, got, c.wantRed, issues)
		}
		if got := contains(issues, "young-domain"); got != c.wantYellow {
			t.Errorf("%s: young-domain=%v, want %v (issues %v)", c.name, got, c.wantYellow, issues)
		}
	}
}

func TestComputeIssuesCertExpiringSoon(t *testing.T) {
	now := time.Now()
	result := &CheckResult{Hostname: "example.com"}

	probe := healthyProbe(now)
	probe.NotAfter = now.Add(7 * 24 * time.Hour)
	if issues := computeIssues(result, probe, false); !contains(issues, "cert-expiring-soon") {
		t.Errorf("cert expiring in 7d: expected cert-expiring-soon, got %v", issues)
	}

	probe.NotAfter = now.Add(15 * 24 * time.Hour)
	if issues := computeIssues(result, probe, false); contains(issues, "cert-expiring-soon") {
		t.Errorf("cert expiring in 15d: unexpected cert-expiring-soon in %v", issues)
	}

	// Already expired: "expired" owns the finding, expiring-soon must stay quiet.
	probe.NotAfter = now.Add(-time.Hour)
	issues := computeIssues(result, probe, false)
	if !contains(issues, "expired") || contains(issues, "cert-expiring-soon") {
		t.Errorf("expired cert: want expired without cert-expiring-soon, got %v", issues)
	}
}

func TestComputeIssuesDomainExpiringSoon(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		expires int64
		want    bool
	}{
		{"expires in 13 days", now.Add(13 * 24 * time.Hour).Unix(), true},
		{"expires in 15 days", now.Add(15 * 24 * time.Hour).Unix(), false},
		{"no whois data", 0, false},
		{"already lapsed", now.Add(-time.Hour).Unix(), true},
	}
	for _, c := range cases {
		result := &CheckResult{Hostname: "example.com", DomainExpires: c.expires}
		issues := computeIssues(result, healthyProbe(now), false)
		if got := contains(issues, "domain-expiring-soon"); got != c.want {
			t.Errorf("%s: domain-expiring-soon=%v, want %v (issues %v)", c.name, got, c.want, issues)
		}
	}
}

func TestComputeIssuesRevoked(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		status string
		want   bool
	}{
		{certprobe.RevocationRevoked, true},
		{certprobe.RevocationGood, false},
		{certprobe.RevocationUnknown, false},
		{"", false},
	} {
		probe := healthyProbe(now)
		probe.RevocationStatus = c.status
		issues := computeIssues(&CheckResult{Hostname: "example.com"}, probe, false)
		if got := contains(issues, "revoked"); got != c.want {
			t.Errorf("status %q: revoked=%v, want %v (issues %v)", c.status, got, c.want, issues)
		}
	}
}

func TestComputeIssuesWeakCrypto(t *testing.T) {
	now := time.Now()

	probe := healthyProbe(now)
	probe.WeakSignature = true
	if issues := computeIssues(&CheckResult{Hostname: "example.com"}, probe, false); !contains(issues, "weak-signature") {
		t.Errorf("weak signature: expected weak-signature, got %v", issues)
	}

	cases := []struct {
		name    string
		keyType string
		keyBits int
		want    bool
	}{
		{"RSA 1024", "RSA", 1024, true},
		{"RSA 2048", "RSA", 2048, false},
		{"ECDSA 256", "ECDSA", 256, false},
		{"unknown key", "", 0, false},
	}
	for _, c := range cases {
		probe := healthyProbe(now)
		probe.KeyType = c.keyType
		probe.KeyBits = c.keyBits
		issues := computeIssues(&CheckResult{Hostname: "example.com"}, probe, false)
		if got := contains(issues, "weak-key"); got != c.want {
			t.Errorf("%s: weak-key=%v, want %v (issues %v)", c.name, got, c.want, issues)
		}
	}
}

func TestIssueCatalogAndSetIssues(t *testing.T) {
	// Every code any backend path can emit; keep in step with computeIssues and the
	// resolve-failed/probe-failed paths in performCheck.
	emitted := []string{
		"expired", "not-yet-valid", "self-signed", "incomplete-chain", "untrusted-chain",
		"hostname-mismatch", "weak-protocol", "revoked", "weak-signature", "weak-key",
		"recently-registered", "young-domain",
		"cert-expiring-soon", "domain-expiring-soon", "resolve-failed", "probe-failed",
	}
	validLevels := map[string]bool{"critical": true, "warning": true, "info": true}
	for _, code := range emitted {
		detail, ok := issueCatalog[code]
		if !ok {
			t.Errorf("emitted code %q missing from issueCatalog", code)
			continue
		}
		if detail.Label == "" || !validLevels[detail.Level] {
			t.Errorf("catalog entry for %q has bad label/level: %+v", code, detail)
		}
	}

	var result CheckResult
	setIssues(&result, []string{"recently-registered", "young-domain"})
	if len(result.Issues) != 2 || len(result.IssueDetails) != 2 {
		t.Fatalf("setIssues: got %d issues / %d details", len(result.Issues), len(result.IssueDetails))
	}
	for i, code := range result.Issues {
		if result.IssueDetails[i].Code != code {
			t.Errorf("issueDetails[%d].code = %q, want %q", i, result.IssueDetails[i].Code, code)
		}
	}
	if result.IssueDetails[0].Level != "critical" || result.IssueDetails[1].Level != "warning" {
		t.Errorf("domain-age tiers: got levels %q/%q, want critical/warning",
			result.IssueDetails[0].Level, result.IssueDetails[1].Level)
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

func TestCappedTTL(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name      string
		deadlines []time.Time
		want      time.Duration
	}{
		{name: "no deadlines", deadlines: nil, want: resultsCacheTTL},
		{name: "zero deadlines ignored", deadlines: []time.Time{{}, {}}, want: resultsCacheTTL},
		{name: "deadline beyond base", deadlines: []time.Time{now.Add(48 * time.Hour)}, want: resultsCacheTTL},
		{name: "deadline inside base", deadlines: []time.Time{now.Add(2 * time.Hour)}, want: 2 * time.Hour},
		{name: "earliest of several wins", deadlines: []time.Time{now.Add(6 * time.Hour), now.Add(2 * time.Hour)}, want: 2 * time.Hour},
		{name: "deadline within floor window stays exact", deadlines: []time.Time{now.Add(2 * time.Minute)}, want: 2 * time.Minute},
		{name: "past deadline floors", deadlines: []time.Time{now.Add(-time.Hour)}, want: minCacheTTL},
	}
	for _, c := range cases {
		got := cappedTTL(resultsCacheTTL, c.deadlines...)
		// cappedTTL calls time.Now() itself, so allow a small skew.
		if diff := got - c.want; diff < -time.Second || diff > time.Second {
			t.Errorf("%s: got %v, want ~%v", c.name, got, c.want)
		}
	}
}

func TestResultTTLAndDataExpired(t *testing.T) {
	now := time.Now()

	healthy := CheckResult{NotAfter: now.Add(90 * 24 * time.Hour).Unix(), DomainExpires: now.Add(365 * 24 * time.Hour).Unix()}
	if got := resultTTL(healthy); got != resultsCacheTTL {
		t.Errorf("healthy cert: got %v, want full %v", got, resultsCacheTTL)
	}
	if dataExpired(healthy) {
		t.Error("healthy cert reported as expired data")
	}

	expiringSoon := CheckResult{NotAfter: now.Add(3 * time.Hour).Unix()}
	if got := resultTTL(expiringSoon); got > 3*time.Hour || got < 3*time.Hour-time.Second {
		t.Errorf("cert expiring in 3h: got %v, want ~3h", got)
	}

	domainExpiringSoon := CheckResult{NotAfter: now.Add(90 * 24 * time.Hour).Unix(), DomainExpires: now.Add(time.Hour).Unix()}
	if got := resultTTL(domainExpiringSoon); got > time.Hour || got < time.Hour-time.Second {
		t.Errorf("domain expiring in 1h: got %v, want ~1h", got)
	}

	expired := CheckResult{NotAfter: now.Add(-time.Hour).Unix()}
	if got := resultTTL(expired); got != minCacheTTL {
		t.Errorf("expired cert: got %v, want floor %v", got, minCacheTTL)
	}
	if !dataExpired(expired) {
		t.Error("expired cert not reported as expired data")
	}

	lapsedDomain := CheckResult{NotAfter: now.Add(90 * 24 * time.Hour).Unix(), DomainExpires: now.Add(-time.Hour).Unix()}
	if !dataExpired(lapsedDomain) {
		t.Error("lapsed domain not reported as expired data")
	}

	// omitempty zeros (e.g. probe without whois data) must not cap or expire anything
	noDates := CheckResult{}
	if got := resultTTL(noDates); got != resultsCacheTTL {
		t.Errorf("no dates: got %v, want full %v", got, resultsCacheTTL)
	}
	if dataExpired(noDates) {
		t.Error("zero dates reported as expired data")
	}

	// Threshold-crossing deadlines: a cached verdict must expire the moment a
	// domain-age tier or an expiring-soon window would flip.
	farCert := now.Add(90 * 24 * time.Hour).Unix()
	farDomain := now.Add(365 * 24 * time.Hour).Unix()

	redToYellow := CheckResult{NotAfter: farCert, DomainExpires: farDomain, DomainCreated: now.Add(-(10*24 - 6) * time.Hour).Unix()}
	if got := resultTTL(redToYellow); got > 6*time.Hour || got < 6*time.Hour-time.Second {
		t.Errorf("domain 6h from 10d boundary: got %v, want ~6h", got)
	}
	if dataExpired(redToYellow) {
		t.Error("recently created domain reported as expired data")
	}

	yellowToClean := CheckResult{NotAfter: farCert, DomainExpires: farDomain, DomainCreated: now.Add(-(30*24 - 6) * time.Hour).Unix()}
	if got := resultTTL(yellowToClean); got > 6*time.Hour || got < 6*time.Hour-time.Second {
		t.Errorf("domain 6h from 30d boundary: got %v, want ~6h", got)
	}

	// Regression guard: thresholds already crossed are not deadlines — a mature
	// domain must keep the full TTL, not get floored to minCacheTTL.
	mature := CheckResult{NotAfter: farCert, DomainExpires: farDomain, DomainCreated: now.Add(-45 * 24 * time.Hour).Unix()}
	if got := resultTTL(mature); got != resultsCacheTTL {
		t.Errorf("mature domain: got %v, want full %v", got, resultsCacheTTL)
	}

	certNearWindow := CheckResult{NotAfter: now.Add((14*24 + 2) * time.Hour).Unix()}
	if got := resultTTL(certNearWindow); got > 2*time.Hour || got < 2*time.Hour-time.Second {
		t.Errorf("cert 2h from expiring-soon window: got %v, want ~2h", got)
	}

	domainNearWindow := CheckResult{NotAfter: farCert, DomainExpires: now.Add((14*24 + 3) * time.Hour).Unix()}
	if got := resultTTL(domainNearWindow); got > 3*time.Hour || got < 3*time.Hour-time.Second {
		t.Errorf("domain 3h from expiring-soon window: got %v, want ~3h", got)
	}
}

func TestResultCacheHonorsPerEntryTTL(t *testing.T) {
	c := newResultCache(10)

	c.Set("live.example", CheckResult{Org: "live"}, time.Hour)
	if _, ok := c.Get("live.example"); !ok {
		t.Error("entry with 1h TTL should be a hit")
	}

	c.Set("dead.example", CheckResult{Org: "dead"}, -time.Second)
	if _, ok := c.Get("dead.example"); ok {
		t.Error("entry with already-elapsed TTL should be a miss")
	}

	// Updating an existing entry must apply the new TTL, not the original one.
	c.Set("live.example", CheckResult{Org: "live"}, -time.Second)
	if _, ok := c.Get("live.example"); ok {
		t.Error("updated entry with elapsed TTL should be a miss")
	}
}
