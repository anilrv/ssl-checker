package main

import (
	"container/list"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/azure/azure-functions-golang-worker/sdk"
	"github.com/azure/azure-functions-golang-worker/worker"

	"sslcheckerfunc/certprobe"
	"sslcheckerfunc/geoip"
	"sslcheckerfunc/ssrfguard"
	"sslcheckerfunc/whois"
)

func main() {
	app := sdk.FunctionApp()
	// host.json sets routePrefix to "" — each route below is given explicitly so
	// existing URLs (already in use by the extension and the Store listing) don't move.
	app.HTTP("checkssl", checkSSLHandler,
		sdk.WithRoute("api/checkssl"),
		sdk.WithMethods("GET", "OPTIONS"),
		sdk.WithAuth("function"),
	)
	app.HTTP("bootstrap", bootstrapHandler,
		sdk.WithRoute("api/bootstrap"),
		sdk.WithMethods("GET", "OPTIONS"),
		sdk.WithAuth("anonymous"),
	)
	app.HTTP("privacy", privacyHandler,
		sdk.WithRoute("api/privacy"),
		sdk.WithMethods("GET"),
		sdk.WithAuth("anonymous"),
	)
	app.HTTP("home", homeHandler,
		sdk.WithRoute("/"),
		sdk.WithMethods("GET"),
		sdk.WithAuth("anonymous"),
	)
	app.HTTP("faviconIco", faviconICOHandler,
		sdk.WithRoute("favicon.ico"),
		sdk.WithMethods("GET"),
		sdk.WithAuth("anonymous"),
	)
	app.HTTP("faviconSvg", faviconSVGHandler,
		sdk.WithRoute("favicon.svg"),
		sdk.WithMethods("GET"),
		sdk.WithAuth("anonymous"),
	)
	app.HTTP("favicon96", favicon96Handler,
		sdk.WithRoute("favicon-96x96.png"),
		sdk.WithMethods("GET"),
		sdk.WithAuth("anonymous"),
	)
	app.HTTP("appleTouchIcon", appleTouchIconHandler,
		sdk.WithRoute("apple-touch-icon.png"),
		sdk.WithMethods("GET"),
		sdk.WithAuth("anonymous"),
	)
	app.HTTP("webAppIcon192", webAppIcon192Handler,
		sdk.WithRoute("web-app-manifest-192x192.png"),
		sdk.WithMethods("GET"),
		sdk.WithAuth("anonymous"),
	)
	app.HTTP("webAppIcon512", webAppIcon512Handler,
		sdk.WithRoute("web-app-manifest-512x512.png"),
		sdk.WithMethods("GET"),
		sdk.WithAuth("anonymous"),
	)
	app.HTTP("siteWebmanifest", siteWebmanifestHandler,
		sdk.WithRoute("site.webmanifest"),
		sdk.WithMethods("GET"),
		sdk.WithAuth("anonymous"),
	)
	worker.Start(app)
}

// ---- response shape ----

type CheckResult struct {
	Hostname        string   `json:"hostname"`
	Org             string   `json:"org,omitempty"`
	IssuerOrg       string   `json:"issuerOrg,omitempty"`
	NotBefore       int64    `json:"notBefore,omitempty"`
	NotAfter        int64    `json:"notAfter,omitempty"`
	DaysSinceIssued int      `json:"daysSinceIssued,omitempty"`
	DaysUntilExpiry int      `json:"daysUntilExpiry,omitempty"`
	DNSNames        []string `json:"dnsNames,omitempty"`
	Protocol        string   `json:"protocol,omitempty"`
	CipherSuite     string   `json:"cipherSuite,omitempty"`

	ChainLength   int    `json:"chainLength,omitempty"`
	ChainComplete bool   `json:"chainComplete,omitempty"`
	ChainVerified bool   `json:"chainVerified,omitempty"`
	ChainError    string `json:"chainError,omitempty"`

	ALPNProtocol string `json:"alpnProtocol,omitempty"`
	HTTP2        bool   `json:"http2,omitempty"`
	OCSPStapled  bool   `json:"ocspStapled,omitempty"`
	SCTCount     int    `json:"sctCount,omitempty"`
	HandshakeMs  int64  `json:"handshakeMs,omitempty"`
	Server       string `json:"server,omitempty"`
	PoweredBy    string `json:"poweredBy,omitempty"`

	GeoCountry     string `json:"geoCountry,omitempty"`
	GeoCity        string `json:"geoCity,omitempty"`
	GeoCountryFlag string `json:"geoCountryFlag,omitempty"`
	GeoAsn         string `json:"geoAsn,omitempty"`
	GeoAsName      string `json:"geoAsName,omitempty"`

	RegistrarName         string   `json:"registrarName,omitempty"`
	DomainCreated         int64    `json:"domainCreated,omitempty"`
	DomainExpires         int64    `json:"domainExpires,omitempty"`
	DaysSinceRegistered   int      `json:"daysSinceRegistered,omitempty"`
	DaysUntilDomainExpiry int      `json:"daysUntilDomainExpiry,omitempty"`
	DNSProviders          []string `json:"dnsProviders,omitempty"`
	OwnerOrg              string   `json:"ownerOrg,omitempty"`

	Issues    []string `json:"issues"`
	ScannedAt int64    `json:"scannedAt"`
	Error     string   `json:"error,omitempty"`
}

// ---- in-memory (per-instance) rate limiter ----
// Not distributed across scaled-out instances — acceptable for a lightweight personal
// tool. A durable multi-instance limit would need Table Storage/Redis instead.

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string][]time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: make(map[string][]time.Time)}
}

func (rl *rateLimiter) Allow(key string, limit int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)
	kept := rl.buckets[key][:0]
	for _, t := range rl.buckets[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= limit {
		rl.buckets[key] = kept
		return false
	}
	rl.buckets[key] = append(kept, now)

	if len(rl.buckets) > 10000 { // crude safeguard against unbounded growth
		rl.buckets = make(map[string][]time.Time)
	}
	return true
}

var limiter = newRateLimiter()

// ---- bounded in-memory LRU result cache: up to 500 entries, 24h TTL ----

type cacheItem struct {
	key       string
	result    CheckResult
	expiresAt time.Time
}

type resultCache struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	ll       *list.List
	items    map[string]*list.Element
}

func newResultCache(capacity int, ttl time.Duration) *resultCache {
	return &resultCache{
		capacity: capacity,
		ttl:      ttl,
		ll:       list.New(),
		items:    make(map[string]*list.Element),
	}
}

func (c *resultCache) Get(key string) (CheckResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		return CheckResult{}, false
	}
	item := el.Value.(*cacheItem)
	if time.Now().After(item.expiresAt) {
		c.ll.Remove(el)
		delete(c.items, key)
		return CheckResult{}, false
	}
	c.ll.MoveToFront(el)
	return item.result, true
}

func (c *resultCache) Set(key string, result CheckResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		item := el.Value.(*cacheItem)
		item.result = result
		item.expiresAt = time.Now().Add(c.ttl)
		c.ll.MoveToFront(el)
		return
	}

	item := &cacheItem{key: key, result: result, expiresAt: time.Now().Add(c.ttl)}
	el := c.ll.PushFront(item)
	c.items[key] = el

	if c.ll.Len() > c.capacity {
		back := c.ll.Back()
		if back != nil {
			c.ll.Remove(back)
			delete(c.items, back.Value.(*cacheItem).key)
		}
	}
}

var resultsCache = newResultCache(500, 24*time.Hour)

// ---- HTTP handler ----

func checkSSLHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", corsOrigin(r))
	w.Header().Set("Vary", "Origin")

	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	hostname := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host")))
	if hostname == "" || !ssrfguard.ValidHostname(hostname) {
		writeJSONError(w, http.StatusBadRequest, "invalid or missing 'host' query parameter")
		return
	}

	clientIP := clientIPFrom(r)
	if !limiter.Allow(clientIP, 20, time.Minute) {
		writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded, try again shortly")
		return
	}

	if r.URL.Query().Get("force") != "1" {
		if cached, ok := resultsCache.Get(hostname); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	result := performCheck(ctx, hostname)
	resultsCache.Set(hostname, result)
	writeJSON(w, http.StatusOK, result)
}

// bootstrapHandler lets the extension fetch its own function key instead of asking the
// user to enter it. It's genuinely anonymous, gated only by rate limiting: an Origin-based
// check was tried here first, but Chromium sends Origin as "null" (or omits it) for
// fetch() calls from extension pages (popup/background) to external hosts unless the
// extension has host_permissions for that host — which this extension deliberately
// doesn't have (removed earlier to avoid the "read and change your data on all websites"
// warning). So Origin can never actually match here; the key isn't meant to be secret
// from someone running the extension anyway, this just keeps the endpoint from being
// trivially hammered by anything automated.
func bootstrapHandler(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if strings.HasPrefix(origin, "chrome-extension://") {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
	}

	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	clientIP := clientIPFrom(r)
	if !limiter.Allow("bootstrap:"+clientIP, 10, time.Minute) {
		writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded, try again shortly")
		return
	}

	key := os.Getenv("CHECKSSL_KEY")
	if key == "" {
		writeJSONError(w, http.StatusInternalServerError, "server not configured")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"key": key})
}

func corsOrigin(r *http.Request) string {
	origin := r.Header.Get("Origin")
	if strings.HasPrefix(origin, "chrome-extension://") {
		return origin
	}
	return "null"
}

func clientIPFrom(r *http.Request) string {
	// The public hostname is proxied through Cloudflare, which sets CF-Connecting-IP to the
	// real client address on every proxied request. X-Forwarded-For's last entry is Azure's
	// view of the caller — under the proxy that's a Cloudflare EDGE IP, which would bucket
	// unrelated users together and let an abuser rotate edges. NOTE: CF-Connecting-IP is
	// only trustworthy while the *.azurewebsites.net origin is restricted to Cloudflare's
	// IP ranges — anyone reaching the origin directly can forge it.
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return cf
	}

	// Fallback (direct-to-origin traffic): X-Forwarded-For can arrive with client-supplied
	// entries already in it; Azure's front end APPENDS the real caller, so only the LAST
	// entry is trustworthy — taking the first would let a caller rotate fake IPs to sidestep
	// the per-IP rate limit. Azure formats its entry as ip:port, so strip the port.
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		last := strings.TrimSpace(parts[len(parts)-1])
		if host, _, err := net.SplitHostPort(last); err == nil {
			return host
		}
		return last
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ---- core check logic ----

func performCheck(ctx context.Context, hostname string) CheckResult {
	result := CheckResult{Hostname: hostname, ScannedAt: time.Now().Unix()}

	// whois.Lookup only needs the hostname (not the resolved IP), so it can start even
	// before DNS resolution — overlapping with everything else that follows, rather than
	// just with certprobe.Probe. The channel is buffered so the goroutine can't leak even
	// if this function returns early before anyone reads from it.
	whoisCh := make(chan *whois.Info, 1)
	go func() { whoisCh <- whois.Lookup(ctx, hostname) }()

	ip, err := ssrfguard.ResolvePublicIP(ctx, hostname)
	if err != nil {
		result.Error = err.Error()
		result.Issues = []string{"resolve-failed"}
		return result
	}

	// geoip.Lookup runs concurrently with certprobe.Probe (not after it) so its latency
	// overlaps with the TLS work instead of adding to it — both only need the IP above.
	// The channel is buffered so the goroutine can't leak even if this function returns
	// early (e.g. on a probe failure) before anyone reads from it.
	geoCh := make(chan *geoip.Info, 1)
	go func() { geoCh <- geoip.Lookup(ctx, ip) }()

	probe, err := certprobe.Probe(ctx, ip, hostname)
	if err != nil {
		result.Error = err.Error()
		result.Issues = []string{"probe-failed"}
		return result
	}

	result.Org = probe.SubjectOrg
	if result.Org == "" {
		result.Org = probe.SubjectCN
	}
	result.IssuerOrg = probe.IssuerOrg
	if result.IssuerOrg == "" {
		result.IssuerOrg = probe.IssuerCN
	}
	result.NotBefore = probe.NotBefore.Unix()
	result.NotAfter = probe.NotAfter.Unix()
	result.DaysSinceIssued = int(time.Since(probe.NotBefore).Hours() / 24)
	result.DaysUntilExpiry = int(time.Until(probe.NotAfter).Hours() / 24)
	result.DNSNames = probe.DNSNames
	result.Protocol = probe.Protocol
	result.CipherSuite = probe.CipherSuite
	result.ChainLength = probe.ChainLength
	result.ChainComplete = probe.ChainComplete
	result.ChainVerified = probe.ChainVerified
	result.ChainError = probe.ChainVerifyError

	result.ALPNProtocol = probe.ALPNProtocol
	result.HTTP2 = probe.ALPNProtocol == "h2"
	result.OCSPStapled = probe.OCSPStapled
	result.SCTCount = probe.SCTCount
	result.HandshakeMs = probe.HandshakeMs
	result.Server = probe.ServerHeader
	result.PoweredBy = probe.PoweredBy

	if geo := <-geoCh; geo != nil {
		result.GeoCountry = geo.Country
		result.GeoCity = geo.City
		result.GeoCountryFlag = geo.CountryFlag
		result.GeoAsn = geo.ASN
		result.GeoAsName = geo.ASName
	}

	if wh := <-whoisCh; wh != nil {
		result.RegistrarName = wh.RegistrarName
		result.DNSProviders = wh.DetectedProviders
		result.OwnerOrg = wh.OwnerOrg
		if !wh.Created.IsZero() {
			result.DomainCreated = wh.Created.Unix()
			result.DaysSinceRegistered = int(time.Since(wh.Created).Hours() / 24)
		}
		if !wh.Expires.IsZero() {
			result.DomainExpires = wh.Expires.Unix()
			result.DaysUntilDomainExpiry = int(time.Until(wh.Expires).Hours() / 24)
		}
	}

	weakProtocol := certprobe.SupportsLegacyProtocol(ctx, ip, hostname, tls.VersionTLS10)
	result.Issues = computeIssues(hostname, probe, weakProtocol)
	return result
}

func computeIssues(hostname string, probe *certprobe.Result, weakProtocol bool) []string {
	var issues []string
	now := time.Now()

	if probe.NotAfter.Before(now) {
		issues = append(issues, "expired")
	}
	if probe.NotBefore.After(now) {
		issues = append(issues, "not-yet-valid")
	}

	// Cryptographic check (signature verifies against the leaf's own public key), not
	// a string comparison of issuer/subject Organization — the latter false-positives
	// whenever a CA and the leaf happen to share an org name (e.g. a company running
	// its own subordinate CA for its own domains).
	if probe.LeafSelfSigned {
		issues = append(issues, "self-signed")
	}

	// Distinguish two different root causes for "doesn't verify," instead of one
	// blunt flag: a structurally incomplete chain (server misconfiguration) vs a
	// complete chain that simply doesn't terminate in a trusted root.
	if !probe.ChainVerified && !probe.LeafSelfSigned {
		if !probe.ChainComplete {
			issues = append(issues, "incomplete-chain")
		} else {
			issues = append(issues, "untrusted-chain")
		}
	}

	// A cert with no SANs at all can't cover any hostname — browsers ignore the legacy
	// CommonName field entirely (Chrome since 58) — so an empty DNSNames list is itself
	// a mismatch, not a pass.
	matched := false
	for _, san := range probe.DNSNames {
		if matchesHostname(hostname, san) {
			matched = true
			break
		}
	}
	if !matched {
		issues = append(issues, "hostname-mismatch")
	}

	if weakProtocol {
		issues = append(issues, "weak-protocol")
	}

	return issues
}

func matchesHostname(hostname, pattern string) bool {
	hostname = strings.ToLower(hostname)
	pattern = strings.ToLower(pattern)
	if pattern == hostname {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		if strings.HasSuffix(hostname, suffix) {
			rest := hostname[:len(hostname)-len(suffix)]
			return !strings.Contains(rest, ".")
		}
	}
	return false
}
