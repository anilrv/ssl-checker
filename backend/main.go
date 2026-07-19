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
	"sslcheckerfunc/durablecache"
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

	SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"`
	KeyType            string `json:"keyType,omitempty"`
	KeyBits            int    `json:"keyBits,omitempty"`
	RevocationStatus   string `json:"revocationStatus,omitempty"` // "good" | "revoked" | "unknown"
	RevocationSource   string `json:"revocationSource,omitempty"` // "stapled-ocsp" | "ocsp" | "crl"

	ALPNProtocol string `json:"alpnProtocol,omitempty"`
	HTTP2        bool   `json:"http2,omitempty"`
	OCSPStapled  bool   `json:"ocspStapled,omitempty"`
	SCTCount     int    `json:"sctCount,omitempty"`
	HandshakeMs  int64  `json:"handshakeMs,omitempty"`
	Server       string `json:"server,omitempty"`
	PoweredBy    string `json:"poweredBy,omitempty"`

	GeoCountry     string `json:"geoCountry,omitempty"`
	GeoCountryCode string `json:"geoCountryCode,omitempty"`
	GeoCity        string `json:"geoCity,omitempty"`
	GeoCountryFlag string `json:"geoCountryFlag,omitempty"` // kept for older extension versions
	// The flag as a data: URI — what current extensions render, since cross-origin-
	// isolated pages (COEP) block direct <img> loads from ipgeolocation.io.
	GeoCountryFlagData string `json:"geoCountryFlagData,omitempty"`
	GeoAsn             string `json:"geoAsn,omitempty"`
	GeoAsName          string `json:"geoAsName,omitempty"`

	RegistrarName         string   `json:"registrarName,omitempty"`
	DomainCreated         int64    `json:"domainCreated,omitempty"`
	DomainExpires         int64    `json:"domainExpires,omitempty"`
	DaysSinceRegistered   int      `json:"daysSinceRegistered,omitempty"`
	DaysUntilDomainExpiry int      `json:"daysUntilDomainExpiry,omitempty"`
	DNSProviders          []string `json:"dnsProviders,omitempty"`
	OwnerOrg              string   `json:"ownerOrg,omitempty"`

	Issues       []string      `json:"issues"`
	IssueDetails []IssueDetail `json:"issueDetails,omitempty"`
	ScannedAt    int64         `json:"scannedAt"`
	Error        string        `json:"error,omitempty"`
}

// IssueDetail carries the display metadata for one issue code, so the extension
// renders whatever the backend sends instead of keeping its own code→label/level
// maps in sync — a new rule ships with a backend deploy alone. Issues (codes only)
// stays alongside for extension versions that predate this field.
type IssueDetail struct {
	Code  string `json:"code"`
	Label string `json:"label"`
	Level string `json:"level"` // "critical" | "warning" | "info"
}

// issueCatalog is the single source of truth for every code the backend can emit.
// The extension's own maps are fallback-only (for its client-side "no-https" code,
// which never reaches this server, and for cached rows written before IssueDetails
// existed) — new codes are added here, never there.
var issueCatalog = map[string]IssueDetail{
	"expired":              {Label: "Certificate has expired", Level: "critical"},
	"not-yet-valid":        {Label: "Certificate is not yet valid", Level: "critical"},
	"self-signed":          {Label: "Certificate appears to be self-signed", Level: "critical"},
	"incomplete-chain":     {Label: "Server is missing its intermediate certificate", Level: "warning"},
	"untrusted-chain":      {Label: "Chain doesn't lead to a trusted root CA", Level: "critical"},
	"hostname-mismatch":    {Label: "Certificate does not cover this site's hostname", Level: "critical"},
	"weak-protocol":        {Label: "Server still accepts an outdated TLS protocol (TLS 1.0)", Level: "warning"},
	"revoked":              {Label: "Certificate has been revoked by its issuer", Level: "critical"},
	"weak-signature":       {Label: "Certificate is signed with a weak algorithm (SHA-1/MD5)", Level: "warning"},
	"weak-key":             {Label: "Certificate uses a weak RSA key (under 2048 bits)", Level: "warning"},
	"recently-registered":  {Label: "Domain was registered less than 10 days ago", Level: "critical"},
	"young-domain":         {Label: "Domain was registered less than 30 days ago", Level: "warning"},
	"cert-expiring-soon":   {Label: "Certificate expires within 14 days", Level: "warning"},
	"domain-expiring-soon": {Label: "Domain registration expires within 14 days", Level: "warning"},
	"resolve-failed":       {Label: "Could not resolve this hostname", Level: "info"},
	"probe-failed":         {Label: "Could not connect to check the certificate", Level: "info"},
}

// setIssues stores the codes plus their catalog metadata on the result, keeping the
// two representations 1:1. Every site that assigns Issues must go through here.
func setIssues(result *CheckResult, codes []string) {
	result.Issues = codes
	result.IssueDetails = nil
	for _, code := range codes {
		detail := issueCatalog[code]
		detail.Code = code
		if detail.Label == "" {
			detail.Label = code
		}
		if detail.Level == "" {
			detail.Level = "warning"
		}
		result.IssueDetails = append(result.IssueDetails, detail)
	}
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
// Each entry's TTL is capped at the data's own expiry (cert NotAfter, domain
// expiration) so a result is never served past the moment it stops being true.

type cacheItem struct {
	key       string
	result    CheckResult
	expiresAt time.Time
}

type resultCache struct {
	mu       sync.Mutex
	capacity int
	ll       *list.List
	items    map[string]*list.Element
}

func newResultCache(capacity int) *resultCache {
	return &resultCache{
		capacity: capacity,
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

func (c *resultCache) Set(key string, result CheckResult, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		item := el.Value.(*cacheItem)
		item.result = result
		item.expiresAt = time.Now().Add(ttl)
		c.ll.MoveToFront(el)
		return
	}

	item := &cacheItem{key: key, result: result, expiresAt: time.Now().Add(ttl)}
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

var resultsCache = newResultCache(500)

const resultsCacheTTL = 24 * time.Hour

// minCacheTTL is the floor applied when the underlying data has already expired:
// the (accurate) "expired" result is still cached briefly so a popular dead site
// doesn't trigger a full probe on every request, while a renewal shows up within
// minutes instead of hours.
const minCacheTTL = 5 * time.Minute

// ---- issue-rule thresholds ----
// Each threshold below also feeds resultTTL: a cached result must expire at the
// instant an issue would appear or disappear, or the cache would keep serving a
// verdict that has stopped being true.
const domainAgeCritical = 10 * 24 * time.Hour   // recently-registered: domain younger than this (red)
const domainAgeWarning = 30 * 24 * time.Hour    // young-domain: domain younger than this (yellow)
const certExpiryWarning = 14 * 24 * time.Hour   // cert-expiring-soon: NotAfter within this window
const domainExpiryWarning = 14 * 24 * time.Hour // domain-expiring-soon: DomainExpires within this window
const minRSAKeyBits = 2048                      // weak-key: RSA below this

// cappedTTL returns base reduced to the time remaining until the earliest non-zero
// deadline, floored at minCacheTTL once that remaining time reaches zero. A copy of
// this helper lives in the whois package (per-package caches are deliberately
// self-contained in this repo).
func cappedTTL(base time.Duration, deadlines ...time.Time) time.Duration {
	ttl := base
	now := time.Now()
	for _, d := range deadlines {
		if d.IsZero() {
			continue
		}
		if remaining := d.Sub(now); remaining < ttl {
			ttl = remaining
		}
	}
	if ttl <= 0 {
		ttl = minCacheTTL
	}
	return ttl
}

// unixTime maps a Unix-seconds field to time.Time, with 0 (field absent) becoming
// the zero time so cappedTTL ignores it.
func unixTime(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

// futureDeadline returns t only if it is still ahead: a threshold crossing that has
// already happened is not a deadline anymore. This matters because cappedTTL floors
// past deadlines to minCacheTTL — right for NotAfter/DomainExpires (genuinely expired
// data), but created+10d is in the past for every mature domain and NotAfter−14d for
// every cert already inside its warning window; passing those unconditionally would
// cap virtually every result at 5 minutes.
func futureDeadline(t time.Time) time.Time {
	if t.IsZero() || !t.After(time.Now()) {
		return time.Time{}
	}
	return t
}

// resultTTL is the cache lifetime for one result: the default TTL, cut short if the
// certificate or domain expires before it would — or if a time-based issue would
// appear (a cert/domain entering its expiring-soon window) or change tier / disappear
// (a young domain crossing the 10d red→yellow or 30d yellow→clean boundary) first.
func resultTTL(result CheckResult) time.Duration {
	deadlines := []time.Time{
		unixTime(result.NotAfter),
		unixTime(result.DomainExpires),
	}
	if created := unixTime(result.DomainCreated); !created.IsZero() {
		deadlines = append(deadlines,
			futureDeadline(created.Add(domainAgeCritical)),
			futureDeadline(created.Add(domainAgeWarning)))
	}
	if notAfter := unixTime(result.NotAfter); !notAfter.IsZero() {
		deadlines = append(deadlines, futureDeadline(notAfter.Add(-certExpiryWarning)))
	}
	if domExp := unixTime(result.DomainExpires); !domExp.IsZero() {
		deadlines = append(deadlines, futureDeadline(domExp.Add(-domainExpiryWarning)))
	}
	return cappedTTL(resultsCacheTTL, deadlines...)
}

// dataExpired reports whether a cached result claims validity past the cert's or
// domain's own expiry — i.e. the world has moved on since it was probed.
func dataExpired(result CheckResult) bool {
	now := time.Now().Unix()
	return (result.NotAfter > 0 && now > result.NotAfter) ||
		(result.DomainExpires > 0 && now > result.DomainExpires)
}

// ---- durable L2 layer (Azure Table Storage) behind the in-memory cache above ----
// Flex Consumption scales to zero when idle and scales out under load, wiping/fragmenting
// the in-memory LRU far more often than its 24h TTL implies. This durable layer, backed by
// the storage account Azure already requires (AzureWebJobsStorage), lets a cold or
// newly-scaled instance reuse a result another instance already computed.

const resultsCacheTable = "sslcheckercache"
const resultsCachePartition = "results"

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

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	if r.URL.Query().Get("force") != "1" {
		if cached, ok := resultsCache.Get(hostname); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}
		// Durable rows written before per-entry TTL capping (or written just inside the
		// minCacheTTL floor) can outlive the cert or domain registration they describe;
		// treat those as misses rather than serving a result that is no longer true.
		if cached, ok := durablecache.Get[CheckResult](ctx, resultsCacheTable, resultsCachePartition, hostname); ok && !dataExpired(cached) {
			resultsCache.Set(hostname, cached, resultTTL(cached))
			writeJSON(w, http.StatusOK, cached)
			return
		}
	}

	result := performCheck(ctx, hostname)
	// Only cache successful results — durably persisting a transient failure (e.g. a DNS
	// blip) for the full TTL across every instance would be a much bigger footgun than the
	// old in-memory-only behavior this replaces.
	if result.Error == "" {
		ttl := resultTTL(result)
		resultsCache.Set(hostname, result, ttl)
		go durablecache.Set(context.Background(), resultsCacheTable, resultsCachePartition, hostname, result, ttl)
	}
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

func writeJSON(w http.ResponseWriter, status int, v any) {
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
		setIssues(&result, []string{"resolve-failed"})
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
		setIssues(&result, []string{"probe-failed"})
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
	result.SignatureAlgorithm = probe.SignatureAlgorithm
	result.KeyType = probe.KeyType
	result.KeyBits = probe.KeyBits

	result.ALPNProtocol = probe.ALPNProtocol
	result.HTTP2 = probe.ALPNProtocol == "h2"
	result.OCSPStapled = probe.OCSPStapled
	result.SCTCount = probe.SCTCount
	result.HandshakeMs = probe.HandshakeMs
	result.Server = probe.ServerHeader
	result.PoweredBy = probe.PoweredBy

	if geo := <-geoCh; geo != nil {
		result.GeoCountry = geo.Country
		result.GeoCountryCode = geo.CountryCode
		result.GeoCity = geo.City
		result.GeoCountryFlag = geo.CountryFlag
		result.GeoCountryFlagData = geo.CountryFlagData
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

	// Revocation involves its own network fetches (OCSP responder / CRL), so it runs
	// concurrently with the legacy-protocol probe instead of adding to it. It mutates
	// probe in place; the channel is buffered so the goroutine can't leak.
	revDone := make(chan struct{}, 1)
	go func() { certprobe.CheckRevocation(ctx, probe); revDone <- struct{}{} }()
	weakProtocol := certprobe.SupportsLegacyProtocol(ctx, ip, hostname, tls.VersionTLS10)
	<-revDone
	result.RevocationStatus = probe.RevocationStatus
	result.RevocationSource = probe.RevocationSource

	setIssues(&result, computeIssues(&result, probe, weakProtocol))
	return result
}

// computeIssues runs after the WHOIS merge, so domain-registration fields on result
// are populated (or zero when the best-effort lookup failed — those rules stay quiet).
func computeIssues(result *CheckResult, probe *certprobe.Result, weakProtocol bool) []string {
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
		if matchesHostname(result.Hostname, san) {
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

	// Only a definitive revoked verdict is reported — "good" and "couldn't determine"
	// are both silent (see certprobe.CheckRevocation for why silence is correct there).
	if probe.RevocationStatus == certprobe.RevocationRevoked {
		issues = append(issues, "revoked")
	}

	if probe.WeakSignature {
		issues = append(issues, "weak-signature")
	}
	if probe.KeyType == "RSA" && probe.KeyBits > 0 && probe.KeyBits < minRSAKeyBits {
		issues = append(issues, "weak-key")
	}

	// Domain age is a phishing/typosquat signal, tiered: red inside 10 days, yellow
	// inside 30 — mutually exclusive by construction. A future-dated creation lands in
	// the red tier (negative age), which is the right call for such an anomaly. The raw
	// epoch field is compared, not the truncated DaysSinceRegistered int, so the issue
	// boundary coincides exactly with the resultTTL deadline for the same threshold.
	if result.DomainCreated > 0 {
		age := now.Sub(time.Unix(result.DomainCreated, 0))
		switch {
		case age < domainAgeCritical:
			issues = append(issues, "recently-registered")
		case age < domainAgeWarning:
			issues = append(issues, "young-domain")
		}
	}

	// Suppressed once the cert is actually expired — "expired" already covers it.
	if now.Before(probe.NotAfter) && probe.NotAfter.Sub(now) < certExpiryWarning {
		issues = append(issues, "cert-expiring-soon")
	}

	// Deliberately also fires for an already-lapsed registration: there is no separate
	// domain-expired issue to hand off to.
	if result.DomainExpires > 0 && time.Unix(result.DomainExpires, 0).Sub(now) < domainExpiryWarning {
		issues = append(issues, "domain-expiring-soon")
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
