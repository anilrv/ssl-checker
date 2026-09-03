// Package whois does a best-effort domain registration lookup by querying the domain's
// own registry directly — RDAP first, falling back to port-43 WHOIS text parsing for TLDs
// with no RDAP server (e.g. .be) — instead of going through a third-party API. Both
// protocol clients are vendored from github.com/lissy93/who-dat (internal/{domain, model,
// rdap, srcerr, whoisclient}; MIT licensed, see internal/LICENSE-who-dat), so this package
// has no third-party API dependency and no token to configure. Every failure mode
// (timeout, upstream error, no RDAP/WHOIS source for the TLD) is swallowed here — callers
// only ever see a nil *Info, never an error, since this is purely supplementary context
// and must never affect the main certificate check. Genuine failures are still logged at
// Error level via slog so they reach Application Insights — silent to the caller, not
// silent to us. A TLD with no usable data isn't logged: that's an expected outcome, not a
// failure.
package whois

import (
	"container/list"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"sslcheckerfunc/durablecache"
	"sslcheckerfunc/ssrfguard"
	"sslcheckerfunc/whois/internal/domain"
	"sslcheckerfunc/whois/internal/model"
	"sslcheckerfunc/whois/internal/rdap"
	"sslcheckerfunc/whois/internal/srcerr"
	"sslcheckerfunc/whois/internal/whoisclient"
)

const cacheTable = "sslcheckercache"
const cachePartition = "whois"

type Info struct {
	RegistrarName     string
	Created           time.Time
	Expires           time.Time
	DetectedProviders []string
	OwnerOrg          string
}

// ---- bounded in-memory cache, keyed by registrable domain: up to 500 entries, 30-day TTL ----
// Domain registration data changes rarely, but this keeps daysLeft-style figures
// reasonably fresh. Only successful lookups are cached — a transient outage self-heals
// on the next request instead of being stuck empty for a day. Each entry's TTL is
// capped at the domain's own expiration date so lapsed registration data isn't served.

type cacheItem struct {
	key       string
	info      Info
	expiresAt time.Time
}

type whoisCache struct {
	mu       sync.Mutex
	capacity int
	ll       *list.List
	items    map[string]*list.Element
}

func newWhoisCache(capacity int) *whoisCache {
	return &whoisCache{
		capacity: capacity,
		ll:       list.New(),
		items:    make(map[string]*list.Element),
	}
}

func (c *whoisCache) Get(key string) (Info, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		return Info{}, false
	}
	item := el.Value.(*cacheItem)
	if time.Now().After(item.expiresAt) {
		c.ll.Remove(el)
		delete(c.items, key)
		return Info{}, false
	}
	c.ll.MoveToFront(el)
	return item.info, true
}

func (c *whoisCache) Set(key string, info Info, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		item := el.Value.(*cacheItem)
		item.info = info
		item.expiresAt = time.Now().Add(ttl)
		c.ll.MoveToFront(el)
		return
	}

	item := &cacheItem{key: key, info: info, expiresAt: time.Now().Add(ttl)}
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

// Registration data barely changes day-to-day, and persistence (see durablecache below)
// means a cold start doesn't have to re-query a registry (or its RDAP/WHOIS server) for a
// domain this instance already resolved recently, even though there's no external quota
// pushing the TTL long the way whoisjson.com's request budget once did.
const cacheTTL = 30 * 24 * time.Hour

// minCacheTTL is the floor applied when the domain registration has already lapsed:
// the (accurate) lapsed data is still cached briefly, while a renewal shows up within
// minutes.
const minCacheTTL = 5 * time.Minute

// cappedTTL returns base reduced to the time remaining until the earliest non-zero
// deadline, floored at minCacheTTL once that remaining time reaches zero. A copy of
// this helper lives in main.go (per-package caches are deliberately self-contained
// in this repo).
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

var cache = newWhoisCache(500)

// source is satisfied by *rdap.Client and *whoisclient.Client. Kept local instead of
// pulling in who-dat's own internal/lookup, which bundles its own cache — this package
// already has one above, keyed and TTL'd the way this repo's other lookups are.
type source interface {
	Lookup(ctx context.Context, n domain.Name) (*model.Result, error)
}

// warmer is implemented by *rdap.Client (see WarmBootstrap's doc comment). Checked via an
// optional-interface assertion, not a direct call on rdapSource's concrete type, so a test
// fake substituted for rdapSource is never mistaken for the real thing and hit with a live
// network call to IANA.
type warmer interface {
	WarmBootstrap(ctx context.Context) error
}

var httpClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig:   rdap.TLSConfig(), // some registries need legacy RSA-CBC suites
		ForceAttemptHTTP2: true,             // the config above turns h2 off by default; some registries demand it
	},
}

var rdapSource source = rdap.NewClient(httpClient)
var whoisSource source = whoisclient.NewClient()

// bootstrapTimeout bounds warming the IANA RDAP registry (see WarmBootstrap), kept
// separate from lookupTimeout below so a cold start's registry fetch — rare, since it's
// cached in-process for 24h — never eats into the per-request budget and turns an
// otherwise-healthy lookup into a silent nil.
const bootstrapTimeout = 5 * time.Second

// lookupTimeout bounds the actual RDAP or WHOIS query, independent of how much of ctx's
// deadline remains. Longer than the 2s convention used elsewhere in this repo (see
// geoip.Lookup) since this package talks directly to whichever registry owns the TLD
// instead of one known-fast API host, and the WHOIS fallback in particular can involve a
// referral chain.
const lookupTimeout = 3 * time.Second

// Lookup returns domain registration info for hostname, or nil if unavailable for any
// reason (SSRF-guarded host, unparseable domain, no RDAP/WHOIS source for the TLD, request
// failure, timeout, bad response).
func Lookup(ctx context.Context, hostname string) *Info {
	if ssrfguard.NeverPubliclyResolvable(hostname) {
		return nil
	}

	name, err := domain.Parse(hostname)
	if err != nil {
		return nil
	}

	if info, ok := cache.Get(name.ASCII); ok {
		return &info
	}
	// Durable rows written before per-entry TTL capping (or written just inside the
	// minCacheTTL floor) can outlive the registration they describe; treat those as
	// misses rather than serving lapsed data. Rows written before the isEmpty guard
	// below existed can also carry a "successful" empty Info (zero Expires, so it'd
	// otherwise pass the freshness check here) — also treated as a miss so it retries
	// instead of serving no-data for whatever's left of its original 30-day TTL.
	if info, ok := durablecache.Get[Info](ctx, cacheTable, cachePartition, name.ASCII); ok &&
		(info.Expires.IsZero() || time.Now().Before(info.Expires)) && !isEmpty(info) {
		cache.Set(name.ASCII, info, cappedTTL(cacheTTL, info.Expires))
		return &info
	}

	if w, ok := rdapSource.(warmer); ok {
		bootstrapCtx, cancel := context.WithTimeout(ctx, bootstrapTimeout)
		_ = w.WarmBootstrap(bootstrapCtx) // best-effort; Lookup below surfaces the same failure itself
		cancel()
	}

	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	res, err := rdapSource.Lookup(lookupCtx, name)
	if errors.Is(err, srcerr.ErrNoSource) {
		res, err = whoisSource.Lookup(lookupCtx, name)
	}
	cancel()
	if err != nil {
		slog.ErrorContext(ctx, "whois: lookup failed", "domain", name.ASCII, "err", err)
		return nil
	}

	info := toInfo(res)

	// A result with none of these fields populated isn't a successful lookup — e.g. a
	// genuinely unregistered domain, or a registry with no usable data — and caching it
	// would freeze "no domain info" in place for the full 30-day TTL instead of
	// self-healing on the next request.
	if isEmpty(info) {
		return nil
	}

	ttl := cappedTTL(cacheTTL, info.Expires)
	cache.Set(name.ASCII, info, ttl)
	go durablecache.Set(context.Background(), cacheTable, cachePartition, name.ASCII, info, ttl)
	return &info
}

// toInfo maps the canonical who-dat result onto this package's public Info shape.
func toInfo(r *model.Result) Info {
	info := Info{DetectedProviders: detectProviders(r.Nameservers)}
	if r.Registrar.Name != nil {
		info.RegistrarName = *r.Registrar.Name
	}
	if r.Contacts.Registrant.Organization != nil {
		info.OwnerOrg = *r.Contacts.Registrant.Organization
	}
	if r.Dates.Created != nil {
		info.Created = *r.Dates.Created
	}
	if r.Dates.Expires != nil {
		info.Expires = *r.Dates.Expires
	}
	return info
}

// nsProviderPatterns maps a substring found in a nameserver hostname (matched
// case-insensitively) to the friendly hosting/DNS provider label it identifies. Neither
// RDAP nor WHOIS report this directly — who-dat's own hosted API doesn't compute it either
// — so this is a small local re-implementation of whoisjson.com's now-retired
// nsAnalysis.detectedProviders, covering the common providers.
var nsProviderPatterns = []struct {
	substr string
	label  string
}{
	{"awsdns", "aws-route53"},
	{"cloudflare", "cloudflare"},
	{"domaincontrol", "godaddy"},
	{"azure-dns", "azure-dns"},
	{"googledomains", "google-domains"},
	{"registrar-servers.com", "namecheap"},
	{"dnsmadeeasy", "dnsmadeeasy"},
	{"digitalocean", "digitalocean"},
	{"nsone.net", "ns1"},
	{"dynect.net", "dyn"},
	{"ultradns", "neustar-ultradns"},
	{"akam.net", "akamai"},
	{"vercel-dns.com", "vercel"},
	{"netlify", "netlify"},
	{"wixdns.net", "wix"},
	{"squarespacedns.com", "squarespace"},
	{"shopify", "shopify"},
	{"linode.com", "linode"},
	{"ovh.net", "ovh"},
	{"gandi.net", "gandi"},
	{"he.net", "hurricane-electric"},
	{"worldnic.com", "network-solutions"},
	{"bluehost.com", "bluehost"},
	{"hostgator.com", "hostgator"},
	{"dreamhost.com", "dreamhost"},
}

// detectProviders maps nameserver hostnames to the hosting/DNS providers they identify,
// deduplicated and in first-seen order.
func detectProviders(nameservers []model.Nameserver) []string {
	var providers []string
	seen := make(map[string]bool)
	for _, ns := range nameservers {
		lower := strings.ToLower(ns.Name)
		for _, p := range nsProviderPatterns {
			if strings.Contains(lower, p.substr) && !seen[p.label] {
				seen[p.label] = true
				providers = append(providers, p.label)
			}
		}
	}
	return providers
}

// isEmpty reports whether info carries no usable data at all — a "successful" lookup
// with every field at its zero value, which is not meaningfully different from a failed
// one and must not be cached (or trusted from a previously-cached row) as if it were.
func isEmpty(info Info) bool {
	return info.RegistrarName == "" && info.OwnerOrg == "" && len(info.DetectedProviders) == 0 &&
		info.Created.IsZero() && info.Expires.IsZero()
}
