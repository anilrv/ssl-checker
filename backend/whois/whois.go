// Package whois does a best-effort domain registration lookup via whoisjson.com. Every
// failure mode (missing token, timeout, rate limit, bad response) is swallowed here —
// callers only ever see a nil *Info, never an error, since this is purely supplementary
// context and must never affect the main certificate check. Genuine failures (network
// error, non-200, undecodable body) are still logged at Error level via slog so they
// reach Application Insights — silent to the caller, not silent to us. A missing token
// or an upstream response with no usable data isn't logged: those are expected outcomes,
// not failures.
package whois

import (
	"container/list"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"sslcheckerfunc/durablecache"
	"sslcheckerfunc/ssrfguard"
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

// whoisjson.com's date fields use this layout, not RFC3339.
const whoisTimeLayout = "2006-01-02 15:04:05"

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

// Registration data barely changes day-to-day, and persistence (see durablecache below) is
// what finally makes a long TTL pay off against whoisjson.com's tight 1000-request/month
// budget (~33/day) — a short TTL only mattered when the cache was purely in-memory and
// wiped on every cold start anyway.
const cacheTTL = 30 * 24 * time.Hour

// minCacheTTL is the floor applied when the domain registration has already lapsed:
// the (accurate) lapsed data is still cached briefly to protect the tight monthly
// request budget, while a renewal shows up within minutes.
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

var httpClient = &http.Client{}

// Decoded field-by-field, not into one struct: whoisjson.com sends "contacts" as
// {"owner": [...]} normally but as a bare [] for privacy-redacted domains, and a single
// field's shape mismatch would otherwise fail encoding/json's decode of the whole object
// — discarding registrar/created/expires along with it even though those decoded fine.
type registrarField struct {
	Name string `json:"name"`
}

type nsAnalysisField struct {
	DetectedProviders []string `json:"detectedProviders"`
}

type contactsField struct {
	Owner []struct {
		Organization string `json:"organization"`
	} `json:"owner"`
}

// decodeField unmarshals raw[key] into dst, leaving dst untouched if the key is absent
// or its value doesn't match dst's shape.
func decodeField(raw map[string]json.RawMessage, key string, dst any) {
	if v, ok := raw[key]; ok {
		_ = json.Unmarshal(v, dst)
	}
}

// Lookup returns domain registration info for hostname, or nil if unavailable for any
// reason (no WHOISJSON_TOKEN configured, request failure, timeout, bad response).
// Bounded to 2 seconds regardless of how much of ctx's deadline remains.
func Lookup(ctx context.Context, hostname string) *Info {
	if ssrfguard.NeverPubliclyResolvable(hostname) {
		return nil
	}

	domain, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		domain = hostname // best-effort fallback (e.g. bare TLDs, unusual hosts)
	}

	if info, ok := cache.Get(domain); ok {
		return &info
	}
	// Durable rows written before per-entry TTL capping (or written just inside the
	// minCacheTTL floor) can outlive the registration they describe; treat those as
	// misses rather than serving lapsed data.
	if info, ok := durablecache.Get[Info](ctx, cacheTable, cachePartition, domain); ok &&
		(info.Expires.IsZero() || time.Now().Before(info.Expires)) {
		cache.Set(domain, info, cappedTTL(cacheTTL, info.Expires))
		return &info
	}

	token := os.Getenv("WHOISJSON_TOKEN")
	if token == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://whoisjson.com/api/v1/whois?domain="+domain, nil)
	if err != nil {
		slog.ErrorContext(ctx, "whois: building request failed", "domain", domain, "err", err)
		return nil
	}
	req.Header.Set("Authorization", "TOKEN="+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "whois: request failed", "domain", domain, "err", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.ErrorContext(ctx, "whois: non-200 response", "domain", domain, "status", resp.StatusCode)
		return nil
	}

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		slog.ErrorContext(ctx, "whois: decoding response failed", "domain", domain, "err", err)
		return nil
	}

	var registrar registrarField
	decodeField(raw, "registrar", &registrar)
	var nsAnalysis nsAnalysisField
	decodeField(raw, "nsAnalysis", &nsAnalysis)
	var contacts contactsField
	decodeField(raw, "contacts", &contacts)
	var created, expires string
	decodeField(raw, "created", &created)
	decodeField(raw, "expires", &expires)

	info := Info{
		RegistrarName:     registrar.Name,
		DetectedProviders: nsAnalysis.DetectedProviders,
	}
	if t, err := time.Parse(whoisTimeLayout, created); err == nil {
		info.Created = t
	}
	if t, err := time.Parse(whoisTimeLayout, expires); err == nil {
		info.Expires = t
	}
	if len(contacts.Owner) > 0 {
		info.OwnerOrg = contacts.Owner[0].Organization
	}

	// A 200 with none of these fields populated isn't a successful lookup — e.g. a
	// registry whoisjson.com has no usable data for — and caching it would freeze
	// "no domain info" in place for the full 30-day TTL instead of self-healing on
	// the next request.
	if info.RegistrarName == "" && info.OwnerOrg == "" && len(info.DetectedProviders) == 0 &&
		info.Created.IsZero() && info.Expires.IsZero() {
		return nil
	}

	ttl := cappedTTL(cacheTTL, info.Expires)
	cache.Set(domain, info, ttl)
	go durablecache.Set(context.Background(), cacheTable, cachePartition, domain, info, ttl)
	return &info
}
