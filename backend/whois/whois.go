// Package whois does a best-effort domain registration lookup via whoisjson.com. Every
// failure mode (missing token, timeout, rate limit, bad response) is swallowed here —
// callers only ever see a nil *Info, never an error, since this is purely supplementary
// context and must never affect the main certificate check.
package whois

import (
	"container/list"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"sslcheckerfunc/durablecache"
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

// registrarResponse mirrors only the fields we use from whoisjson.com's response.
type registrarResponse struct {
	Registrar struct {
		Name string `json:"name"`
	} `json:"registrar"`
	Created    string `json:"created"`
	Expires    string `json:"expires"`
	NSAnalysis struct {
		DetectedProviders []string `json:"detectedProviders"`
	} `json:"nsAnalysis"`
	Contacts struct {
		Owner []struct {
			Organization string `json:"organization"`
		} `json:"owner"`
	} `json:"contacts"`
}

// Lookup returns domain registration info for hostname, or nil if unavailable for any
// reason (no WHOISJSON_TOKEN configured, request failure, timeout, bad response).
// Bounded to 2 seconds regardless of how much of ctx's deadline remains.
func Lookup(ctx context.Context, hostname string) *Info {
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
		return nil
	}
	req.Header.Set("Authorization", "TOKEN="+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var body registrarResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil
	}

	info := Info{
		RegistrarName:     body.Registrar.Name,
		DetectedProviders: body.NSAnalysis.DetectedProviders,
	}
	if t, err := time.Parse(whoisTimeLayout, body.Created); err == nil {
		info.Created = t
	}
	if t, err := time.Parse(whoisTimeLayout, body.Expires); err == nil {
		info.Expires = t
	}
	if len(body.Contacts.Owner) > 0 {
		info.OwnerOrg = body.Contacts.Owner[0].Organization
	}

	ttl := cappedTTL(cacheTTL, info.Expires)
	cache.Set(domain, info, ttl)
	go durablecache.Set(context.Background(), cacheTable, cachePartition, domain, info, ttl)
	return &info
}
