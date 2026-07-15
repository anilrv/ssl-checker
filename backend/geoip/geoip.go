// Package geoip does a best-effort IP -> country/network lookup via ipgeolocation.io.
// Every failure mode (missing token, timeout, rate limit, bad response) is swallowed
// here — callers only ever see a nil *Info, never an error, since this is purely
// supplementary context and must never affect the main certificate check.
package geoip

import (
	"container/list"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"sslcheckerfunc/durablecache"
)

const cacheTable = "sslcheckercache"
const cachePartition = "geoip"
const flagsTable = "sslcheckerflags"
const flagsPartition = "flag"

type Info struct {
	Country         string
	CountryCode     string // ISO 3166-1 alpha-2, e.g. "IN" — the extension's last-resort flag fallback
	City            string
	CountryFlag     string // URL to a static flag image
	CountryFlagData string // the same flag as a data: URI; empty if the fetch failed (see fetchFlagData)
	ASN             string // e.g. "AS1257"
	ASName          string // e.g. "Tele2 Sverige AB"
}

// ---- bounded in-memory cache, keyed by IP: up to 500 entries, 7-day TTL ----
// IP-to-network mapping changes far less often than TLS certificate state, and multiple
// hostnames on shared hosting/CDNs resolve to the same IP, so a longer TTL keyed by IP
// (rather than hostname) meaningfully cuts down on API calls. Only successful lookups
// are cached — a transient outage self-heals on the next request instead of being stuck
// empty for a week.

type cacheItem struct {
	key       string
	info      Info
	expiresAt time.Time
}

type geoCache struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	ll       *list.List
	items    map[string]*list.Element
}

func newGeoCache(capacity int, ttl time.Duration) *geoCache {
	return &geoCache{
		capacity: capacity,
		ttl:      ttl,
		ll:       list.New(),
		items:    make(map[string]*list.Element),
	}
}

func (c *geoCache) Get(key string) (Info, bool) {
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

func (c *geoCache) Set(key string, info Info) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		item := el.Value.(*cacheItem)
		item.info = info
		item.expiresAt = time.Now().Add(c.ttl)
		c.ll.MoveToFront(el)
		return
	}

	item := &cacheItem{key: key, info: info, expiresAt: time.Now().Add(c.ttl)}
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

const cacheTTL = 7 * 24 * time.Hour

var cache = newGeoCache(500, cacheTTL)

var httpClient = &http.Client{}

// Lookup returns network/country info for ip, or nil if unavailable for any reason
// (no IPGEOLOCATION_TOKEN configured, request failure, timeout, rate limit, bad
// response). Bounded to 2 seconds regardless of how much of ctx's deadline remains, so a
// slow or down provider never meaningfully delays the caller.
func Lookup(ctx context.Context, ip net.IP) *Info {
	key := ip.String()
	if info, ok := cache.Get(key); ok {
		return &info
	}
	if info, ok := durablecache.Get[Info](ctx, cacheTable, cachePartition, key); ok {
		cache.Set(key, info)
		return &info
	}

	token := os.Getenv("IPGEOLOCATION_TOKEN")
	if token == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// ipgeolocation.io takes the API key as a query parameter, not a header.
	reqURL := "https://api.ipgeolocation.io/v3/ipgeo?apiKey=" + url.QueryEscape(token) + "&ip=" + url.QueryEscape(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var body struct {
		Location struct {
			CountryName string `json:"country_name"`
			CountryCode string `json:"country_code2"`
			City        string `json:"city"`
			CountryFlag string `json:"country_flag"`
		} `json:"location"`
		ASN struct {
			ASNumber     string `json:"as_number"`
			Organization string `json:"organization"`
		} `json:"asn"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil
	}

	info := Info{
		Country:         body.Location.CountryName,
		CountryCode:     body.Location.CountryCode,
		City:            body.Location.City,
		CountryFlag:     body.Location.CountryFlag,
		CountryFlagData: fetchFlagData(body.Location.CountryFlag),
		ASN:             body.ASN.ASNumber,
		ASName:          body.ASN.Organization,
	}
	cache.Set(key, info)
	go durablecache.Set(context.Background(), cacheTable, cachePartition, key, info, cacheTTL)
	return &info
}

// ---- flag image, embedded as a data: URI ----
// The extension renders the flag inside pages it doesn't control; cross-origin-isolated
// pages (COEP: require-corp — e.g. web.whatsapp.com) block <img> loads from third-party
// hosts that don't send CORP headers, which ipgeolocation.io's static server doesn't.
// Embedding the image as a data: URI sidesteps that entirely (data URIs are same-origin
// by definition) and means the user's browser never contacts ipgeolocation.io at all.

// There are only ~250 distinct country flags, so a simple grow-only map with a cap is
// enough — no TTL or eviction needed. The cap is just a safety net against a misbehaving
// upstream returning unique URLs per request.
var (
	flagMu    sync.Mutex
	flagCache = make(map[string]string)
)

const flagCacheCap = 300
const flagMaxBytes = 16 * 1024

// fetchFlagData downloads flagURL and returns it as a data: URI, or "" on any failure —
// best-effort like everything else in this package; the URL field remains as a fallback.
// Bounded by its own short timeout so it can't meaningfully delay the caller.
func fetchFlagData(flagURL string) string {
	if flagURL == "" {
		return ""
	}

	flagMu.Lock()
	cached, ok := flagCache[flagURL]
	flagMu.Unlock()
	if ok {
		return cached
	}
	// Durable second tier: only ~250 distinct country flags exist, so once one is captured
	// here it never needs to be re-fetched from the flag host again, even across cold
	// starts — stored with no TTL (see Set's ttl <= 0 semantics).
	if uri, ok := durablecache.Get[string](context.Background(), flagsTable, flagsPartition, flagURL); ok {
		flagMu.Lock()
		if len(flagCache) < flagCacheCap {
			flagCache[flagURL] = uri
		}
		flagMu.Unlock()
		return uri
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, flagURL, nil)
	if err != nil {
		return ""
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(contentType, "image/") {
		return ""
	}

	// +1 so a body exactly at the limit is distinguishable from one that exceeds it.
	data, err := io.ReadAll(io.LimitReader(resp.Body, flagMaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > flagMaxBytes {
		return ""
	}

	uri := "data:" + contentType + ";base64," + base64.StdEncoding.EncodeToString(data)

	flagMu.Lock()
	if len(flagCache) < flagCacheCap {
		flagCache[flagURL] = uri
	}
	flagMu.Unlock()
	go durablecache.Set(context.Background(), flagsTable, flagsPartition, flagURL, uri, 0)
	return uri
}
