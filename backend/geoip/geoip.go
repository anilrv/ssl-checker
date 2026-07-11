// Package geoip does a best-effort IP -> country/network lookup via ipgeolocation.io.
// Every failure mode (missing token, timeout, rate limit, bad response) is swallowed
// here — callers only ever see a nil *Info, never an error, since this is purely
// supplementary context and must never affect the main certificate check.
package geoip

import (
	"container/list"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

type Info struct {
	Country     string
	City        string
	CountryFlag string // URL to a static flag image
	ASN         string // e.g. "AS1257"
	ASName      string // e.g. "Tele2 Sverige AB"
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

var cache = newGeoCache(500, 7*24*time.Hour)

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
		Country:     body.Location.CountryName,
		City:        body.Location.City,
		CountryFlag: body.Location.CountryFlag,
		ASN:         body.ASN.ASNumber,
		ASName:      body.ASN.Organization,
	}
	cache.Set(key, info)
	return &info
}
