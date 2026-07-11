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
)

type Info struct {
	RegistrarName     string
	Created           time.Time
	Expires           time.Time
	DetectedProviders []string
	OwnerOrg          string
}

// whoisjson.com's date fields use this layout, not RFC3339.
const whoisTimeLayout = "2006-01-02 15:04:05"

// ---- bounded in-memory cache, keyed by registrable domain: up to 500 entries, 24h TTL ----
// Domain registration data changes rarely, but this keeps daysLeft-style figures
// reasonably fresh. Only successful lookups are cached — a transient outage self-heals
// on the next request instead of being stuck empty for a day.

type cacheItem struct {
	key       string
	info      Info
	expiresAt time.Time
}

type whoisCache struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	ll       *list.List
	items    map[string]*list.Element
}

func newWhoisCache(capacity int, ttl time.Duration) *whoisCache {
	return &whoisCache{
		capacity: capacity,
		ttl:      ttl,
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

func (c *whoisCache) Set(key string, info Info) {
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

var cache = newWhoisCache(500, 24*time.Hour)

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

	cache.Set(domain, info)
	return &info
}
