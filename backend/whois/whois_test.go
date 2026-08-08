package whois

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLookupSkipsReservedAndIPLiteralHosts(t *testing.T) {
	t.Setenv("WHOISJSON_TOKEN", "dummy-token")

	oldTransport := httpClient.Transport
	httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected outbound request to %s", r.URL)
		return nil, nil
	})
	t.Cleanup(func() { httpClient.Transport = oldTransport })

	for _, host := range []string{"printer.local", "server.internal", "a.b.c.local", "192.168.0.85", "8.8.8.8", "::1"} {
		if info := Lookup(context.Background(), host); info != nil {
			t.Errorf("Lookup(%q) = %+v, want nil", host, info)
		}
	}
}

// dominosResponse is the real whoisjson.com payload for dominos.co.in, captured while
// diagnosing why pizzaonline.dominos.co.in showed no domain-registration info. Its
// "contacts" field is a bare [], not the usual {"owner": [...]} object.
const dominosResponse = `{
	"server": "Iota",
	"name": "dominos.co.in",
	"status": "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
	"nameserver": ["NS-1807.AWSDNS-33.CO.UK"],
	"created": "2005-03-03 06:53:08",
	"changed": "2026-03-02 09:18:43",
	"expires": "2031-03-03 06:53:08",
	"registered": true,
	"dnssec": "unsigned",
	"whoisserver": "whois.101domain.com",
	"contacts": [],
	"registrar": {
		"id": "1011",
		"name": "https://www.101domain.com/",
		"email": "abuse@101domain.com",
		"url": "https://www.101domain.com/",
		"phone": "+1.8582954626"
	},
	"network": null,
	"exception": null,
	"parsedContacts": false,
	"source": "whois"
}`

func TestLookupSurvivesArrayShapedContacts(t *testing.T) {
	t.Setenv("WHOISJSON_TOKEN", "dummy-token")

	oldTransport := httpClient.Transport
	httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(dominosResponse)),
			Header:     make(http.Header),
		}, nil
	})
	t.Cleanup(func() { httpClient.Transport = oldTransport })

	info := Lookup(context.Background(), "pizzaonline.dominos.co.in")
	if info == nil {
		t.Fatal("Lookup returned nil; a shape mismatch on one field should not discard the whole response")
	}
	if info.RegistrarName != "https://www.101domain.com/" {
		t.Errorf("RegistrarName = %q, want the registrar URL", info.RegistrarName)
	}
	wantCreated := time.Date(2005, 3, 3, 6, 53, 8, 0, time.UTC)
	if !info.Created.Equal(wantCreated) {
		t.Errorf("Created = %v, want %v", info.Created, wantCreated)
	}
	wantExpires := time.Date(2031, 3, 3, 6, 53, 8, 0, time.UTC)
	if !info.Expires.Equal(wantExpires) {
		t.Errorf("Expires = %v, want %v", info.Expires, wantExpires)
	}
	if info.OwnerOrg != "" {
		t.Errorf("OwnerOrg = %q, want empty (contacts carried no owner data)", info.OwnerOrg)
	}
}

func TestCappedTTL(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name      string
		deadlines []time.Time
		want      time.Duration
	}{
		{name: "no deadlines", deadlines: nil, want: cacheTTL},
		{name: "zero deadline ignored", deadlines: []time.Time{{}}, want: cacheTTL},
		{name: "deadline beyond base", deadlines: []time.Time{now.Add(60 * 24 * time.Hour)}, want: cacheTTL},
		{name: "deadline inside base", deadlines: []time.Time{now.Add(48 * time.Hour)}, want: 48 * time.Hour},
		{name: "deadline within floor window stays exact", deadlines: []time.Time{now.Add(2 * time.Minute)}, want: 2 * time.Minute},
		{name: "past deadline floors", deadlines: []time.Time{now.Add(-time.Hour)}, want: minCacheTTL},
	}
	for _, c := range cases {
		got := cappedTTL(cacheTTL, c.deadlines...)
		// cappedTTL calls time.Now() itself, so allow a small skew.
		if diff := got - c.want; diff < -time.Second || diff > time.Second {
			t.Errorf("%s: got %v, want ~%v", c.name, got, c.want)
		}
	}
}

func TestWhoisCacheHonorsPerEntryTTL(t *testing.T) {
	c := newWhoisCache(10)

	c.Set("live.example", Info{RegistrarName: "live"}, time.Hour)
	if _, ok := c.Get("live.example"); !ok {
		t.Error("entry with 1h TTL should be a hit")
	}

	c.Set("dead.example", Info{RegistrarName: "dead"}, -time.Second)
	if _, ok := c.Get("dead.example"); ok {
		t.Error("entry with already-elapsed TTL should be a miss")
	}

	// Updating an existing entry must apply the new TTL, not the original one.
	c.Set("live.example", Info{RegistrarName: "live"}, -time.Second)
	if _, ok := c.Get("live.example"); ok {
		t.Error("updated entry with elapsed TTL should be a miss")
	}
}
