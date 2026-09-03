package whois

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/azure/azure-functions-golang-worker/sdk"

	"sslcheckerfunc/whois/internal/domain"
	"sslcheckerfunc/whois/internal/model"
	"sslcheckerfunc/whois/internal/srcerr"
)

// fakeSource is a source that returns a canned result/error, letting tests exercise
// Lookup's caching/mapping/fallback logic without a real RDAP or WHOIS network call. It
// deliberately does not implement warmer, so swapping it in for rdapSource also disables
// Lookup's bootstrap warm-up — no test here should ever reach the real IANA registry.
type fakeSource struct {
	result *model.Result
	err    error
}

func (f fakeSource) Lookup(ctx context.Context, n domain.Name) (*model.Result, error) {
	return f.result, f.err
}

func withSources(t *testing.T, rdapFake, whoisFake source) {
	t.Helper()
	oldRDAP, oldWhois := rdapSource, whoisSource
	rdapSource, whoisSource = rdapFake, whoisFake
	t.Cleanup(func() { rdapSource, whoisSource = oldRDAP, oldWhois })
}

func TestLookupSkipsReservedAndIPLiteralHosts(t *testing.T) {
	withSources(t,
		fakeSource{err: errors.New("unexpected: rdap should never be called")},
		fakeSource{err: errors.New("unexpected: whois should never be called")},
	)

	for _, host := range []string{"printer.local", "server.internal", "a.b.c.local", "192.168.0.85", "8.8.8.8", "::1"} {
		if info := Lookup(context.Background(), host); info != nil {
			t.Errorf("Lookup(%q) = %+v, want nil", host, info)
		}
	}
}

func TestLookupMapsRDAPResultAndDetectsProvider(t *testing.T) {
	created := time.Date(2007, 8, 22, 0, 0, 0, 0, time.UTC)
	expires := time.Date(2028, 4, 30, 0, 0, 0, 0, time.UTC)
	result := &model.Result{
		Registrar: model.Registrar{Name: model.Str("NameWeb BVBA")},
		Nameservers: []model.Nameserver{
			{Name: "ns-1807.awsdns-33.co.uk"},
			{Name: "ns-1807.awsdns-33.com"}, // same provider again — must not duplicate
		},
		Dates: model.Dates{Created: &created, Expires: &expires},
		Contacts: model.Contacts{
			Registrant: model.Contact{Organization: model.Str("NameWeb BV")},
		},
	}
	withSources(t, fakeSource{result: result}, fakeSource{err: errors.New("unexpected: whois fallback should not run when rdap succeeds")})

	info := Lookup(context.Background(), "example-nameweb-test.com")
	if info == nil {
		t.Fatal("Lookup returned nil, want a populated Info")
	}
	if info.RegistrarName != "NameWeb BVBA" {
		t.Errorf("RegistrarName = %q, want %q", info.RegistrarName, "NameWeb BVBA")
	}
	if info.OwnerOrg != "NameWeb BV" {
		t.Errorf("OwnerOrg = %q, want %q", info.OwnerOrg, "NameWeb BV")
	}
	if !info.Created.Equal(created) {
		t.Errorf("Created = %v, want %v", info.Created, created)
	}
	if !info.Expires.Equal(expires) {
		t.Errorf("Expires = %v, want %v", info.Expires, expires)
	}
	if want := []string{"aws-route53"}; len(info.DetectedProviders) != 1 || info.DetectedProviders[0] != want[0] {
		t.Errorf("DetectedProviders = %v, want %v", info.DetectedProviders, want)
	}
}

func TestLookupFallsBackToWhoisWhenNoRDAPSource(t *testing.T) {
	whoisResult := &model.Result{Registrar: model.Registrar{Name: model.Str("Registrar via WHOIS fallback")}}
	withSources(t,
		fakeSource{err: srcerr.ErrNoSource},
		fakeSource{result: whoisResult},
	)

	info := Lookup(context.Background(), "example-fallback-test.com")
	if info == nil {
		t.Fatal("Lookup returned nil, want the WHOIS fallback's result")
	}
	if info.RegistrarName != "Registrar via WHOIS fallback" {
		t.Errorf("RegistrarName = %q, want the WHOIS fallback's value", info.RegistrarName)
	}
}

func TestLookupReturnsNilWithoutCachingOnEmptyResult(t *testing.T) {
	withSources(t, fakeSource{result: &model.Result{}}, fakeSource{})

	host := "example-empty-result-test.com"
	if info := Lookup(context.Background(), host); info != nil {
		t.Fatalf("Lookup = %+v, want nil for an all-empty result", info)
	}
	if _, ok := cache.Get(host); ok {
		t.Error("an empty result must not be cached")
	}
}

// TestLookupLogsOnFailure verifies a genuine lookup failure actually reaches slog, not
// just that the code path compiles.
func TestLookupLogsOnFailure(t *testing.T) {
	withSources(t, fakeSource{err: errors.New("simulated registry failure")}, fakeSource{})

	var buf bytes.Buffer
	oldDefault := slog.Default()
	slog.SetDefault(slog.New(sdk.NewLogHandler(slog.NewJSONHandler(&buf, nil))))
	t.Cleanup(func() { slog.SetDefault(oldDefault) })

	if info := Lookup(context.Background(), "logging-check-whois-test.com"); info != nil {
		t.Fatalf("Lookup = %+v, want nil on lookup failure", info)
	}

	var record struct {
		Level string `json:"level"`
		Msg   string `json:"msg"`
	}
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("expected one JSON log record, got %q (err: %v)", buf.String(), err)
	}
	if record.Level != slog.LevelError.String() {
		t.Errorf("level = %q, want %q", record.Level, slog.LevelError.String())
	}
	if record.Msg != "whois: lookup failed" {
		t.Errorf("msg = %q, want %q", record.Msg, "whois: lookup failed")
	}
}

func TestDetectProviders(t *testing.T) {
	tests := []struct {
		name string
		ns   []string
		want []string
	}{
		{"aws route53", []string{"ns-1807.awsdns-33.co.uk", "ns-200.awsdns-25.com"}, []string{"aws-route53"}},
		{"cloudflare", []string{"lucy.ns.cloudflare.com", "sam.ns.cloudflare.com"}, []string{"cloudflare"}},
		{"multiple distinct providers", []string{"dns1.registrar-servers.com", "ns1.digitalocean.com"}, []string{"namecheap", "digitalocean"}},
		{"unknown nameserver", []string{"ns1.some-unheard-of-host.example"}, nil},
		{"no nameservers", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nss []model.Nameserver
			for _, n := range tt.ns {
				nss = append(nss, model.Nameserver{Name: n})
			}
			got := detectProviders(nss)
			if len(got) != len(tt.want) {
				t.Fatalf("detectProviders(%v) = %v, want %v", tt.ns, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("detectProviders(%v) = %v, want %v", tt.ns, got, tt.want)
				}
			}
		})
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
