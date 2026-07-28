package ssrfguard

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// swapEndpoints points dohQuery at test servers for the duration of a test.
func swapEndpoints(t *testing.T, endpoints []string) {
	t.Helper()
	old := dohEndpoints
	dohEndpoints = endpoints
	t.Cleanup(func() { dohEndpoints = old })
}

func TestResolveFallsBackWhenPrimaryDown(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer primary.Close()

	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") == "A" {
			fmt.Fprint(w, `{"Answer":[{"type":1,"data":"93.184.216.34"}]}`)
			return
		}
		fmt.Fprint(w, `{"Answer":[]}`)
	}))
	defer fallback.Close()

	swapEndpoints(t, []string{primary.URL, fallback.URL})

	ip, err := ResolvePublicIP(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("expected fallback resolver to answer, got error: %v", err)
	}
	if ip.String() != "93.184.216.34" {
		t.Errorf("got %s, want 93.184.216.34", ip)
	}
}

func TestResolveErrorsWhenAllResolversDown(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()

	swapEndpoints(t, []string{down.URL, down.URL})

	if _, err := ResolvePublicIP(context.Background(), "example.com"); err == nil {
		t.Fatal("expected an error when every resolver is down")
	}
}

func TestNeverPubliclyResolvable(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"printer.local", true},
		{"PRINTER.LOCAL", true}, // case-insensitive
		{"a.b.c.local", true},
		{"server.internal", true},
		{"router.home.arpa", true},
		{"foo.example", true},
		{"foo.test", true},
		{"foo.invalid", true},
		{"foo.onion", true},
		{"localhost", true}, // single-label, but exercised here in case a future caller skips ValidHostname
		{"192.168.0.85", true},
		{"8.8.8.8", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"example.com", false},  // real, deliberately-live IANA demo domain — must stay checkable
		{"sub.example.org", false},
		{"github.com", false},
		{"www.google.com", false},
	}
	for _, c := range cases {
		if got := NeverPubliclyResolvable(c.host); got != c.want {
			t.Errorf("NeverPubliclyResolvable(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestResolvePublicIPSkipsReservedAndIPLiteralHosts(t *testing.T) {
	hit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		fmt.Fprint(w, `{"Answer":[]}`)
	}))
	defer server.Close()
	swapEndpoints(t, []string{server.URL, server.URL})

	for _, host := range []string{"printer.local", "server.internal", "192.168.0.85", "::1"} {
		if _, err := ResolvePublicIP(context.Background(), host); err == nil {
			t.Errorf("ResolvePublicIP(%q): expected an error", host)
		}
	}
	if hit {
		t.Error("DoH endpoint was queried for a reserved/IP-literal hostname")
	}
}

func TestResolveDoesNotFallBackOnEmptyAnswer(t *testing.T) {
	// NXDOMAIN / no records is a real answer, not an outage — the second resolver must
	// not even be consulted.
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"Answer":[]}`)
	}))
	defer primary.Close()

	fallbackHits := 0
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackHits++
		fmt.Fprint(w, `{"Answer":[{"type":1,"data":"93.184.216.34"}]}`)
	}))
	defer fallback.Close()

	swapEndpoints(t, []string{primary.URL, fallback.URL})

	if _, err := ResolvePublicIP(context.Background(), "example.com"); err == nil {
		t.Error("expected a no-records error")
	}
	if fallbackHits != 0 {
		t.Errorf("fallback resolver was consulted %d times on an authoritative empty answer", fallbackHits)
	}
}
