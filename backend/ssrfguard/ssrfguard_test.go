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
