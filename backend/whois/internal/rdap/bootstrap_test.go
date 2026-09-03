// Vendored from github.com/lissy93/who-dat (internal/rdap), MIT licensed — see
// ../LICENSE-who-dat. Unmodified from upstream.
package rdap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSeedsAreSane(t *testing.T) {
	for tld, urls := range seeds {
		if tld != strings.ToLower(tld) || len(urls) == 0 {
			t.Errorf("seed %q: TLDs are lowercase and need at least one URL", tld)
		}
		for _, u := range urls {
			if !strings.HasPrefix(u, "https://") || !strings.HasSuffix(u, "/") {
				t.Errorf("seed %q: %q must be https and end with /", tld, u)
			}
		}
	}
}

func TestBootstrapSeeds(t *testing.T) {
	// Fake IANA registry: knows com, and claims ch (so the seed must lose).
	iana := `{"services":[[["com"],["https://rdap.verisign.com/com/v1/"]],[["ch"],["https://iana.example/"]]]}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(iana))
	}))
	defer ts.Close()

	b := newBootstrap(ts.Client())
	b.url = ts.URL

	tests := []struct{ domain, want string }{
		{"vaduz.li", "https://rdap.nic.li/"},                 // seed fills the gap
		{"nic.ch", "https://iana.example/"},                  // IANA outranks the seed
		{"example.com", "https://rdap.verisign.com/com/v1/"}, // business as usual
	}
	for _, tt := range tests {
		urls, err := b.serversFor(context.Background(), tt.domain)
		if err != nil {
			t.Fatalf("%s: %v", tt.domain, err)
		}
		if urls[0] != tt.want {
			t.Errorf("%s = %q, want %q", tt.domain, urls[0], tt.want)
		}
	}
}
