// Vendored from github.com/lissy93/who-dat (internal/rdap), MIT licensed — see
// ../LICENSE-who-dat. Unmodified from upstream.
package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"sslcheckerfunc/whois/internal/srcerr"
)

// bootstrapURL is the IANA RDAP bootstrap registry for DNS.
const bootstrapURL = "https://data.iana.org/rdap/dns.json"

// bootstrapTTL is how long a fetched registry is trusted before re-fetching.
const bootstrapTTL = 24 * time.Hour

// seeds covers registries that run perfectly good RDAP but never told IANA
// (rdap.org calls these "stealth" servers). Every entry is verified against a
// live domain before landing here; add one line per missing TLD. If a TLD
// later shows up in the IANA registry, that entry wins and the seed retires.
var seeds = map[string][]string{
	"ac":               {"https://rdap.identitydigital.services/rdap/"},
	"af":               {"https://whois.nic.af/"}, // whois by name, rdap by nature
	"ag":               {"https://rdap.identitydigital.services/rdap/"},
	"arpa":             {"https://rdap.iana.org/"},
	"aw":               {"https://rdap.nic.aw/"},
	"bh":               {"https://rdap.centralnic.com/bh/"},
	"bw":               {"https://rdap.nic.net.bw/"},
	"bz":               {"https://rdap.identitydigital.services/rdap/"},
	"ch":               {"https://rdap.nic.ch/"},
	"ci":               {"https://rdap.nic.ci/"},
	"co":               {"https://rdap.registry.co/co/"},
	"de":               {"https://rdap.denic.de/"},
	"dm":               {"https://rdap.dmdomains.dm/rdap/"},
	"ga":               {"https://rdap.nic.ga/"},
	"gi":               {"https://rdap.identitydigital.services/rdap/"},
	"gl":               {"https://rdap.centralnic.com/gl/"},
	"io":               {"https://rdap.identitydigital.services/rdap/"},
	"iq":               {"https://rdap.reg.iq/rdap/"},
	"ki":               {"https://rdap.coccaregistry.org/"},
	"kz":               {"https://rdap.nic.kz/"},
	"lc":               {"https://rdap.identitydigital.services/rdap/"},
	"li":               {"https://rdap.nic.li/"},
	"me":               {"https://rdap.identitydigital.services/rdap/"},
	"mn":               {"https://rdap.identitydigital.services/rdap/"},
	"mr":               {"https://rdap.nic.mr/"},
	"my":               {"https://rdap.mynic.my/rdap/"},
	"mz":               {"https://rdap.nic.mz/"},
	"om":               {"https://rdap.registry.om/"},
	"pr":               {"https://rdap.identitydigital.services/rdap/"},
	"ru":               {"https://cctld.ru/tci-ripn-rdap/"},
	"sb":               {"https://rdap.nic.sb/"},
	"sc":               {"https://rdap.identitydigital.services/rdap/"},
	"sh":               {"https://rdap.identitydigital.services/rdap/"},
	"sk":               {"https://rdap.sk-nic.sk/sk/"},
	"so":               {"https://rdap.nic.so/"},
	"td":               {"https://rdap.nic.td/"},
	"tl":               {"https://rdap.nic.tl/"},
	"us":               {"https://rdap.nic.us/"},
	"vc":               {"https://rdap.identitydigital.services/rdap/"},
	"ve":               {"https://rdap.nic.ve/rdap/"},
	"vu":               {"https://rdap.dnrs.vu/"},
	"ws":               {"https://rdap.website.ws/"},
	"xn--kprw13d":      {"https://ccrdap.twnic.tw/taiwan/"},               // Taiwan IDN, twin of IANA-listed xn--kpry57d
	"xn--mgbcpq6gpa1a": {"https://rdap.centralnic.com/xn--mgbcpq6gpa1a/"}, // Bahrain IDN
	"xn--p1ai":         {"https://cctld.ru/tci-ripn-rdap/"},               // Cyrillic .rf
}

// bootstrap resolves a TLD to its RDAP base URLs using the IANA registry, which it
// fetches once and refreshes lazily.
type bootstrap struct {
	http *http.Client
	url  string

	mu        sync.RWMutex
	services  map[string][]string
	fetchedAt time.Time
}

func newBootstrap(httpClient *http.Client) *bootstrap {
	return &bootstrap{http: httpClient, url: bootstrapURL}
}

// dnsRegistry mirrors the IANA bootstrap file: each service is [[tlds...], [urls...]].
type dnsRegistry struct {
	Services [][][]string `json:"services"`
}

// serversFor returns the RDAP base URLs for the registrable domain's TLD, picking the
// longest matching suffix. Returns srcerr.ErrNoSource when no TLD entry matches.
func (b *bootstrap) serversFor(ctx context.Context, asciiDomain string) ([]string, error) {
	if err := b.ensure(ctx); err != nil {
		return nil, err
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	labels := strings.Split(asciiDomain, ".")
	for i := range labels {
		if urls, ok := b.services[strings.Join(labels[i:], ".")]; ok {
			return urls, nil
		}
	}
	return nil, srcerr.ErrNoSource
}

func (b *bootstrap) ensure(ctx context.Context) error {
	b.mu.RLock()
	fresh := b.services != nil && time.Since(b.fetchedAt) < bootstrapTTL
	b.mu.RUnlock()
	if fresh {
		return nil
	}
	return b.fetch(ctx)
}

func (b *bootstrap) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.url, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", srcerr.ErrUpstream, err)
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := b.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: bootstrap fetch: %v", srcerr.ErrUpstream, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: bootstrap status %d", srcerr.ErrUpstream, resp.StatusCode)
	}

	var reg dnsRegistry
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&reg); err != nil {
		return fmt.Errorf("%w: bootstrap decode: %v", srcerr.ErrUpstream, err)
	}

	services := make(map[string][]string)
	for _, svc := range reg.Services {
		if len(svc) < 2 {
			continue
		}
		for _, tld := range svc[0] {
			services[strings.ToLower(tld)] = svc[1]
		}
	}
	if len(services) == 0 {
		return fmt.Errorf("%w: empty bootstrap registry", srcerr.ErrUpstream)
	}
	for tld, urls := range seeds {
		if _, ok := services[tld]; !ok {
			services[tld] = urls
		}
	}

	b.mu.Lock()
	b.services = services
	b.fetchedAt = time.Now()
	b.mu.Unlock()
	return nil
}
