// Package ssrfguard resolves a hostname via DNS-over-HTTPS and returns only a PUBLIC
// IP address to connect to. This is the core SSRF defense: the live-TLS probe must
// never be pointed at a private, loopback, link-local, or reserved address (including
// cloud metadata endpoints).
package ssrfguard

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

var ipv4Blocklist []*net.IPNet
var ipv6Blocklist []*net.IPNet

func mustParseCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			panic(fmt.Sprintf("ssrfguard: invalid CIDR %q: %v", c, err))
		}
		out = append(out, ipnet)
	}
	return out
}

func init() {
	ipv4Blocklist = mustParseCIDRs([]string{
		"0.0.0.0/8",          // "this network"
		"10.0.0.0/8",         // private
		"100.64.0.0/10",      // shared address space / CGNAT
		"127.0.0.0/8",        // loopback
		"169.254.0.0/16",     // link-local (includes 169.254.169.254 cloud metadata)
		"172.16.0.0/12",      // private
		"192.0.0.0/24",       // IETF protocol assignments
		"192.0.2.0/24",       // documentation TEST-NET-1
		"192.88.99.0/24",     // deprecated 6to4 relay anycast
		"192.168.0.0/16",     // private
		"198.18.0.0/15",      // benchmarking
		"198.51.100.0/24",    // documentation TEST-NET-2
		"203.0.113.0/24",     // documentation TEST-NET-3
		"224.0.0.0/4",        // multicast
		"240.0.0.0/4",        // reserved
		"255.255.255.255/32", // broadcast
	})
	ipv6Blocklist = mustParseCIDRs([]string{
		"::/128",         // unspecified
		"::1/128",        // loopback
		"::ffff:0:0/96",  // IPv4-mapped (blocked wholesale)
		"64:ff9b::/96",   // NAT64
		"64:ff9b:1::/48", // NAT64 (RFC 8215)
		"100::/64",       // discard-only
		"2001:db8::/32",  // documentation
		"fc00::/7",       // unique local (private)
		"fe80::/10",      // link-local
		"ff00::/8",       // multicast
	})
}

func isPublicIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		for _, b := range ipv4Blocklist {
			if b.Contains(ip4) {
				return false
			}
		}
		return true
	}
	for _, b := range ipv6Blocklist {
		if b.Contains(ip) {
			return false
		}
	}
	return true
}

var hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

// ValidHostname reports whether s looks like a syntactically valid DNS hostname
// (RFC-1123-ish labels, no scheme/path/whitespace, reasonable length). It does not
// perform any lookup.
func ValidHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	return hostnameRe.MatchString(s)
}

type dohAnswer struct {
	Type int    `json:"type"`
	Data string `json:"data"`
}
type dohResponse struct {
	Answer []dohAnswer `json:"Answer"`
}

// Two independently operated DoH resolvers, tried in order — both speak the same
// dns-json schema, so a Cloudflare outage degrades to Google instead of failing every
// uncached check (DoH is the one external dependency the probe can't work without).
var dohEndpoints = []string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/resolve",
}

var httpClient = &http.Client{}

func dohQuery(ctx context.Context, hostname, qtype string) ([]string, error) {
	var lastErr error
	for _, endpoint := range dohEndpoints {
		out, err := dohQueryOne(ctx, endpoint, hostname, qtype)
		if err == nil {
			// A successful query with zero answers (NXDOMAIN, no records of this type) is
			// a real answer, not an outage — asking another resolver wouldn't change it.
			return out, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func dohQueryOne(ctx context.Context, endpoint, hostname, qtype string) ([]string, error) {
	// Per-attempt sub-deadline: a primary that HANGS (rather than failing fast) must not
	// eat ResolvePublicIP's whole 5s budget and starve the fallback of time to answer.
	ctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	reqURL := fmt.Sprintf("%s?name=%s&type=%s", endpoint, url.QueryEscape(hostname), qtype)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	// Required by Cloudflare to get the JSON form; dns.google/resolve ignores it.
	req.Header.Set("Accept", "application/dns-json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh query returned status %d", resp.StatusCode)
	}

	var parsed dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}

	wantType := 1 // A
	if qtype == "AAAA" {
		wantType = 28
	}
	var out []string
	for _, a := range parsed.Answer {
		if a.Type == wantType {
			out = append(out, a.Data)
		}
	}
	return out, nil
}

// ResolvePublicIP resolves hostname via DNS-over-HTTPS and returns the first vetted
// PUBLIC IP address, preferring IPv4. Returns an error if resolution fails, or if the
// hostname resolves only to private/reserved/loopback addresses.
func ResolvePublicIP(ctx context.Context, hostname string) (net.IP, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	aRecords, errA := dohQuery(ctx, hostname, "A")
	aaaaRecords, errAAAA := dohQuery(ctx, hostname, "AAAA")

	for _, ipStr := range aRecords {
		if ip := net.ParseIP(ipStr); ip != nil && isPublicIP(ip) {
			return ip, nil
		}
	}
	for _, ipStr := range aaaaRecords {
		if ip := net.ParseIP(ipStr); ip != nil && isPublicIP(ip) {
			return ip, nil
		}
	}

	if len(aRecords) == 0 && len(aaaaRecords) == 0 {
		if errA != nil {
			return nil, fmt.Errorf("DNS resolution failed for %s: %w", hostname, errA)
		}
		if errAAAA != nil {
			return nil, fmt.Errorf("DNS resolution failed for %s: %w", hostname, errAAAA)
		}
		return nil, fmt.Errorf("DNS resolution returned no records for %s", hostname)
	}
	return nil, fmt.Errorf("hostname %s resolves only to private/reserved IP addresses", hostname)
}
