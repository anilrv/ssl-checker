// Revocation checking for the probed leaf certificate, tried cheapest-first:
//
//  1. the OCSP response stapled during the handshake (already in hand, no network),
//  2. a live OCSP query against the leaf's AIA responder — note Let's Encrypt shut its
//     OCSP responders down in August 2025, so their certs skip straight past this,
//  3. the leaf's CRL distribution points (the only path that works for modern LE certs).
//
// Best-effort like geoip/whois: any failure leaves the status empty rather than failing
// the probe. Only a definitive "good" or "revoked" is ever reported — "couldn't
// determine" stays silent, because an unreachable responder is not evidence of anything.
//
// SSRF matters here more than it first appears: OCSP/CRL URLs come out of the
// certificate itself, which the probed server chose. Every fetch below resolves the
// URL's host through ssrfguard, dials the vetted public IP directly (no re-resolution
// to swap in), and refuses redirects (a redirect target would bypass that pin).
package certprobe

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"

	"sslcheckerfunc/ssrfguard"
)

const (
	RevocationGood    = "good"
	RevocationRevoked = "revoked"
	RevocationUnknown = "unknown"
)

// The whole check gets its own fixed budget independent of the parent context's
// remaining deadline (same convention as geoip/whois), sized for up to two sequential
// fetches; each individual fetch is capped tighter below.
const revocationBudget = 4 * time.Second
const revocationFetchTimeout = 2 * time.Second

const maxOCSPRespBytes = 64 * 1024
// CRLs are the one potentially large download here. Let's Encrypt's sharded CRLs are
// hundreds of KB; some legacy CA CRLs run to megabytes. Capped, not unbounded.
const maxCRLBytes = 8 * 1024 * 1024

// Test seam: unit tests point this at a stub so httptest servers on 127.0.0.1 (which
// ssrfguard rightly refuses) can stand in for real responders.
var resolvePublicIP = ssrfguard.ResolvePublicIP

// CheckRevocation determines whether r.Leaf has been revoked and fills
// r.RevocationStatus / r.RevocationSource. No-ops when the probe didn't yield both the
// leaf and its issuer — without the issuer no revocation evidence can be validated
// (and those chains are already flagged as self-signed/incomplete by other rules).
func CheckRevocation(ctx context.Context, r *Result) {
	if r == nil || r.Leaf == nil || r.Issuer == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, revocationBudget)
	defer cancel()

	if len(r.RawOCSPStaple) > 0 {
		if resp, err := ocsp.ParseResponseForCert(r.RawOCSPStaple, r.Leaf, r.Issuer); err == nil {
			if status := ocspStatusName(resp.Status); status != RevocationUnknown {
				r.RevocationStatus, r.RevocationSource = status, "stapled-ocsp"
				return
			}
		}
	}

	for _, responder := range r.Leaf.OCSPServer {
		if status := ocspQuery(ctx, responder, r.Leaf, r.Issuer); status != RevocationUnknown {
			r.RevocationStatus, r.RevocationSource = status, "ocsp"
			return
		}
	}

	for _, dp := range r.Leaf.CRLDistributionPoints {
		if status := crlCheck(ctx, dp, r.Leaf, r.Issuer); status != RevocationUnknown {
			r.RevocationStatus, r.RevocationSource = status, "crl"
			return
		}
	}
}

func ocspStatusName(status int) string {
	switch status {
	case ocsp.Good:
		return RevocationGood
	case ocsp.Revoked:
		return RevocationRevoked
	}
	return RevocationUnknown
}

func ocspQuery(ctx context.Context, responderURL string, leaf, issuer *x509.Certificate) string {
	reqDER, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return RevocationUnknown
	}
	body, err := guardedFetch(ctx, http.MethodPost, responderURL, "application/ocsp-request", reqDER, maxOCSPRespBytes)
	if err != nil {
		return RevocationUnknown
	}
	resp, err := ocsp.ParseResponseForCert(body, leaf, issuer)
	if err != nil {
		return RevocationUnknown
	}
	return ocspStatusName(resp.Status)
}

func crlCheck(ctx context.Context, crlURL string, leaf, issuer *x509.Certificate) string {
	rl := cachedCRL(ctx, crlURL, issuer)
	if rl == nil {
		return RevocationUnknown
	}
	for _, entry := range rl.RevokedCertificateEntries {
		if entry.SerialNumber != nil && entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			return RevocationRevoked
		}
	}
	// A validated, current CRL that doesn't list this serial IS a definitive answer.
	return RevocationGood
}

// ---- bounded in-memory CRL cache, keyed by URL ----
// Hosts sharing a CA (e.g. every Let's Encrypt site hitting the same CRL shard) reuse
// one download instead of re-fetching per hostname. Entries expire at the CRL's own
// NextUpdate or after 6 hours, whichever comes first; only validated CRLs are cached,
// so a transient fetch failure self-heals on the next request.

type crlCacheEntry struct {
	key       string
	rl        *x509.RevocationList
	expiresAt time.Time
}

var (
	crlMu    sync.Mutex
	crlItems = make(map[string]*crlCacheEntry)
)

const crlCacheCap = 64
const crlCacheTTL = 6 * time.Hour

func cachedCRL(ctx context.Context, crlURL string, issuer *x509.Certificate) *x509.RevocationList {
	crlMu.Lock()
	if e, ok := crlItems[crlURL]; ok {
		if time.Now().Before(e.expiresAt) {
			crlMu.Unlock()
			// Re-verify against THIS caller's issuer: two different CAs could in theory
			// point at the same URL, and a cache hit must not skip the signature check.
			if e.rl.CheckSignatureFrom(issuer) == nil {
				return e.rl
			}
			return nil
		}
		delete(crlItems, crlURL)
	}
	crlMu.Unlock()

	rl := fetchCRL(ctx, crlURL, issuer)
	if rl == nil {
		return nil
	}

	expires := time.Now().Add(crlCacheTTL)
	if !rl.NextUpdate.IsZero() && rl.NextUpdate.Before(expires) {
		expires = rl.NextUpdate
	}
	crlMu.Lock()
	// Cap enforcement is crude (drop-newest when full, no LRU order) — with 64 slots
	// and a handful of CAs in practice, eviction pressure is not a real concern.
	if len(crlItems) < crlCacheCap {
		crlItems[crlURL] = &crlCacheEntry{key: crlURL, rl: rl, expiresAt: expires}
	}
	crlMu.Unlock()
	return rl
}

func fetchCRL(ctx context.Context, crlURL string, issuer *x509.Certificate) *x509.RevocationList {
	body, err := guardedFetch(ctx, http.MethodGet, crlURL, "", nil, maxCRLBytes)
	if err != nil {
		return nil
	}
	der := body
	if p, _ := pem.Decode(body); p != nil {
		der = p.Bytes
	}
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil
	}
	// An unverifiable or stale CRL proves nothing — treat as no answer rather than
	// trusting whatever a misbehaving distribution point served.
	if rl.CheckSignatureFrom(issuer) != nil {
		return nil
	}
	if !rl.NextUpdate.IsZero() && time.Now().After(rl.NextUpdate) {
		return nil
	}
	return rl
}

// guardedFetch performs one SSRF-guarded HTTP request: scheme allow-list, host vetted
// to a public IP via ssrfguard, that exact IP pinned for the dial, redirects refused,
// response size capped.
func guardedFetch(ctx context.Context, method, rawURL, contentType string, payload []byte, maxBytes int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if !ssrfguard.ValidHostname(host) {
		return nil, errors.New("invalid host in URL")
	}
	ip, err := resolvePublicIP(ctx, host)
	if err != nil {
		return nil, err
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	pinnedAddr := net.JoinHostPort(ip.String(), port)

	client := &http.Client{
		Timeout: revocationFetchTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := &net.Dialer{Timeout: revocationFetchTimeout}
				return d.DialContext(ctx, network, pinnedAddr)
			},
			TLSClientConfig: &tls.Config{ServerName: host},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var reqBody io.Reader
	if payload != nil {
		reqBody = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reqBody)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch returned status %d", resp.StatusCode)
	}

	// +1 so a body exactly at the limit is distinguishable from one that exceeds it.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("response exceeds size cap")
	}
	return data, nil
}
