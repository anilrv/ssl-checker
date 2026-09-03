// Package rdap is a self-contained RDAP client: it resolves the registry server via the
// IANA bootstrap, fetches the domain object, and maps it to the canonical model.
//
// Vendored from github.com/lissy93/who-dat (internal/rdap), MIT licensed — see
// ../LICENSE-who-dat. WarmBootstrap is a small addition on top of upstream (see its own
// doc comment); everything else is unmodified.
package rdap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sslcheckerfunc/whois/internal/domain"
	"sslcheckerfunc/whois/internal/model"
	"sslcheckerfunc/whois/internal/srcerr"
)

const (
	maxBody     = 4 << 20
	contentType = "application/rdap+json"
	userAgent   = "who-dat/2.0 (+https://github.com/lissy93/who-dat)"
)

// Client performs RDAP domain lookups.
type Client struct {
	http      *http.Client
	bootstrap *bootstrap
}

// Client using the given HTTP client
func NewClient(httpClient *http.Client) *Client {
	return &Client{http: httpClient, bootstrap: newBootstrap(httpClient)}
}

// TLS config for outbound RDAP requests, since need some legacy RSA-CBC suites for some registries
func TLSConfig() *tls.Config {
	ids := []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA}
	for _, cs := range tls.CipherSuites() {
		ids = append(ids, cs.ID)
	}
	return &tls.Config{CipherSuites: ids}
}

// WarmBootstrap ensures the IANA bootstrap registry is fetched and fresh, using whatever
// deadline ctx carries. Not part of upstream who-dat: callers here (see whois.Lookup) invoke
// this with its own, more generous timeout before the tighter per-lookup Lookup call below,
// so a cold start's registry fetch never eats into that budget and silently returns nil.
func (c *Client) WarmBootstrap(ctx context.Context) error {
	return c.bootstrap.ensure(ctx)
}

// Lookup queries the registry's RDAP server for n. A 404 is a successful "not registered"
// answer, not an error. Returns srcerr.ErrNoSource when the TLD has no RDAP server.
func (c *Client) Lookup(ctx context.Context, n domain.Name) (*model.Result, error) {
	servers, err := c.bootstrap.serversFor(ctx, n.ASCII)
	if err != nil {
		return nil, err
	}

	base := strings.TrimRight(servers[0], "/")
	r, err := c.get(ctx, n, base)
	if err != nil {
		return nil, &srcerr.SourceError{Source: model.SourceRDAP, Server: base, Err: err}
	}
	return r, nil
}

// get fetches and maps the domain object from the RDAP server at base.
func (c *Client) get(ctx context.Context, n domain.Name, base string) (*model.Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/domain/"+n.ASCII, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", srcerr.ErrUpstream, err)
	}
	req.Header.Set("Accept", contentType)
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: %v", srcerr.ErrTimeout, err)
		}
		return nil, fmt.Errorf("%w: %v", srcerr.ErrUpstream, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))

	switch {
	case resp.StatusCode == http.StatusOK:
		return mapDomain(n, base, body)
	case resp.StatusCode == http.StatusNotFound:
		return notRegistered(n, base, body), nil
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, &srcerr.RateLimited{RetryAfter: retryAfter(resp), Err: fmt.Errorf("rdap %s", base)}
	default:
		return nil, fmt.Errorf("%w: rdap status %d", srcerr.ErrUpstream, resp.StatusCode)
	}
}

func notRegistered(n domain.Name, base string, raw []byte) *model.Result {
	r := model.New(n.ASCII, n.ASCII, n.TLD)
	if n.IsIDN() {
		r.DomainUnicode = model.Str(n.Unicode)
	}
	r.IsRegistered = false
	r.Meta = model.Meta{Source: model.SourceRDAP, Server: model.Str(base), FetchedAt: time.Now().UTC()}
	r.Raw = raw
	r.RawContentType = contentType
	return r
}

func retryAfter(resp *http.Response) time.Duration {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
