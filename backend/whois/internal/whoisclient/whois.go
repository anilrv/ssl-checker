// Package whoisclient is the port-43 WHOIS fallback for TLDs without an RDAP server. It
// wraps the blocking likexian client with context handling and maps the parsed result onto
// the canonical model.
//
// Vendored from github.com/lissy93/who-dat (internal/whois), MIT licensed — see
// ../LICENSE-who-dat. Renamed from upstream's package name "whois" to "whoisclient" only to
// avoid confusion with this repo's own top-level whois package; logic is unmodified.
package whoisclient

import (
	"context"
	"fmt"
	"time"

	gowhois "github.com/likexian/whois"

	"sslcheckerfunc/whois/internal/domain"
	"sslcheckerfunc/whois/internal/model"
	"sslcheckerfunc/whois/internal/srcerr"
)

// Client performs WHOIS lookups.
type Client struct{}

// NewClient returns a WHOIS client.
func NewClient() *Client { return &Client{} }

// Lookup queries WHOIS for n, honoring ctx cancellation/deadline
func (c *Client) Lookup(ctx context.Context, n domain.Name) (*model.Result, error) {
	r, err := c.query(ctx, n)
	if err != nil {
		return nil, &srcerr.SourceError{Source: model.SourceWhois, Err: err}
	}
	return r, nil
}

// query runs the blocking WHOIS lookup. The lib picks the server itself, so we never
// learn which host we actually asked.
func (c *Client) query(ctx context.Context, n domain.Name) (*model.Result, error) {
	type result struct {
		raw string
		err error
	}
	ch := make(chan result, 1)

	go func() {
		wc := gowhois.NewClient()
		if dl, ok := ctx.Deadline(); ok {
			wc.SetTimeout(time.Until(dl))
		}
		raw, err := wc.Whois(n.ASCII)
		ch <- result{raw: raw, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %v", srcerr.ErrTimeout, ctx.Err())
	case res := <-ch:
		if res.err != nil {
			// timeout
			if ctx.Err() != nil {
				return nil, fmt.Errorf("%w: %v", srcerr.ErrTimeout, res.err)
			}
			// referral failed (maybe URL instead of host), fallback to usable record if present
			if res.raw == "" {
				return nil, fmt.Errorf("%w: whois query: %v", srcerr.ErrUpstream, res.err)
			}
		}
		return mapWhois(n, res.raw)
	}
}
