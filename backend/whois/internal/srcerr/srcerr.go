// Package srcerr is the shared error vocabulary that lookup sources (rdap, whois) raise.
//
// Vendored from github.com/lissy93/who-dat (internal/srcerr), MIT licensed — see
// ../LICENSE-who-dat. Unmodified from upstream.
package srcerr

import (
	"errors"
	"fmt"
	"time"
)

// ErrNoSource means the TLD has no known RDAP or WHOIS source.
var ErrNoSource = errors.New("no rdap or whois source for tld")

// ErrUpstream means the registry was unreachable or returned garbage.
var ErrUpstream = errors.New("upstream registry error")

// ErrTimeout means the registry did not respond in time.
var ErrTimeout = errors.New("upstream registry timed out")

// SourceError tags an error with the backend that raised it and, when known, the
// server queried, so API errors can say exactly who let us down.
type SourceError struct {
	Source string // "rdap" or "whois"
	Server string // empty when unknown
	Err    error
}

func (e *SourceError) Error() string {
	if e.Server != "" {
		return fmt.Sprintf("%s %s: %v", e.Source, e.Server, e.Err)
	}
	return fmt.Sprintf("%s: %v", e.Source, e.Err)
}

func (e *SourceError) Unwrap() error { return e.Err }

// RateLimited wraps an upstream (or local) rate-limit signal.
type RateLimited struct {
	RetryAfter time.Duration
	Err        error
}

func (e *RateLimited) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("rate limited: %v", e.Err)
	}
	return "rate limited"
}

func (e *RateLimited) Unwrap() error { return e.Err }
