// Package domain sanitizes user input into a registrable domain name. It accepts loose
// input (full URLs, mixed case, IDNs, trailing dots) and returns the registrable domain
// (eTLD+1) that RDAP and WHOIS actually operate on.
//
// Vendored from github.com/lissy93/who-dat (internal/domain), MIT licensed — see
// ../LICENSE-who-dat. Unmodified from upstream.
package domain

import (
	"errors"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// ErrInvalidDomain means the input could not be parsed into a hostname.
var ErrInvalidDomain = errors.New("could not parse a registrable domain")

// ErrNoPublicSuffix means the host has no valid public suffix (so no registrable domain).
var ErrNoPublicSuffix = errors.New("no valid public suffix")

// Name is a parsed, registrable domain.
type Name struct {
	ASCII   string // punycode/ASCII form, used for lookups, e.g. "xn--n3h.com"
	Unicode string // human form, e.g. "☃.com"; equals ASCII when not an IDN
	TLD     string // the public suffix, e.g. "com" or "co.uk"
}

// IsIDN reports whether the name contained non-ASCII labels.
func (n Name) IsIDN() bool { return n.Unicode != n.ASCII }

// Parse extracts the registrable domain from raw input.
func Parse(raw string) (Name, error) {
	host := hostname(raw)
	if host == "" {
		return Name{}, ErrInvalidDomain
	}

	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return Name{}, ErrInvalidDomain
	}

	registrable, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil {
		return Name{}, ErrNoPublicSuffix
	}
	suffix, _ := publicsuffix.PublicSuffix(registrable)

	unicode, err := idna.Lookup.ToUnicode(registrable)
	if err != nil {
		unicode = registrable
	}

	return Name{ASCII: registrable, Unicode: unicode, TLD: suffix}, nil
}

// hostname strips scheme, credentials, port, path, query, and a trailing dot, leaving a
// bare lowercase host.
func hostname(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	return strings.ToLower(s)
}
