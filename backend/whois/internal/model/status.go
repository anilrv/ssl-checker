// Vendored from github.com/lissy93/who-dat (internal/model), MIT licensed — see
// ../LICENSE-who-dat. Unmodified from upstream.
package model

import "strings"

// eppStatuses is the canonical EPP status set (RFC 5731 / 3915). Both RDAP
// (space separated, e.g. "client transfer prohibited") and WHOIS (camelCase plus a
// trailing URL, e.g. "clientTransferProhibited https://icann.org/epp#...") map onto it.
var eppStatuses = []string{
	"addPeriod", "autoRenewPeriod", "inactive", "ok", "pendingCreate", "pendingDelete",
	"pendingRenew", "pendingRestore", "pendingTransfer", "pendingUpdate", "redemptionPeriod",
	"renewPeriod", "transferPeriod", "serverDeleteProhibited", "serverHold",
	"serverRenewProhibited", "serverTransferProhibited", "serverUpdateProhibited",
	"clientDeleteProhibited", "clientHold", "clientRenewProhibited", "clientTransferProhibited",
	"clientUpdateProhibited",
}

// canonicalStatus maps a normalized key to its canonical EPP spelling.
var canonicalStatus = func() map[string]string {
	m := make(map[string]string, len(eppStatuses)+1)
	for _, s := range eppStatuses {
		m[statusKey(s)] = s
	}
	// RFC 8056: RDAP "active" corresponds to EPP "ok".
	m[statusKey("active")] = "ok"
	return m
}()

// NormalizeStatus maps a single RDAP or WHOIS status string to its canonical EPP form.
// Unrecognized values are returned trimmed and otherwise unchanged.
func NormalizeStatus(raw string) string {
	s := raw
	if i := strings.Index(strings.ToLower(s), "http"); i > 0 {
		s = s[:i] // drop the trailing EPP URL that WHOIS appends
	}
	if v, ok := canonicalStatus[statusKey(s)]; ok {
		return v
	}
	return strings.TrimSpace(s)
}

// NormalizeStatuses normalizes, de-duplicates, and drops empties, always returning a
// non-nil slice so the field serializes as [] rather than null.
func NormalizeStatuses(raw []string) []string {
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, r := range raw {
		s := NormalizeStatus(r)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// statusKey reduces a status to lowercase alphanumerics so the various spellings collapse
// to one lookup key ("client transfer prohibited" == "clientTransferProhibited").
func statusKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
