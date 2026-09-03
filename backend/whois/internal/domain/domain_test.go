// Vendored from github.com/lissy93/who-dat (internal/domain), MIT licensed — see
// ../LICENSE-who-dat. Unmodified from upstream.
package domain

import (
	"errors"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantASCII   string
		wantTLD     string
		wantUnicode string // "" means expect equal to ASCII (not an IDN)
	}{
		{"plain", "example.com", "example.com", "com", ""},
		{"full url with www", "https://www.Example.com/path?q=1", "example.com", "com", ""},
		{"subdomain", "a.b.example.co.uk", "example.co.uk", "co.uk", ""},
		{"trailing dot", "example.com.", "example.com", "com", ""},
		{"port and creds", "user:pass@example.com:8080", "example.com", "com", ""},
		{"uppercase", "EXAMPLE.COM", "example.com", "com", ""},
		{"idn unicode", "bücher.de", "xn--bcher-kva.de", "de", "bücher.de"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.in, err)
			}
			if got.ASCII != tt.wantASCII {
				t.Errorf("ASCII = %q, want %q", got.ASCII, tt.wantASCII)
			}
			if got.TLD != tt.wantTLD {
				t.Errorf("TLD = %q, want %q", got.TLD, tt.wantTLD)
			}
			wantUni := tt.wantUnicode
			if wantUni == "" {
				wantUni = tt.wantASCII
			}
			if got.Unicode != wantUni {
				t.Errorf("Unicode = %q, want %q", got.Unicode, wantUni)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr error
	}{
		{"empty", "", ErrInvalidDomain},
		{"whitespace", "   ", ErrInvalidDomain},
		{"bare tld", "com", ErrNoPublicSuffix},
		{"suffix only", "co.uk", ErrNoPublicSuffix},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Parse(%q) err = %v, want %v", tt.in, err, tt.wantErr)
			}
		})
	}
}
