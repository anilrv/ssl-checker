// Vendored from github.com/lissy93/who-dat (internal/model), MIT licensed — see
// ../LICENSE-who-dat. Unmodified from upstream.
package model

import (
	"reflect"
	"testing"
)

func TestNormalizeStatus(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"rdap spaced", "client transfer prohibited", "clientTransferProhibited"},
		{"whois camel with url", "clientTransferProhibited https://icann.org/epp#clientTransferProhibited", "clientTransferProhibited"},
		{"rdap active to ok", "active", "ok"},
		{"server hold", "server hold", "serverHold"},
		{"pending delete", "pending delete", "pendingDelete"},
		{"already canonical", "clientDeleteProhibited", "clientDeleteProhibited"},
		{"hyphenated", "client-hold", "clientHold"},
		{"unknown passthrough", "someRegistryStatus", "someRegistryStatus"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeStatus(tt.in); got != tt.want {
				t.Errorf("NormalizeStatus(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeStatuses(t *testing.T) {
	in := []string{
		"client transfer prohibited",
		"clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
		"",
		"server hold",
	}
	want := []string{"clientTransferProhibited", "serverHold"}
	if got := NormalizeStatuses(in); !reflect.DeepEqual(got, want) {
		t.Errorf("NormalizeStatuses() = %v, want %v", got, want)
	}
	if got := NormalizeStatuses(nil); got == nil {
		t.Error("NormalizeStatuses(nil) returned nil, want empty slice")
	}
}
