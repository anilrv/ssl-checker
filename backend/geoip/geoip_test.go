package geoip

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Minimal valid PNG header bytes — enough to stand in for an image body.
var fakePNG = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 1, 2, 3, 4}

func TestFetchFlagDataEmbedsImage(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(fakePNG)
	}))
	defer srv.Close()

	uri := fetchFlagData(srv.URL + "/flag.png")
	if !strings.HasPrefix(uri, "data:image/png;base64,") {
		t.Fatalf("expected a data:image/png URI, got %q", uri)
	}

	// Second call must come from the flag cache, not the server.
	if again := fetchFlagData(srv.URL + "/flag.png"); again != uri {
		t.Errorf("cached result differs from first fetch")
	}
	if hits != 1 {
		t.Errorf("expected exactly 1 upstream hit, got %d", hits)
	}
}

func TestFetchFlagDataRejectsNonImage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>not a flag</html>"))
	}))
	defer srv.Close()

	if uri := fetchFlagData(srv.URL); uri != "" {
		t.Errorf("expected empty result for non-image content type, got %q", uri)
	}
}

func TestFetchFlagDataRejectsOversized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(bytes.Repeat([]byte{0xAB}, flagMaxBytes+1))
	}))
	defer srv.Close()

	if uri := fetchFlagData(srv.URL); uri != "" {
		t.Errorf("expected empty result for oversized image, got %d chars", len(uri))
	}
}

func TestFetchFlagDataEmptyURL(t *testing.T) {
	if uri := fetchFlagData(""); uri != "" {
		t.Errorf("expected empty result for empty URL, got %q", uri)
	}
}
