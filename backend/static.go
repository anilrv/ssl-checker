package main

import (
	_ "embed"
	"net/http"
)

//go:embed static/favicon.ico
var faviconICO []byte

//go:embed static/favicon.svg
var faviconSVG []byte

//go:embed static/favicon-96x96.png
var favicon96 []byte

//go:embed static/apple-touch-icon.png
var appleTouchIcon []byte

//go:embed static/web-app-manifest-192x192.png
var webAppIcon192 []byte

//go:embed static/web-app-manifest-512x512.png
var webAppIcon512 []byte

//go:embed static/site.webmanifest
var siteWebmanifest []byte

// serveStatic returns a handler for a single embedded static asset. Browsers request
// /favicon.ico directly regardless of any <link> tag in the page head, so it needs its
// own real route rather than relying solely on a data-URI link.
func serveStatic(contentType string, data []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}
}

var faviconICOHandler = serveStatic("image/x-icon", faviconICO)
var faviconSVGHandler = serveStatic("image/svg+xml", faviconSVG)
var favicon96Handler = serveStatic("image/png", favicon96)
var appleTouchIconHandler = serveStatic("image/png", appleTouchIcon)
var webAppIcon192Handler = serveStatic("image/png", webAppIcon192)
var webAppIcon512Handler = serveStatic("image/png", webAppIcon512)
var siteWebmanifestHandler = serveStatic("application/manifest+json", siteWebmanifest)
