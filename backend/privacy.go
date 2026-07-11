package main

import (
	_ "embed"
	"net/http"
)

//go:embed privacy.html
var privacyHTML []byte

//go:embed home.html
var homeHTML []byte

func privacyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(privacyHTML)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(homeHTML)
}
