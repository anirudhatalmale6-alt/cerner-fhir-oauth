package main

import (
	"net/http"
	"time"
)

// newHTTPClient returns a plain client with a sane timeout. No custom TLS or
// proxy config — the sandbox uses ordinary public HTTPS.
func newHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}
