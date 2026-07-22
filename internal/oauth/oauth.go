// Package oauth implements the OAuth 2.0 "client_credentials" grant as used by
// SMART Backend Services (http://hl7.org/fhir/uv/bulkdata/authorization/index.html),
// which is the flow Oracle Health / Cerner exposes for system-to-system (backend)
// access.
//
// The key idea for a beginner refreshing OAuth:
//
//   - There is NO username/password and NO shared client secret here.
//   - Instead you prove your identity by SIGNING a short-lived JSON Web Token
//     (the "client assertion") with a PRIVATE key that only you hold.
//   - The authorization server verifies the signature using the PUBLIC key you
//     registered with it, and if it checks out, it returns an access token.
//   - You then send that access token as "Authorization: Bearer <token>" on your
//     FHIR requests.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Config holds everything needed to obtain a token. Every field maps to a value
// you copy out of the Oracle Health / Cerner "Code Console" when you register a
// System (backend) application. See README.md for exactly where each one lives.
type Config struct {
	ClientID   string          // the App/Client ID shown in the console
	TokenURL   string          // the "Token" endpoint for your tenant
	Scopes     string          // space-separated, e.g. "system/Patient.read"
	KeyID      string          // "kid" of the public key you uploaded (optional but recommended)
	PrivateKey *rsaPrivateKey  // your RSA private key (loaded from a PEM file)
}

// TokenResponse is the raw JSON the token endpoint returns on success.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// Trace captures the raw HTTP request and response so the CLI can print them,
// which is exactly what the client asked to see in real time.
type Trace struct {
	RequestLine   string
	RequestBody   string
	ResponseCode  int
	ResponseBody  string
	ClientAssertJWT string // the signed JWT we sent, so you can decode it at jwt.io
}

// buildClientAssertion creates and signs the JWT that authenticates us to the
// token endpoint. This is the heart of SMART Backend Services.
//
// Per the spec (and Cerner's requirements) the claims are:
//
//	iss = client_id   (who is asserting)
//	sub = client_id   (the subject is the app itself)
//	aud = token URL   (locks the token to this exact endpoint)
//	exp = now + 5 min (must be short-lived)
//	jti = random id   (prevents replay)
//
// Cerner requires the RS384 signing algorithm.
func buildClientAssertion(cfg *Config, now time.Time) (string, error) {
	claims := jwt.MapClaims{
		"iss": cfg.ClientID,
		"sub": cfg.ClientID,
		"aud": cfg.TokenURL,
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
		"jti": uuid.NewString(),
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS384, claims)
	if cfg.KeyID != "" {
		tok.Header["kid"] = cfg.KeyID
	}

	signed, err := tok.SignedString(cfg.PrivateKey.key)
	if err != nil {
		return "", fmt.Errorf("signing client assertion: %w", err)
	}
	return signed, nil
}

// FetchToken performs the full client_credentials exchange and returns the token
// plus a Trace of exactly what went over the wire.
func FetchToken(ctx context.Context, httpClient *http.Client, cfg *Config, now time.Time) (*TokenResponse, *Trace, error) {
	assertion, err := buildClientAssertion(cfg, now)
	if err != nil {
		return nil, nil, err
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", cfg.Scopes)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	body := form.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	trace := &Trace{
		RequestLine:     fmt.Sprintf("POST %s", cfg.TokenURL),
		RequestBody:     redactAssertion(body, assertion),
		ClientAssertJWT: assertion,
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, trace, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	trace.ResponseCode = resp.StatusCode
	trace.ResponseBody = string(raw)

	if resp.StatusCode != http.StatusOK {
		return nil, trace, fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}

	var tr TokenResponse
	if err := json.Unmarshal(raw, &tr); err != nil {
		return nil, trace, fmt.Errorf("decoding token response: %w", err)
	}
	return &tr, trace, nil
}

// redactAssertion shortens the very long JWT in the printed request body so the
// trace stays readable; the full JWT is available in Trace.ClientAssertJWT.
func redactAssertion(body, assertion string) string {
	if assertion == "" {
		return body
	}
	short := assertion
	if len(short) > 24 {
		short = short[:12] + "...(truncated, see full JWT below)..." + short[len(short)-8:]
	}
	return strings.ReplaceAll(body, url.QueryEscape(assertion), short)
}
