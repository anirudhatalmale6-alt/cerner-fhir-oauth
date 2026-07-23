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
	"encoding/base64"
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

// AuthMethod selects HOW we prove our identity to the token endpoint. Different
// EMRs choose different methods, so this is what makes switching vendors a config
// change instead of a code change.
type AuthMethod string

const (
	// PrivateKeyJWT: sign a JWT with our private key (SMART Backend Services).
	// This is what Cerner / Oracle Health uses.
	PrivateKeyJWT AuthMethod = "private_key_jwt"
	// ClientSecretPost: send client_id + client_secret in the POST body. Common
	// for other backends (some Meditech setups, Epic app-with-secret, etc.).
	ClientSecretPost AuthMethod = "client_secret_post"
	// ClientSecretBasic: send client_id:client_secret as an HTTP Basic header.
	ClientSecretBasic AuthMethod = "client_secret_basic"
)

// Config holds everything needed to obtain a token. For Cerner, the values map
// to what you register in the Code Console; for another EMR you point the same
// fields at that vendor's values. See README.md.
type Config struct {
	Method       AuthMethod     // how to authenticate (default private_key_jwt)
	ClientID     string         // the App/Client ID from the vendor
	ClientSecret string         // only for the client_secret_* methods
	TokenURL     string         // the vendor's OAuth token endpoint
	Scopes       string         // space-separated, e.g. "system/Patient.read"
	KeyID        string         // "kid" of the uploaded public key (private_key_jwt)
	PrivateKey   *rsaPrivateKey // your RSA private key (private_key_jwt only)
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
// plus a Trace of exactly what went over the wire. It branches on cfg.Method so
// the SAME call works whether the vendor wants a signed JWT or a client secret.
func FetchToken(ctx context.Context, httpClient *http.Client, cfg *Config, now time.Time) (*TokenResponse, *Trace, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", cfg.Scopes)

	assertion := ""
	basicAuth := ""

	switch cfg.Method {
	case ClientSecretPost:
		form.Set("client_id", cfg.ClientID)
		form.Set("client_secret", cfg.ClientSecret)
	case ClientSecretBasic:
		form.Set("client_id", cfg.ClientID)
		basicAuth = base64.StdEncoding.EncodeToString([]byte(cfg.ClientID + ":" + cfg.ClientSecret))
	default: // PrivateKeyJWT (Cerner)
		var err error
		assertion, err = buildClientAssertion(cfg, now)
		if err != nil {
			return nil, nil, err
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
	}

	body := form.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basicAuth != "" {
		req.Header.Set("Authorization", "Basic "+basicAuth)
	}

	trace := &Trace{
		RequestLine:     fmt.Sprintf("POST %s", cfg.TokenURL),
		RequestBody:     redactSecrets(redactAssertion(body, assertion), cfg.ClientSecret),
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

// redactSecrets hides a client secret so it never shows up in printed traces.
func redactSecrets(body, secret string) string {
	if secret == "" {
		return body
	}
	return strings.ReplaceAll(body, url.QueryEscape(secret), "***REDACTED***")
}
