package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestBuildClientAssertion verifies the JWT we send to the token endpoint is
// well-formed, signed with RS384, and carries the exact claims SMART Backend
// Services requires. This runs with no network access.
func TestBuildClientAssertion(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		ClientID:   "my-client-id",
		TokenURL:   "https://authorization.cerner.com/tenants/T/token",
		KeyID:      "kid-123",
		PrivateKey: &rsaPrivateKey{key: priv},
	}
	now := time.Unix(1_700_000_000, 0)

	signed, err := buildClientAssertion(cfg, now)
	if err != nil {
		t.Fatalf("buildClientAssertion: %v", err)
	}

	// Verify the signature with the PUBLIC key, exactly as the server would.
	tok, err := jwt.Parse(signed, func(tk *jwt.Token) (any, error) {
		if tk.Method.Alg() != "RS384" {
			t.Errorf("alg = %s, want RS384", tk.Method.Alg())
		}
		if kid, _ := tk.Header["kid"].(string); kid != "kid-123" {
			t.Errorf("kid = %q, want kid-123", kid)
		}
		return &priv.PublicKey, nil
	}, jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("parse/verify: %v", err)
	}

	claims := tok.Claims.(jwt.MapClaims)
	if claims["iss"] != cfg.ClientID || claims["sub"] != cfg.ClientID {
		t.Errorf("iss/sub = %v/%v, want %s", claims["iss"], claims["sub"], cfg.ClientID)
	}
	if claims["aud"] != cfg.TokenURL {
		t.Errorf("aud = %v, want %s", claims["aud"], cfg.TokenURL)
	}
	if claims["jti"] == nil || claims["jti"] == "" {
		t.Error("jti missing")
	}
	exp := int64(claims["exp"].(float64))
	if exp <= now.Unix() || exp > now.Add(5*time.Minute).Unix() {
		t.Errorf("exp %d not within (now, now+5m]", exp)
	}
}
