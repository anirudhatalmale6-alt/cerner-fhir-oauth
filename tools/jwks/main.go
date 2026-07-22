// Command jwks converts an RSA public key (PEM) into a single-key JWKS document.
// Some registration flows want a JWKS URL rather than a pasted public key; this
// produces the jwks.json you would host at that URL.
//
//	go run ./tools/jwks keys/public.pem > jwks.json
package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: jwks <public-key.pem>")
		os.Exit(1)
	}
	raw, err := os.ReadFile(os.Args[1])
	must(err)

	block, _ := pem.Decode(raw)
	if block == nil {
		fmt.Fprintln(os.Stderr, "no PEM block found")
		os.Exit(1)
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	must(err)
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		fmt.Fprintln(os.Stderr, "not an RSA public key")
		os.Exit(1)
	}

	// A stable key id: SHA-256 of the modulus, base64url-encoded.
	sum := sha256.Sum256(pub.N.Bytes())
	kid := base64.RawURLEncoding.EncodeToString(sum[:])[:16]

	jwk := map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS384",
		"kid": kid,
		"n":   b64(pub.N),
		"e":   b64(big.NewInt(int64(pub.E))),
	}
	out := map[string]any{"keys": []any{jwk}}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(enc.Encode(out))
	fmt.Fprintf(os.Stderr, "\n>> kid = %s  (put this in CERNER_KEY_ID)\n", kid)
}

func b64(i *big.Int) string { return base64.RawURLEncoding.EncodeToString(i.Bytes()) }

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
