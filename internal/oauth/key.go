package oauth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// rsaPrivateKey is a thin wrapper so the rest of the package doesn't import
// crypto directly.
type rsaPrivateKey struct {
	key *rsa.PrivateKey
}

// LoadPrivateKey reads an RSA private key from a PEM file on disk. This is the
// key you generated locally; its PUBLIC half is what you upload to the Cerner
// Code Console. Supports both PKCS#1 ("RSA PRIVATE KEY") and PKCS#8
// ("PRIVATE KEY") PEM blocks, which covers keys produced by `openssl` either way.
func LoadPrivateKey(path string) (*rsaPrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key %q: %w", path, err)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}

	switch block.Type {
	case "RSA PRIVATE KEY": // PKCS#1
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS#1 key: %w", err)
		}
		return &rsaPrivateKey{key: k}, nil
	case "PRIVATE KEY": // PKCS#8
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS#8 key: %w", err)
		}
		k, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key in %q is not RSA", path)
		}
		return &rsaPrivateKey{key: k}, nil
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
}
