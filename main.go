// Command cerner-fhir-oauth demonstrates, end to end:
//
//  1. an OAuth 2.0 client_credentials exchange (SMART Backend Services) against
//     the Oracle Health / Cerner sandbox, and
//  2. using the returned access token to pull a single Patient resource, first
//     by MRN identifier and then by native FHIR id.
//
// Everything is driven by environment variables (loaded from a .env file) so you
// only edit credentials in one place. Run `make run` after filling in .env.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anirudhatalmale6-alt/cerner-fhir-oauth/internal/fhir"
	"github.com/anirudhatalmale6-alt/cerner-fhir-oauth/internal/oauth"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\n[ERROR] %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	loadDotEnv(".env")

	// AUTH_MODE selects how we reach FHIR:
	//   backend (default) — full OAuth 2.0 token exchange, then Bearer-authed calls.
	//                        This is what a real hospital requires.
	//   open              — skip OAuth entirely and hit an OPEN/unauthenticated
	//                        FHIR endpoint directly. Handy to see the Patient calls
	//                        work with zero registration. Real PHI is never open.
	authMode := strings.ToLower(envOr("AUTH_MODE", "backend"))

	// Vendor-agnostic config: prefer the generic EMR_* names, fall back to the
	// original CERNER_* names so existing .env files keep working. Switching from
	// Cerner to Meditech (or any EMR) is therefore JUST env changes.
	fhirBase := firstEnv("EMR_FHIR_BASE_URL", "CERNER_FHIR_BASE_URL")
	if fhirBase == "" {
		return fmt.Errorf("set EMR_FHIR_BASE_URL (or CERNER_FHIR_BASE_URL)")
	}
	mrn := envOr("PATIENT_MRN", "")
	mrnSystem := envOr("PATIENT_MRN_SYSTEM", "")
	patientID := envOr("PATIENT_ID", "")

	httpClient := newHTTPClient()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	accessToken := ""
	if authMode == "open" {
		section("AUTH_MODE=open  Direct FHIR calls, no OAuth (unauthenticated endpoint)")
		fmt.Println("Skipping token exchange. Calling FHIR directly at:", fhirBase)
	} else {
		// TOKEN_AUTH_METHOD picks how we authenticate to the token endpoint:
		//   private_key_jwt (default) — signed JWT, e.g. Cerner
		//   client_secret_post / client_secret_basic — a client secret, e.g. some
		//   Meditech / other backends. This is the knob that keeps a new EMR to
		//   config only.
		method := oauth.AuthMethod(strings.ToLower(firstEnv("TOKEN_AUTH_METHOD", "")))
		if method == "" {
			method = oauth.PrivateKeyJWT
		}
		cfg := &oauth.Config{
			Method:       method,
			ClientID:     firstEnv("EMR_CLIENT_ID", "CERNER_CLIENT_ID"),
			ClientSecret: firstEnv("EMR_CLIENT_SECRET", "CERNER_CLIENT_SECRET"),
			TokenURL:     firstEnv("EMR_TOKEN_URL", "CERNER_TOKEN_URL"),
			Scopes:       envOr2("EMR_SCOPES", "CERNER_SCOPES", "system/Patient.read"),
			KeyID:        firstEnv("EMR_KEY_ID", "CERNER_KEY_ID"),
		}
		if cfg.ClientID == "" {
			return fmt.Errorf("set EMR_CLIENT_ID (or CERNER_CLIENT_ID)")
		}
		if cfg.TokenURL == "" {
			return fmt.Errorf("set EMR_TOKEN_URL (or CERNER_TOKEN_URL)")
		}
		// The private key is only needed for the JWT method.
		if method == oauth.PrivateKeyJWT {
			keyPath := envOr2("EMR_PRIVATE_KEY_PATH", "CERNER_PRIVATE_KEY_PATH", "keys/private.pem")
			key, err := oauth.LoadPrivateKey(keyPath)
			if err != nil {
				return err
			}
			cfg.PrivateKey = key
		}

		// ---- STEP 1: get an access token ---------------------------------
		section("STEP 1  Exchange backend credentials for an access token (" + string(method) + ")")
		tok, tTrace, err := oauth.FetchToken(ctx, httpClient, cfg, time.Now())
		if tTrace != nil {
			if tTrace.ClientAssertJWT != "" {
				fmt.Println("--- Signed client-assertion JWT (paste at jwt.io to inspect) ---")
				fmt.Println(tTrace.ClientAssertJWT)
				fmt.Println()
			}
			fmt.Println(">>> REQUEST")
			fmt.Println(tTrace.RequestLine)
			fmt.Println(tTrace.RequestBody)
			fmt.Printf("\n<<< RESPONSE (%d)\n%s\n", tTrace.ResponseCode, tTrace.ResponseBody)
		}
		if err != nil {
			return err
		}
		fmt.Printf("\n[OK] Access token acquired. Type=%s ExpiresIn=%ds Scope=%q\n",
			tok.TokenType, tok.ExpiresIn, tok.Scope)
		accessToken = tok.AccessToken
	}

	fc := &fhir.Client{BaseURL: fhirBase, AccessToken: accessToken, HTTP: httpClient}

	// ---- STEP 2: search Patient by MRN -----------------------------------
	if mrn != "" {
		section("STEP 2  GET /Patient?identifier=<MRN>")
		trace, err := fc.SearchByMRN(ctx, mrnSystem, mrn)
		printFHIR(trace)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[warn] MRN search: %v\n", err)
		}
	} else {
		fmt.Println("\n[skip] PATIENT_MRN not set — skipping the MRN search.")
	}

	// ---- STEP 3: read Patient by native id -------------------------------
	if patientID != "" {
		section("STEP 3  GET /Patient/<id>")
		trace, err := fc.GetByID(ctx, patientID)
		printFHIR(trace)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[warn] id read: %v\n", err)
		}
	} else {
		fmt.Println("\n[skip] PATIENT_ID not set — skipping the id read.")
	}

	fmt.Println("\nDone.")
	return nil
}

func printFHIR(t *fhir.Trace) {
	if t == nil {
		return
	}
	fmt.Println(">>> REQUEST")
	fmt.Println(t.RequestLine)
	fmt.Printf("\n<<< RESPONSE (%d)\n%s\n", t.ResponseCode, t.ResponseBody)
}

func section(title string) {
	fmt.Printf("\n============================================================\n%s\n============================================================\n", title)
}

// --- tiny helpers so the POC has no config framework dependency ----------

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		fmt.Fprintf(os.Stderr, "[ERROR] required env var %s is not set (see .env.example)\n", k)
		os.Exit(1)
	}
	return v
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// firstEnv returns the first of the given env vars that is set (non-empty), or "".
// Lets generic EMR_* names take precedence while CERNER_* names still work.
func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// envOr2 is firstEnv with a default fallback.
func envOr2(k1, k2, def string) string {
	if v := firstEnv(k1, k2); v != "" {
		return v
	}
	return def
}

// loadDotEnv is a minimal .env parser: KEY=VALUE per line, # comments, no export.
// We keep it dependency-free and intentionally simple.
func loadDotEnv(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return // .env is optional; env vars may be set another way
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if _, exists := os.LookupEnv(k); !exists {
			os.Setenv(k, v)
		}
	}
}
