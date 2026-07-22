# Cerner (Oracle Health) FHIR — OAuth 2.0 Backend POC (Go)

A small, self-contained Go CLI that:

1. Exchanges **backend (system-to-system) credentials** for an OAuth 2.0 access
   token against the Oracle Health / Cerner sandbox, then
2. Uses that token to pull a single **Patient** resource — first **by MRN**
   identifier, then **by native FHIR id** — and prints the **raw request /
   response** for every call.

It's written to be read. The comments explain *why* each step exists so you can
refresh your OAuth knowledge as you go.

---

## 1. The OAuth flow in one picture

Cerner's backend access uses **SMART Backend Services**, which is the OAuth 2.0
`client_credentials` grant with an extra twist: instead of a shared client
secret, you authenticate with a **signed JWT**.

```
        YOUR APP                                CERNER
  ┌───────────────────┐                 ┌────────────────────────┐
  │ 1. Build a JWT     │                 │                        │
  │    (iss/sub=client │                 │                        │
  │     aud=token URL) │                 │                        │
  │ 2. Sign it with    │                 │                        │
  │    your PRIVATE key │  POST /token   │                        │
  │ 3. Send it as the  ├────────────────▶│ verify JWT signature   │
  │    client_assertion │                 │ with your PUBLIC key   │
  │                    │◀────────────────┤ return access_token    │
  │ 4. Call FHIR with  │  access_token   │                        │
  │    Bearer token    ├────────────────▶│ /Patient?identifier=…  │
  │                    │◀────────────────┤ return Patient JSON    │
  └───────────────────┘                 └────────────────────────┘
```

Key point for someone coming back to this after 10 years: **there is no
username/password and no client secret in the backend flow.** Your identity is
proved by the fact that only you can produce a JWT that verifies against the
public key you registered. The private key *is* the credential.

---

## 2. Where every credential comes from (Cerner Code Console)

You get a **free** sandbox account at **https://code.cerner.com**. After signing
in, create a **New App**:

| Field in the console            | Value / choice                              | Goes into `.env` as        |
|---------------------------------|---------------------------------------------|----------------------------|
| App Type                        | **Provider**                                | —                          |
| Authorization type / scheme     | **System** (a.k.a. "System Account", backend)| —                          |
| FHIR spec                       | **R4**                                       | —                          |
| **Client ID** (shown after save)| e.g. `d1a3e...`                             | `CERNER_CLIENT_ID`         |
| **Tenant** (sandbox GUID)       | `ec2458f2-1e24-41c8-b71b-0e701af7583d`      | inside the two URLs        |
| **Public key** upload           | paste/upload `keys/public.pem`              | (private stays local)      |
| **Key id** shown after upload   | e.g. `k7f2…`                                | `CERNER_KEY_ID`            |
| **Scopes**                      | tick `system/Patient.read`                  | `CERNER_SCOPES`            |

The two endpoint URLs are fixed per tenant and are pre-filled in
`.env.example` for the public sandbox tenant:

- **Token:** `https://authorization.cerner.com/tenants/<tenant>/protocols/oauth2/profiles/smart-v1/token`
- **FHIR base (R4):** `https://fhir-ehr-code.cerner.com/r4/<tenant>`

When you use **your own** app, the only things you change in `.env` are
`CERNER_CLIENT_ID`, `CERNER_KEY_ID`, and your `keys/private.pem`. If Cerner
issues you a different tenant, swap the GUID in the two URLs too.

---

## 3. Environment variables (`.env`)

Copy the template and edit it:

```bash
cp .env.example .env
```

| Variable                  | What it is                                                        |
|---------------------------|------------------------------------------------------------------|
| `CERNER_CLIENT_ID`        | The App/Client ID from the console. **Required.**                |
| `CERNER_KEY_ID`           | `kid` of the public key you uploaded. Recommended.               |
| `CERNER_SCOPES`           | Space-separated scopes, default `system/Patient.read`.           |
| `CERNER_PRIVATE_KEY_PATH` | Path to your RSA private key PEM. Default `keys/private.pem`.     |
| `CERNER_TOKEN_URL`        | OAuth token endpoint for your tenant.                            |
| `CERNER_FHIR_BASE_URL`    | FHIR R4 base URL for your tenant.                                |
| `PATIENT_ID`              | Native FHIR id to read (`GET /Patient/<id>`).                    |
| `PATIENT_MRN`             | MRN value to search (`GET /Patient?identifier=…`). Empty=skip.   |
| `PATIENT_MRN_SYSTEM`      | The identifier "system" the MRN belongs to.                     |

---

## 3b. Two modes: `AUTH_MODE`

The tool can reach FHIR two ways, set by `AUTH_MODE` in `.env`:

- **`AUTH_MODE=open`** — skip OAuth entirely and call an **open/unauthenticated**
  FHIR endpoint directly. Point `CERNER_FHIR_BASE_URL` at the `fhir-open` URL and
  run — you get real Patient JSON with **zero registration**. Great for seeing the
  Patient-by-MRN and Patient-by-id calls work immediately.
- **`AUTH_MODE=backend`** (default) — the full OAuth 2.0 token exchange, then
  Bearer-authenticated calls. **This is what a live hospital requires**, because a
  real EHR never exposes patient data on an open endpoint.

A note for the live-hospital deployment: OAuth is not optional there. Protected
FHIR always demands a Bearer token, and that token comes from this exact backend
flow. The difference in production is only *config, not code* — the hospital's
Oracle Health / Cerner administrator provisions your system app in **their**
tenant (the production equivalent of the sandbox Code Console), hands you a
Client ID and registers your public key, and you point `CERNER_TOKEN_URL` /
`CERNER_FHIR_BASE_URL` at their production tenant. Same binary, new `.env`.

## 4. Run it — 4 commands

```bash
make keygen     # 1. generate keys/private.pem + keys/public.pem
                #    -> upload keys/public.pem in the Cerner Code Console
# ... edit .env with your CLIENT_ID / KEY_ID ...
make build      # 2. compile to ./bin/cerner-fhir-oauth
make run        # 3. run the full flow, printing every request/response
make test       # 4. (optional) unit test the JWT signing, no network needed
```

`make jwks` is available if your registration asks for a **JWKS URL** instead of
a pasted public key — it prints a `jwks.json` you host at that URL.

---

## 5. What you'll see

`make run` prints three sections:

1. **STEP 1** — the signed client-assertion JWT (paste it at https://jwt.io to
   decode the header/claims), the raw `POST` to the token endpoint, and the raw
   token JSON response.
2. **STEP 2** — `GET /Patient?identifier=<system>|<MRN>` and the raw Bundle.
3. **STEP 3** — `GET /Patient/<id>` and the raw Patient JSON.

---

## 6. How this build was verified

The FHIR half was tested end-to-end against Cerner's live sandbox and the OAuth
request shape against Cerner's live token endpoint:

- `GET /Patient/12724066` → **HTTP 200**, real Patient (`SMARTS, NANCYS`).
- `GET /Patient?identifier=urn:oid:2.16.840.1.113883.3.787.0.0|6000031` →
  **HTTP 200**, a Bundle with `total: 1` resolving to that same patient — proof
  the MRN filter works.
- `POST` to the Cerner token endpoint returns a well-formed OAuth
  `invalid_client` error until a real registered app's `CLIENT_ID` + key are in
  place — proof the URL, headers, and body are exactly what Cerner expects.
- `make test` verifies the client-assertion JWT is RS384-signed with the correct
  `iss`/`sub`/`aud`/`exp`/`jti` claims.

Once you drop your own `CLIENT_ID` + private key into `.env`, STEP 1 returns a
live access token and STEP 2/3 return your patient.

---

## 7. Project layout

```
main.go                 CLI: loads .env, runs the 3 steps, prints traces
http.go                 shared HTTP client
internal/oauth/         the OAuth 2.0 client_credentials + JWT assertion logic
  oauth.go              build assertion, POST /token, capture trace
  key.go                load RSA private key (PKCS#1 or PKCS#8 PEM)
  oauth_test.go         unit test for the signed assertion
internal/fhir/          Patient search-by-MRN and read-by-id
tools/jwks/             optional: PEM public key -> JWKS document
Makefile                keygen / build / run / test
.env.example            every variable, documented
```

Libraries used: `github.com/golang-jwt/jwt/v5` (JWT signing) and
`github.com/google/uuid` (the `jti`). Everything else is the Go standard library.
