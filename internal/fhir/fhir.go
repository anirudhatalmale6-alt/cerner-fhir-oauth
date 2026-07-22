// Package fhir performs the two Patient lookups the project asks for, using the
// access token obtained by the oauth package. It returns the JSON response
// untouched, exactly as the FHIR server sent it.
package fhir

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Client calls a FHIR R4 server with a bearer token.
type Client struct {
	BaseURL     string // e.g. https://fhir-ehr-code.cerner.com/r4/<tenant>
	AccessToken string
	HTTP        *http.Client
}

// Trace mirrors oauth.Trace: it lets the CLI show the raw request/response.
type Trace struct {
	RequestLine  string
	ResponseCode int
	ResponseBody string
}

// SearchByMRN searches /Patient filtering on the MRN identifier.
//
// In FHIR you filter identifiers with `identifier=system|value`. Cerner's MRN
// identifier system in the sandbox is well-known; you can also pass just the
// value (`identifier=<mrn>`) and let the server match. We expose the system so
// you can see exactly how the token-typed search is expressed on the wire.
func (c *Client) SearchByMRN(ctx context.Context, mrnSystem, mrn string) (*Trace, error) {
	q := url.Values{}
	if mrnSystem != "" {
		q.Set("identifier", mrnSystem+"|"+mrn)
	} else {
		q.Set("identifier", mrn)
	}
	return c.get(ctx, "/Patient", q)
}

// GetByID reads a single Patient by its native FHIR logical id: GET /Patient/{id}.
// This is a direct resource read, the simplest possible FHIR call.
func (c *Client) GetByID(ctx context.Context, id string) (*Trace, error) {
	return c.get(ctx, "/Patient/"+url.PathEscape(id), nil)
}

func (c *Client) get(ctx context.Context, path string, q url.Values) (*Trace, error) {
	full := strings.TrimRight(c.BaseURL, "/") + path
	if len(q) > 0 {
		full += "?" + q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	req.Header.Set("Accept", "application/fhir+json")

	trace := &Trace{RequestLine: fmt.Sprintf("GET %s", full)}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return trace, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	trace.ResponseCode = resp.StatusCode
	trace.ResponseBody = string(raw)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return trace, fmt.Errorf("FHIR server returned %d", resp.StatusCode)
	}
	return trace, nil
}
