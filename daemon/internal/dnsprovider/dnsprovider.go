// Package dnsprovider holds the DNS host plugins certificate
// provisioning publishes DNS-01 challenge records through. Each
// provider is a pure API client with no ACME knowledge; the acmeprov
// package owns all challenge mechanics.
//
// Ownership rule: providers never overwrite or take over anything in
// the user's zone. SetTXT adds a record alongside whatever exists
// (extra TXT records at a challenge name are permitted by RFC 8555);
// DeleteTXT removes only records matching the exact name AND value
// this box published. A/MX/everything else is never touched: this is
// challenge publication, not zone synchronization.
package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// Provider is what a DNS host plugin implements: publish and remove
// one TXT record in a zone.
type Provider interface {
	// SetTXT creates a TXT record fqdn -> value in the zone,
	// alongside any existing records at that name.
	SetTXT(ctx context.Context, zone, fqdn, value string) error
	// DeleteTXT removes the record SetTXT created. Only records
	// matching fqdn AND value are touched, so concurrent orders and
	// other ACME clients in the same zone cannot lose their
	// challenges to us.
	DeleteTXT(ctx context.Context, zone, fqdn, value string) error
}

// factories is the plugin registry: provider name (as stored per
// zone) -> client constructor. Adding a provider means one API
// client file and one entry here.
var factories = map[string]func(token string, hc *http.Client) Provider{
	"cloudflare":   func(token string, hc *http.Client) Provider { return &Cloudflare{Token: token, HTTP: hc} },
	"digitalocean": func(token string, hc *http.Client) Provider { return &DigitalOcean{Token: token, HTTP: hc} },
	"hetzner":      func(token string, hc *http.Client) Provider { return &Hetzner{Token: token, HTTP: hc} },
}

// Names lists the supported DNS providers, sorted, for API
// validation and the panel's provider picker.
func Names() []string {
	names := make([]string, 0, len(factories))
	for name := range factories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// New builds the API client for a configured zone provider.
func New(name, token string, hc *http.Client) (Provider, error) {
	factory, ok := factories[name]
	if !ok {
		return nil, fmt.Errorf("unknown DNS provider %q", name)
	}
	return factory(token, hc), nil
}

// relativeName converts fqdn to the zone-relative record name most
// provider APIs expect ("_acme-challenge.mail" for zone example.com).
func relativeName(fqdn, zone string) string {
	if fqdn == zone {
		return "@"
	}
	return strings.TrimSuffix(fqdn, "."+zone)
}

// doJSON performs one authenticated JSON API call. A non-2xx status
// is an error carrying a truncated response body for the panel.
func doJSON(ctx context.Context, hc *http.Client, method, url string, headers map[string]string, body, out any) error {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reqBody = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		detail := strings.TrimSpace(string(data))
		if len(detail) > 200 {
			detail = detail[:200]
		}
		return fmt.Errorf("%s %s: %s: %s", method, req.URL.Path, res.Status, detail)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}
