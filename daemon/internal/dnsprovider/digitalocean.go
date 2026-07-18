package dnsprovider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// DigitalOcean publishes TXT records through the DigitalOcean v2
// domains API using a personal access token.
type DigitalOcean struct {
	Token string
	HTTP  *http.Client
	// BaseURL overrides the API endpoint (tests).
	BaseURL string
}

const digitaloceanAPI = "https://api.digitalocean.com/v2"

func (d *DigitalOcean) base() string {
	if d.BaseURL != "" {
		return d.BaseURL
	}
	return digitaloceanAPI
}

func (d *DigitalOcean) headers() map[string]string {
	return map[string]string{"Authorization": "Bearer " + d.Token}
}

func (d *DigitalOcean) SetTXT(ctx context.Context, zone, fqdn, value string) error {
	// DigitalOcean's minimum TTL is 30 seconds.
	body := map[string]any{"type": "TXT", "name": relativeName(fqdn, zone), "data": value, "ttl": 30}
	return doJSON(ctx, d.HTTP, http.MethodPost,
		d.base()+"/domains/"+url.PathEscape(zone)+"/records", d.headers(), body, nil)
}

func (d *DigitalOcean) DeleteTXT(ctx context.Context, zone, fqdn, value string) error {
	var out struct {
		DomainRecords []struct {
			ID   int64  `json:"id"`
			Data string `json:"data"`
		} `json:"domain_records"`
	}
	u := fmt.Sprintf("%s/domains/%s/records?type=TXT&name=%s&per_page=200",
		d.base(), url.PathEscape(zone), url.QueryEscape(fqdn))
	if err := doJSON(ctx, d.HTTP, http.MethodGet, u, d.headers(), nil, &out); err != nil {
		return err
	}
	for _, rec := range out.DomainRecords {
		if rec.Data != value {
			continue
		}
		if err := doJSON(ctx, d.HTTP, http.MethodDelete,
			fmt.Sprintf("%s/domains/%s/records/%d", d.base(), url.PathEscape(zone), rec.ID),
			d.headers(), nil, nil); err != nil {
			return err
		}
	}
	return nil
}
