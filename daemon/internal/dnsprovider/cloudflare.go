package dnsprovider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// Cloudflare publishes TXT records through the Cloudflare v4 API
// using a scoped API token (Zone / DNS / Edit on the zone).
type Cloudflare struct {
	Token string
	HTTP  *http.Client
	// BaseURL overrides the API endpoint (tests).
	BaseURL string
}

const cloudflareAPI = "https://api.cloudflare.com/client/v4"

func (c *Cloudflare) base() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return cloudflareAPI
}

func (c *Cloudflare) headers() map[string]string {
	return map[string]string{"Authorization": "Bearer " + c.Token}
}

// zoneID resolves the zone name to Cloudflare's zone identifier.
func (c *Cloudflare) zoneID(ctx context.Context, zone string) (string, error) {
	var out struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	u := c.base() + "/zones?name=" + url.QueryEscape(zone)
	if err := doJSON(ctx, c.HTTP, http.MethodGet, u, c.headers(), nil, &out); err != nil {
		return "", err
	}
	if len(out.Result) == 0 {
		return "", fmt.Errorf("cloudflare: zone %s not found for this token", zone)
	}
	return out.Result[0].ID, nil
}

func (c *Cloudflare) SetTXT(ctx context.Context, zone, fqdn, value string) error {
	id, err := c.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	body := map[string]any{"type": "TXT", "name": fqdn, "content": value, "ttl": 60}
	return doJSON(ctx, c.HTTP, http.MethodPost, c.base()+"/zones/"+id+"/dns_records", c.headers(), body, nil)
}

func (c *Cloudflare) DeleteTXT(ctx context.Context, zone, fqdn, value string) error {
	id, err := c.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	var out struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	u := fmt.Sprintf("%s/zones/%s/dns_records?type=TXT&name=%s&content=%s",
		c.base(), id, url.QueryEscape(fqdn), url.QueryEscape(value))
	if err := doJSON(ctx, c.HTTP, http.MethodGet, u, c.headers(), nil, &out); err != nil {
		return err
	}
	for _, rec := range out.Result {
		if err := doJSON(ctx, c.HTTP, http.MethodDelete,
			c.base()+"/zones/"+id+"/dns_records/"+rec.ID, c.headers(), nil, nil); err != nil {
			return err
		}
	}
	return nil
}
