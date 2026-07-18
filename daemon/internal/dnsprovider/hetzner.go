package dnsprovider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// Hetzner publishes TXT records through the Hetzner DNS API using an
// API token.
type Hetzner struct {
	Token string
	HTTP  *http.Client
	// BaseURL overrides the API endpoint (tests).
	BaseURL string
}

const hetznerAPI = "https://dns.hetzner.com/api/v1"

func (h *Hetzner) base() string {
	if h.BaseURL != "" {
		return h.BaseURL
	}
	return hetznerAPI
}

func (h *Hetzner) headers() map[string]string {
	return map[string]string{"Auth-API-Token": h.Token}
}

func (h *Hetzner) zoneID(ctx context.Context, zone string) (string, error) {
	var out struct {
		Zones []struct {
			ID string `json:"id"`
		} `json:"zones"`
	}
	u := h.base() + "/zones?name=" + url.QueryEscape(zone)
	if err := doJSON(ctx, h.HTTP, http.MethodGet, u, h.headers(), nil, &out); err != nil {
		return "", err
	}
	if len(out.Zones) == 0 {
		return "", fmt.Errorf("hetzner: zone %s not found for this token", zone)
	}
	return out.Zones[0].ID, nil
}

func (h *Hetzner) SetTXT(ctx context.Context, zone, fqdn, value string) error {
	id, err := h.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	body := map[string]any{
		"zone_id": id, "type": "TXT", "name": relativeName(fqdn, zone), "value": value, "ttl": 60,
	}
	return doJSON(ctx, h.HTTP, http.MethodPost, h.base()+"/records", h.headers(), body, nil)
}

func (h *Hetzner) DeleteTXT(ctx context.Context, zone, fqdn, value string) error {
	id, err := h.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	var out struct {
		Records []struct {
			ID    string `json:"id"`
			Type  string `json:"type"`
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"records"`
	}
	if err := doJSON(ctx, h.HTTP, http.MethodGet,
		h.base()+"/records?zone_id="+url.QueryEscape(id), h.headers(), nil, &out); err != nil {
		return err
	}
	name := relativeName(fqdn, zone)
	for _, rec := range out.Records {
		if rec.Type != "TXT" || rec.Name != name || rec.Value != value {
			continue
		}
		if err := doJSON(ctx, h.HTTP, http.MethodDelete,
			h.base()+"/records/"+url.PathEscape(rec.ID), h.headers(), nil, nil); err != nil {
			return err
		}
	}
	return nil
}
