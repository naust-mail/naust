package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"naust/daemon/internal/store/ent"
	entsetting "naust/daemon/internal/store/ent/setting"
)

// SettingKey holds the administrator's overrides as JSON. Written by
// the config API (httpapi), read by the scheduler each pass so
// changes apply without a restart.
const SettingKey = "status_checks"

// Cadence values an administrator may set per check. "weekly" and
// "off" exist only as overrides; no check defaults to them.
var cadenceIntervals = map[string]time.Duration{
	"fast":   5 * time.Minute,
	"hourly": time.Hour,
	"daily":  24 * time.Hour,
	"weekly": 7 * 24 * time.Hour,
	"off":    0,
}

// CheckOverride is one check's admin configuration.
type CheckOverride struct {
	// Cadence replaces the check's default tier: fast, hourly,
	// daily, weekly, or off. Empty keeps the default.
	Cadence string `json:"cadence,omitempty"`
	// Enabled false stops scheduling the check entirely (its last
	// result is replaced by a "disabled" skip). Nil means enabled.
	Enabled *bool `json:"enabled,omitempty"`
}

// Config is the status_checks setting payload.
type Config struct {
	Checks map[string]CheckOverride `json:"checks,omitempty"`
	// Report schedules the status-change digest email: off, daily,
	// or weekly. Empty means off.
	Report string `json:"report,omitempty"`
}

// Validate rejects unknown cadences and report schedules. Unknown
// check names are allowed (a stale override is harmless and the
// registry may grow).
func (c Config) Validate() error {
	for name, o := range c.Checks {
		if o.Cadence != "" {
			if _, ok := cadenceIntervals[o.Cadence]; !ok {
				return fmt.Errorf("check %q: unknown cadence %q", name, o.Cadence)
			}
		}
	}
	switch c.Report {
	case "", "off", "daily", "weekly":
	default:
		return fmt.Errorf("unknown report schedule %q", c.Report)
	}
	return nil
}

// LoadConfig reads the setting; a missing row is the zero Config.
func LoadConfig(ctx context.Context, store *ent.Client) (Config, error) {
	var cfg Config
	row, err := store.Setting.Query().Where(entsetting.Key(SettingKey)).Only(ctx)
	if ent.IsNotFound(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal([]byte(row.Value), &cfg); err != nil {
		return cfg, fmt.Errorf("%s setting: %w", SettingKey, err)
	}
	return cfg, nil
}

// effective resolves a check's interval under the config. enabled
// false means the admin turned the check off (cadence "off" counts).
func (c Config) effective(chk Check) (interval time.Duration, enabled bool) {
	interval = cadenceIntervals[string(chk.Tier)]
	o, ok := c.Checks[chk.Name]
	if !ok {
		return interval, true
	}
	if o.Enabled != nil && !*o.Enabled {
		return 0, false
	}
	if o.Cadence != "" {
		interval = cadenceIntervals[o.Cadence]
		if o.Cadence == "off" {
			return 0, false
		}
	}
	return interval, true
}
