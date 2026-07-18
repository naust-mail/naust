package checks

import "testing"

func TestIsCloudflareIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"104.21.30.36", true},   // observed live on a proxied test domain
		{"172.67.150.121", true}, // observed live on a proxied test domain
		{"2606:4700:3035::ac43:9679", true},
		{"173.245.48.1", true},   // range floor
		{"103.100.38.25", false}, // a real box IP, not in any Cloudflare /22 near 103.21-31.x
		{"10.0.0.1", false},      // private, unrelated
		{"8.8.8.8", false},       // public, unrelated
		{"not-an-ip", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isCloudflareIP(c.ip); got != c.want {
			t.Errorf("isCloudflareIP(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}
