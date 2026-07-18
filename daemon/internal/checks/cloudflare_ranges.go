package checks

import "net"

// cloudflareRanges are Cloudflare's published proxy IP ranges
// (https://www.cloudflare.com/ips-v4, https://www.cloudflare.com/ips-v6,
// fetched 2026-07-11). Used only to make the dns-zone check's failure
// message specific when a mail-carrying record has been proxied through
// Cloudflare's "orange cloud" - mail protocols cannot pass through it, so
// this is the single most common identifiable cause of a public A/AAAA
// mismatch that check already flags.
var cloudflareRanges = mustParseCIDRs(
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, len(cidrs))
	for i, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("checks: bad Cloudflare CIDR " + c + ": " + err.Error())
		}
		out[i] = n
	}
	return out
}

// isCloudflareIP reports whether ip falls inside Cloudflare's published
// proxy ranges.
func isCloudflareIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range cloudflareRanges {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}
