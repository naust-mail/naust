# Translates the new CheckResult/StepResult shape into the flat
# {type, text, detail, extra} list SystemStatusPage.vue renders.

_LABEL_OVERRIDES = {
	"naust-version": "Version Check",
	"ufw": "Firewall",
	"filebrowser": "FileBrowser",
	"fail2ban": "Fail2ban",
	"unbound": "Unbound",
	"outbound-smtp": "Outbound SMTP",
	"service:rspamd": "Rspamd",
	"service:Redis": "Redis",
}

_ACRONYM_FIX = {
	"Dns": "DNS",
	"Smtp": "SMTP",
	"Mx": "MX",
	"Tls": "TLS",
	"Ssh": "SSH",
	"Imap": "IMAP",
	"Miab": "NAUST",
	"Rbl": "RBL",
	"Ipv4": "IPv4",
	"Ipv6": "IPv6",
	"Lda": "LDA",
	"Http": "HTTP",
	"Https": "HTTPS",
	"Ufw": "UFW",
}


def _humanize(name):
	if name in _LABEL_OVERRIDES:
		return _LABEL_OVERRIDES[name]
	for prefix in ("service:", "rbl-ipv4:", "rbl-ipv6:"):
		if name.startswith(prefix):
			return name[len(prefix) :]
	words = name.replace("-", " ").title().split()
	return " ".join(_ACRONYM_FIX.get(w, w) for w in words)


def to_legacy_items(results):
	items = []
	by_category = {}
	for r in results.values():
		by_category.setdefault(r.category, []).append(r)

	for category in sorted(by_category):
		items.append({"type": "heading", "text": category.replace("-", " ").title(), "extra": []})
		for r in sorted(by_category[category], key=lambda r: (r.name, r.domain or "")):
			if r.status == "skipped":
				continue

			label = _humanize(r.name)
			if r.domain:
				label = f"{label} [{r.domain}]"

			item_type = r.status if r.status in {"ok", "warning", "error"} else "warning"

			failing = [s for s in r.steps if s.status in {"error", "warning"}]
			passing = [s for s in r.steps if s.status == "ok"]

			if item_type in {"error", "warning"}:
				detail = failing[0].message if failing and failing[0].message else ""
				extra = [{"text": f"{s.name}: {s.message}" if s.message else s.name, "monospace": False} for s in failing[1:]]
			else:
				# Show the first passing step name as detail to give context.
				# Skip it only when it duplicates the label (service checks name
				# their single step after the service itself).
				first = passing[0].name if passing else ""
				detail = "" if not first or first.lower() == label.lower() else first
				# Remaining steps go in expand (skip any that also equal the label).
				extra = [{"text": s.name, "monospace": False} for s in passing[1:] if s.name.lower() != label.lower()]

			items.append({"type": item_type, "text": label, "detail": detail, "extra": extra})

	return items
