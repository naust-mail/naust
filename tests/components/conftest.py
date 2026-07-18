import itertools

_SPAM_FILTERS = ["rspamd", "spamassassin"]
_WEBMAIL_CLIENTS = ["rav", "roundcube", "snappymail", "cypht", "none"]
_BOOLS = ["true", "false"]
_RUNTIMES = ["baremetal", "docker"]

CONFIG_MATRIX = [
	{
		"SPAM_FILTER": sf,
		"WEBMAIL_CLIENT": wc,
		"ENABLE_RADICALE": er,
		"ENABLE_FILEBROWSER": ef,
		"ENABLE_CLAMAV": ec,
		"_RUNTIME": rt,
	}
	for sf, wc, er, ef, ec, rt in itertools.product(_SPAM_FILTERS, _WEBMAIL_CLIENTS, _BOOLS, _BOOLS, _BOOLS, _RUNTIMES)
]


def make_env(tmp_path, **overrides):
	base = {
		"STORAGE_ROOT": str(tmp_path / "storage"),
		"PRIMARY_HOSTNAME": "box.example.com",
		"PRIVATE_IP": "10.0.0.1",
		"PRIVATE_IPV6": "",
		"PUBLIC_IP": "1.2.3.4",
		"EMAIL_ADDR": "admin@example.com",
		"SPAM_FILTER": "rspamd",
		"WEBMAIL_CLIENT": "rav",
		"ENABLE_RADICALE": "false",
		"ENABLE_FILEBROWSER": "false",
		"ENABLE_CLAMAV": "false",
		"BACKUP_TOOL": "restic",
	}
	base.update(overrides)
	return base


# Representative backup configs: one per backend, each paired with baremetal.
# Used to extend graph validity and task_names checks to backup components.
BACKUP_CONFIGS = [
	{"BACKUP_TOOL": "restic", "_RUNTIME": "baremetal"},
	{"BACKUP_TOOL": "duplicity", "_RUNTIME": "baremetal"},
]


def all_task_names(graph):
	names = set()
	for comp_name, tasks in graph.items():
		names.update(f"{comp_name}:{t['name']}" for t in tasks)
	return names
