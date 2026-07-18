#!/usr/local/lib/naust/env/bin/python3
"""Nightly maintenance tasks - run via cron from /usr/local/lib/naust/."""

import datetime
import os
import subprocess

os.environ.update({
	"LANGUAGE": "en_US.UTF-8",
	"LC_ALL": "en_US.UTF-8",
	"LANG": "en_US.UTF-8",
	"LC_TYPE": "en_US.UTF-8",
})

_PYTHON = "/usr/local/lib/naust/env/bin/python3"
_EMAILER = "management/mail/email_administrator.py"


def run_task(cmd: list[str], subject: str) -> None:
	result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	subprocess.run([_EMAILER, subject], input=result.stdout)


# Weekly mail usage report (Mondays only).
if datetime.date.today().weekday() == 0:
	run_task([_PYTHON, "management/mail/mail_log", "-t", "week"], "Naust Usage Report")

run_task([_PYTHON, "management/services/backup"], "Backup Status")
run_task([_PYTHON, "management/services/ssl_certificates", "-q"], "TLS Certificate Provisioning Result")
run_task([_PYTHON, "management/services/status_checks", "--show-changes"], "Status Checks Change Notice")
