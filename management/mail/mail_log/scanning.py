import datetime
import gzip
import os.path
import re
import shutil
import tempfile
from collections import defaultdict

from . import state
from .util import readline, user_match


def scan_files(collector):
	"""Scan files until they run out or the earliest date is reached"""

	stop_scan = False

	for fn in state.LOG_FILES:
		tmp_file = None

		if not os.path.exists(fn):
			continue
		if fn[-3:] == '.gz':
			tmp_file = tempfile.NamedTemporaryFile()
			with gzip.open(fn, 'rb') as f:
				shutil.copyfileobj(f, tmp_file)

		if state.VERBOSE:
			print("Processing file", fn, "...")
		fn = tmp_file.name if tmp_file else fn

		for line in readline(fn):
			if scan_mail_log_line(line.strip(), collector) is False:
				if stop_scan:
					return
				stop_scan = True
			else:
				stop_scan = False


def scan_mail_log_line(line, collector):
	"""Scan a log line and extract interesting data"""

	m = re.match(r"(\w+[\s]+\d+ \d+:\d+:\d+) ([\w]+ )?([\w\-/]+)[^:]*: (.*)", line)

	if not m:
		return True

	date, _system, service, log = m.groups()
	collector["scan_count"] += 1

	# print()
	# print("date:", date)
	# print("host:", system)
	# print("service:", service)
	# print("log:", log)

	# Replaced the dateutil parser for a less clever way of parser that is roughly 4 times faster.
	# date = dateutil.parser.parse(date)

	# strptime fails on Feb 29 with ValueError: day is out of range for month if correct year is not provided.
	# See https://bugs.python.org/issue26460
	date = datetime.datetime.strptime(str(state.NOW.year) + ' ' + date, '%Y %b %d %H:%M:%S')
	# if log date in future, step back a year
	if date > state.NOW:
		date = date.replace(year=state.NOW.year - 1)
	# print("date:", date)

	# Check if the found date is within the time span we are scanning
	if date > state.END_DATE:
		# Don't process, and halt
		return False
	if date < state.START_DATE:
		# Don't process, but continue
		return True

	if service == "postfix/submission/smtpd":
		if state.SCAN_OUT:
			scan_postfix_submission_line(date, log, collector)
	elif service == "postfix/lmtp":
		if state.SCAN_IN:
			scan_postfix_lmtp_line(date, log, collector)
	elif service.endswith("-login"):
		if state.SCAN_DOVECOT_LOGIN:
			scan_dovecot_login_line(date, log, collector, service[:4])
	elif service == "postgrey":
		if state.SCAN_GREY:
			scan_postgrey_line(date, log, collector)
	elif service == "postfix/smtpd":
		if state.SCAN_BLOCKED:
			scan_postfix_smtpd_line(date, log, collector)
	elif service in {"postfix/qmgr", "postfix/pickup", "postfix/cleanup", "postfix/scache", "spampd", "postfix/anvil", "postfix/master", "opendkim", "postfix/lmtp", "postfix/tlsmgr", "anvil"}:
		# nothing to look at
		return True
	else:
		collector["other-services"].add(service)
		return True

	collector["parse_count"] += 1
	return True


def scan_postgrey_line(date, log, collector):
	"""Scan a postgrey log line and extract interesting data"""

	m = re.match(
		r"action=(greylist|pass), reason=(.*?), (?:delay=\d+, )?client_name=(.*), "
		r"client_address=(.*), sender=(.*), recipient=(.*)",
		log,
	)

	if m:
		action, reason, client_name, client_address, sender, user = m.groups()

		if user_match(user):
			# Might be useful to group services that use a lot of mail different servers on sub
			# domains like <sub>1.domein.com

			# if '.' in client_name:
			#     addr = client_name.split('.')
			#     if len(addr) > 2:
			#         client_name = '.'.join(addr[1:])

			key = (client_address if client_name == 'unknown' else client_name, sender)

			rep = collector["postgrey"].setdefault(user, {})

			if action == "greylist" and reason == "new":
				rep[key] = (date, rep[key][1] if key in rep else None)
			elif action == "pass":
				rep[key] = (rep[key][0] if key in rep else None, date)


def scan_postfix_smtpd_line(date, log, collector):
	"""Scan a postfix smtpd log line and extract interesting data"""

	# Check if the incoming mail was rejected

	m = re.match(r"NOQUEUE: reject: RCPT from .*?: (.*?); from=<(.*?)> to=<(.*?)>", log)

	if m:
		message, sender, user = m.groups()

		# skip this, if reported in the greylisting report
		if "Recipient address rejected: Greylisted" in message:
			return

		# only log mail to known recipients
		if user_match(user) and (collector["known_addresses"] is None or user in collector["known_addresses"]):
			data = collector["rejected"].get(
				user,
				{
					"blocked": [],
					"earliest": None,
					"latest": None,
				},
			)
			# simplify this one
			m = re.search(r"Client host \[(.*?)\] blocked using zen.spamhaus.org; (.*)", message)
			if m:
				message = "ip blocked: " + m.group(2)
			else:
				# simplify this one too
				m = re.search(r"Sender address \[.*@(.*)\] blocked using dbl.spamhaus.org; (.*)", message)
				if m:
					message = "domain blocked: " + m.group(2)

			if data["earliest"] is None:
				data["earliest"] = date
			data["latest"] = date
			data["blocked"].append((date, sender, message))

			collector["rejected"][user] = data


def scan_dovecot_login_line(date, log, collector, protocol_name):
	"""Scan a dovecot login log line and extract interesting data"""

	m = re.match(r"Info: Login: user=<(.*?)>, method=PLAIN, rip=(.*?),", log)

	if m:
		user, host = m.groups()

		if user_match(user):
			add_login(user, date, protocol_name, host, collector)


def add_login(user, date, protocol_name, host, collector):
	# Get the user data, or create it if the user is new
	data = collector["logins"].get(
		user,
		{
			"earliest": None,
			"latest": None,
			"totals_by_protocol": defaultdict(int),
			"totals_by_protocol_and_host": defaultdict(int),
			"activity-by-hour": defaultdict(lambda: defaultdict(int)),
		},
	)

	if data["earliest"] is None:
		data["earliest"] = date
	data["latest"] = date

	data["totals_by_protocol"][protocol_name] += 1
	data["totals_by_protocol_and_host"][protocol_name, host] += 1

	if host not in {"127.0.0.1", "::1"} or True:
		data["activity-by-hour"][protocol_name][date.hour] += 1

	collector["logins"][user] = data


def scan_postfix_lmtp_line(date, log, collector):
	"""Scan a postfix lmtp log line and extract interesting data

	It is assumed that every log of postfix/lmtp indicates an email that was successfully
	received by Postfix.

	"""

	m = re.match(r"([A-Z0-9]+): to=<(\S+)>, .* Saved", log)

	if m:
		_, user = m.groups()

		if user_match(user):
			# Get the user data, or create it if the user is new
			data = collector["received_mail"].get(
				user,
				{
					"received_count": 0,
					"earliest": None,
					"latest": None,
					"activity-by-hour": defaultdict(int),
				},
			)

			data["received_count"] += 1
			data["activity-by-hour"][date.hour] += 1

			if data["earliest"] is None:
				data["earliest"] = date
			data["latest"] = date

			collector["received_mail"][user] = data


def scan_postfix_submission_line(date, log, collector):
	"""Scan a postfix submission log line and extract interesting data

	Lines containing a sasl_method with the values PLAIN or LOGIN are assumed to indicate a sent
	email.

	"""

	# Match both the 'plain' and 'login' sasl methods, since both authentication methods are
	# allowed by Dovecot. Exclude trailing comma after the username when additional fields
	# follow after.
	m = re.match(r"([A-Z0-9]+): client=(\S+), sasl_method=(PLAIN|LOGIN), sasl_username=(\S+)(?<!,)", log)

	if m:
		_, client, _method, user = m.groups()

		if user_match(user):
			# Get the user data, or create it if the user is new
			data = collector["sent_mail"].get(
				user,
				{
					"sent_count": 0,
					"hosts": set(),
					"earliest": None,
					"latest": None,
					"activity-by-hour": defaultdict(int),
				},
			)

			data["sent_count"] += 1
			data["hosts"].add(client)
			data["activity-by-hour"][date.hour] += 1

			if data["earliest"] is None:
				data["earliest"] = date
			data["latest"] = date

			collector["sent_mail"][user] = data

			# Also log this as a login.
			add_login(user, date, "smtp", client, collector)
