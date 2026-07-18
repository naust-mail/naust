"""Entry point: python3 management/mail/mail_log [options]"""

import argparse
import os
import sys

# When run as `python3 management/mail/mail_log`, __package__ is '' and
# relative imports fail - same situation setup/wizard/__main__.py solves.
if __package__ in (None, ''):
	sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
	from core import utils
	from mail.mail_log import state
	from mail.mail_log.util import valid_date
	from mail.mail_log.summary import scan_mail_log
else:
	from core import utils
	from . import state
	from .util import valid_date
	from .summary import scan_mail_log

if __name__ == "__main__":
	try:
		env_vars = utils.load_environment()
	except FileNotFoundError:
		env_vars = {}

	parser = argparse.ArgumentParser(description="Scan the mail log files for interesting data. By default, this script shows today's incoming and outgoing mail statistics. https://github.com/naust-mail/naust", add_help=False)

	# Switches to determine what to parse and what to ignore

	parser.add_argument("-r", "--received", help="Scan for received emails.", action="store_true")
	parser.add_argument("-s", "--sent", help="Scan for sent emails.", action="store_true")
	parser.add_argument("-l", "--logins", help="Scan for user logins to IMAP/POP3.", action="store_true")
	parser.add_argument("-g", "--grey", help="Scan for greylisted emails.", action="store_true")
	parser.add_argument("-b", "--blocked", help="Scan for blocked emails.", action="store_true")

	parser.add_argument("-t", "--timespan", choices=state.TIME_DELTAS.keys(), default='today', metavar='<time span>', help="Time span to scan, going back from the end date. Possible values: {}. Defaults to 'today'.".format(", ".join(list(state.TIME_DELTAS.keys()))))
	# keep the --startdate arg for backward compatibility
	parser.add_argument("-d", "--enddate", "--startdate", action="store", dest="enddate", type=valid_date, metavar='<end date>', help="Date and time to end scanning the log file. If no date is provided, scanning will end at the current date and time. Alias --startdate is for compatibility.")
	parser.add_argument("-u", "--users", action="store", dest="users", metavar='<email1,email2,email...>', help="Comma separated list of (partial) email addresses to filter the output with.")

	parser.add_argument('-h', '--help', action='help', help="Print this message and exit.")
	parser.add_argument("-v", "--verbose", help="Output extra data where available.", action="store_true")

	args = parser.parse_args()

	if args.enddate is not None:
		state.END_DATE = args.enddate
		if args.timespan == 'today':
			args.timespan = 'day'
		print(f"Setting end date to {state.END_DATE}")

	state.START_DATE = state.END_DATE - state.TIME_DELTAS[args.timespan]

	state.VERBOSE = args.verbose

	if args.received or args.sent or args.logins or args.grey or args.blocked:
		state.SCAN_IN = args.received
		if not state.SCAN_IN:
			print("Ignoring received emails")

		state.SCAN_OUT = args.sent
		if not state.SCAN_OUT:
			print("Ignoring sent emails")

		state.SCAN_DOVECOT_LOGIN = args.logins
		if not state.SCAN_DOVECOT_LOGIN:
			print("Ignoring logins")

		state.SCAN_GREY = args.grey
		if state.SCAN_GREY:
			print("Showing greylisted emails")

		state.SCAN_BLOCKED = args.blocked
		if state.SCAN_BLOCKED:
			print("Showing blocked emails")

	if args.users is not None:
		state.FILTERS = args.users.strip().split(',')

	scan_mail_log(env_vars)
