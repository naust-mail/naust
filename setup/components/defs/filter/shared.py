"""
Shared Dovecot spam-learning setup, used by both rspamd and spamassassin.

Dovecot 2.4 path: imapsieve + sieve_extprograms (setup_dovecot_imapsieve).
Dovecot 2.3 path: the third-party dovecot-antispam plugin, which has no
sieve equivalent (setup_dovecot_antispam_pipe). Each filter provides its
own pipe scripts; this writes the Dovecot config and sieve scripts that
call them. Whole config files live as ${VAR} templates in
setup/conf/filter/<dialect>/; see the dovecot-2x-compat memory for why
2.3/2.4 need separate syntax.
"""

import os
import subprocess

from ... import SETUP_DIR, artifacts

_TPL_DIR_24 = os.path.join(SETUP_DIR, "conf", "filter", "2.4")
_TPL_DIR_23 = os.path.join(SETUP_DIR, "conf", "filter", "2.3")


def setup_dovecot_imapsieve(spam_script: str, ham_script: str) -> None:
	"""Write Dovecot 2.4 imapsieve config and sieve scripts for spam learning.

	Configures imap_sieve + sieve_extprograms so that moving mail into
	the Spam folder calls spam_script, and moving mail out calls ham_script.
	Both script names must be executables in /usr/local/bin.

	The mail_plugins/key=yes BOOLLIST syntax appends to the existing plugin
	list without replacing it - this is the Dovecot 2.4 way to extend lists.

	Do NOT pre-compile the sieve scripts with sievec - the imapsieve and
	vnd.dovecot.pipe extensions are registered by plugins that are not
	loaded until Dovecot starts; lazy compilation avoids startup-time failures.
	"""
	artifacts.write_file(
		"/etc/dovecot/conf.d/99-local-spam-learning.conf",
		artifacts.render_template(os.path.join(_TPL_DIR_24, "99-local-spam-learning.conf")),
	)

	os.makedirs("/etc/dovecot/sieve", exist_ok=True)
	artifacts.write_file(
		"/etc/dovecot/sieve/learn-spam.sieve",
		artifacts.render_template(
			os.path.join(_TPL_DIR_24, "learn-spam.sieve"),
			{"SPAM_SCRIPT": spam_script},
		),
	)
	artifacts.write_file(
		"/etc/dovecot/sieve/learn-ham.sieve",
		artifacts.render_template(
			os.path.join(_TPL_DIR_24, "learn-ham.sieve"),
			{"HAM_SCRIPT": ham_script},
		),
	)


def setup_dovecot_antispam_pipe(spam_script: str, ham_script: str) -> None:
	"""Write Dovecot 2.3 antispam-plugin config for spam learning.

	Sieve-based learning (imapsieve) does not exist in 2.3. The third-party
	dovecot-antispam plugin's pipe backend calls spam_script/ham_script on
	Spam/Not-Spam moves instead. Each arg is the script name (optionally
	with ;extra-args, e.g. "sa-learn-pipe.sh;--spam") resolved under
	/usr/local/bin. Does not touch mail_plugins or mail_access_groups -
	callers wire those themselves since the group differs per filter.
	"""
	artifacts.write_file(
		"/etc/dovecot/conf.d/99-local-spam-learning.conf",
		artifacts.render_template(
			os.path.join(_TPL_DIR_23, "99-local-spam-learning.conf"),
			{"SPAM_SCRIPT": spam_script, "HAM_SCRIPT": ham_script},
		),
	)


def enable_antispam_plugin() -> None:
	"""Add the antispam plugin to Dovecot's IMAP and POP3 mail_plugins (2.3 only)."""
	for conf in ["/etc/dovecot/conf.d/20-imap.conf", "/etc/dovecot/conf.d/20-pop3.conf"]:
		subprocess.run(
			["sed", "-i", r"s/#mail_plugins = .*/mail_plugins = $mail_plugins antispam/", conf],
			check=True,
		)
