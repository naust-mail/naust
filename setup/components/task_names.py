"""
Cross-component task name constants.

Only cross-component task_dep references belong here. Internal deps (e.g.
"postfix:static" used only within postfix.py) stay as plain strings in their
own file - they can only break the component that owns them and the graph
validity tests catch any dangling refs.

Convention: OWNING_COMPONENT_STEP_NAME

A test in tests/components/graph/test_task_names_sync.py verifies every
constant here resolves to a real task in the component graph.
"""

# dovecot
DOVECOT_VERSION = "dovecot:version"

# postfix - last main.cf writer before component-specific milters; rspamd, dkim,
# and users must run after this to ensure their editconf calls are not clobbered
POSTFIX_SPAM_FILTER = "postfix:spam-filter"

# rspamd - assigns smtpd_milters= in main.cf; clamav appends after this
RSPAMD_POSTFIX_MILTERS = "rspamd:postfix-milters"

# dkim - assigns smtpd_milters= in main.cf (spamassassin path); clamav appends after this
DKIM_POSTFIX_MILTERS = "dkim:postfix-milters"

# ssl - self-signed cert generation; rav's config references the cert paths
SSL_CERT = "ssl:cert"

# daemon - Go binary installation; unit-installing components depend on
# the binary their unit execs
DAEMON_HELPERD = "daemon:helperd"
DAEMON_MANAGERD = "daemon:managerd"
DAEMON_MUNINWEB = "daemon:muninweb"

# helper - creates the naust socket group; the managerd user joins it
HELPER_GROUP = "helper:group"
