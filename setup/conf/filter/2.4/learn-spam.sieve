require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];
if environment :matches "imap.mailbox" "Spam" {
    pipe :copy "${SPAM_SCRIPT}";
}
