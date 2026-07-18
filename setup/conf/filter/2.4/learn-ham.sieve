require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];
pipe :copy "${HAM_SCRIPT}";
