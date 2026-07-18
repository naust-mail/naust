class Hm_Handler_log_failed_login extends Hm_Handler_Module {
    public function process() {
        list($success, $form) = $this->process_form(array('username', 'password'));
        if (!$success) { return; }
        if ($this->session->is_active()) { return; }
        $ip = isset($this->request->server['REMOTE_ADDR']) ? $this->request->server['REMOTE_ADDR'] : 'unknown';
        $raw = isset($form['username']) ? rtrim($form['username']) : 'unknown';
        $user = substr(preg_replace('/[^\x20-\x7E]/', '', $raw), 0, 254);
        $line = '[' . date('Y-m-d H:i:s') . '] Failed login for ' . $user . ' from ' . $ip . PHP_EOL;
        @file_put_contents('/var/log/cypht-auth.log', $line, FILE_APPEND | LOCK_EX);
    }
}
