class Hm_Handler_auto_populate_carddav_credentials extends Hm_Handler_Module {
    public function process() {
        list($success, $form) = $this->process_form(array("username", "password"));
        if (!$success || !$this->session->is_active()) {
            return;
        }
        $existing = $this->user_config->get("carddav_contacts_auth_setting", array());
        $servers  = config("carddav");
        $changed  = false;
        foreach ($servers as $name => $details) {
            if (!isset($existing[$name]["user"]) || empty($existing[$name]["user"])) {
                $existing[$name] = array("user" => rtrim($form["username"]), "pass" => $form["password"]);
                $changed = true;
            }
        }
        if ($changed) {
            $this->user_config->set("carddav_contacts_auth_setting", $existing);
            $this->user_config->save(rtrim($form["username"]), $form["password"]);
        }
    }
}
