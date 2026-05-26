<?php
/***********************************************
* File      :   backend/combined/config.php
* Project   :   Z-Push
* Descr     :   configuration file for the
*               combined backend.
************************************************/

class BackendCombinedConfig {
    public static function GetBackendCombinedConfig() {
        return array(
			'backends' => array(
				'i' => array(
					'name' => 'BackendIMAP',
				),
			),
			'delimiter' => '/',
			'folderbackend' => array(
				SYNC_FOLDER_TYPE_INBOX => 'i',
				SYNC_FOLDER_TYPE_DRAFTS => 'i',
				SYNC_FOLDER_TYPE_WASTEBASKET => 'i',
				SYNC_FOLDER_TYPE_SENTMAIL => 'i',
				SYNC_FOLDER_TYPE_OUTBOX => 'i',
				SYNC_FOLDER_TYPE_OTHER => 'i',
				SYNC_FOLDER_TYPE_USER_MAIL => 'i',
				SYNC_FOLDER_TYPE_UNKNOWN => 'i',
			),
			'rootcreatefolderbackend' => 'i',
		);
    }
}

?>
