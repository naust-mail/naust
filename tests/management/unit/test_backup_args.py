from unittest.mock import patch


# ---------------------------------------------------------------------------
# get_duplicity_target_url
# ---------------------------------------------------------------------------


class TestGetDuplicityTargetUrl:
	def test_local_target_unchanged(self):
		from services.backup.duplicity_args import get_duplicity_target_url

		config = {"target": "file:///var/lib/naust/backup/encrypted"}
		with patch('services.backup.duplicity_args.get_target_type', return_value='file'):
			result = get_duplicity_target_url(config)
		assert result == "file:///var/lib/naust/backup/encrypted"

	def test_rsync_target_unchanged(self):
		from services.backup.duplicity_args import get_duplicity_target_url

		config = {"target": "rsync://user@host/path"}
		with patch('services.backup.duplicity_args.get_target_type', return_value='rsync'):
			result = get_duplicity_target_url(config)
		assert result == "rsync://user@host/path"

	def test_s3_target_moves_bucket_to_hostname(self):
		from services.backup.duplicity_args import get_duplicity_target_url

		# S3 URL format: s3://region@s3.amazonaws.com/bucketname/prefix
		config = {"target": "s3://region@s3.amazonaws.com/mybucket/backups"}
		with patch('services.backup.duplicity_args.get_target_type', return_value='s3'):
			result = get_duplicity_target_url(config)
		# The bucket name must now be in the hostname component
		assert "mybucket" in result
		# The S3 hostname should not appear as the netloc
		assert "s3.amazonaws.com" not in result.split("/")[2]

	def test_s3_target_result_is_valid_url(self):
		from urllib.parse import urlsplit
		from services.backup.duplicity_args import get_duplicity_target_url

		config = {"target": "s3://region@s3.amazonaws.com/mybucket/prefix"}
		with patch('services.backup.duplicity_args.get_target_type', return_value='s3'):
			result = get_duplicity_target_url(config)
		parsed = urlsplit(result)
		assert parsed.scheme == "s3"


# ---------------------------------------------------------------------------
# get_duplicity_additional_args
# ---------------------------------------------------------------------------


class TestGetDuplicityAdditionalArgs:
	def test_rsync_target_returns_ssh_args(self):
		from services.backup.duplicity_args import get_duplicity_additional_args

		config = {"target": "rsync://user@host:2222/path"}
		env = {}
		with patch('services.backup.duplicity_args.get_backup_config', return_value=config), patch('services.backup.duplicity_args.get_target_type', return_value='rsync'):
			args = get_duplicity_additional_args(env)
		assert any("--ssh-options" in a for a in args)
		assert any("--rsync-options" in a for a in args)

	def test_rsync_uses_default_port_when_none(self):
		from services.backup.duplicity_args import get_duplicity_additional_args

		config = {"target": "rsync://user@host/path"}
		env = {}
		with patch('services.backup.duplicity_args.get_backup_config', return_value=config), patch('services.backup.duplicity_args.get_target_type', return_value='rsync'):
			args = get_duplicity_additional_args(env)
		assert any("-p 22" in a for a in args)

	def test_s3_target_returns_endpoint_arg(self):
		from services.backup.duplicity_args import get_duplicity_additional_args

		config = {"target": "s3://us-east-1@s3.amazonaws.com/bucket/prefix"}
		env = {}
		with patch('services.backup.duplicity_args.get_backup_config', return_value=config), patch('services.backup.duplicity_args.get_target_type', return_value='s3'):
			args = get_duplicity_additional_args(env)
		assert "--s3-endpoint-url" in args

	def test_local_target_returns_empty_args(self):
		from services.backup.duplicity_args import get_duplicity_additional_args

		config = {"target": "file:///backups"}
		env = {}
		with patch('services.backup.duplicity_args.get_backup_config', return_value=config), patch('services.backup.duplicity_args.get_target_type', return_value='file'):
			args = get_duplicity_additional_args(env)
		assert args == []


# ---------------------------------------------------------------------------
# get_duplicity_env_vars
# ---------------------------------------------------------------------------


class TestGetDuplicityEnvVars:
	def test_passphrase_always_present(self):
		from services.backup.duplicity_args import get_duplicity_env_vars

		config = {"target": "file:///backups"}
		env = {}
		with patch('services.backup.duplicity_args.get_backup_config', return_value=config), patch('services.backup.duplicity_args.get_target_type', return_value='file'), patch('services.backup.duplicity_args.get_passphrase', return_value='mysecretpassphrase'):
			result = get_duplicity_env_vars(env)
		assert result["PASSPHRASE"] == "mysecretpassphrase"

	def test_s3_credentials_included(self):
		from services.backup.duplicity_args import get_duplicity_env_vars

		config = {
			"target": "s3://us-east-1@s3.amazonaws.com/bucket/prefix",
			"target_user": "AKID",
			"target_pass": "SECRET",
		}
		env = {}
		with patch('services.backup.duplicity_args.get_backup_config', return_value=config), patch('services.backup.duplicity_args.get_target_type', return_value='s3'), patch('services.backup.duplicity_args.get_passphrase', return_value='pp'):
			result = get_duplicity_env_vars(env)
		assert result["AWS_ACCESS_KEY_ID"] == "AKID"
		assert result["AWS_SECRET_ACCESS_KEY"] == "SECRET"

	def test_local_target_no_aws_keys(self):
		from services.backup.duplicity_args import get_duplicity_env_vars

		config = {"target": "file:///backups"}
		env = {}
		with patch('services.backup.duplicity_args.get_backup_config', return_value=config), patch('services.backup.duplicity_args.get_target_type', return_value='file'), patch('services.backup.duplicity_args.get_passphrase', return_value='pp'):
			result = get_duplicity_env_vars(env)
		assert "AWS_ACCESS_KEY_ID" not in result
		assert "AWS_SECRET_ACCESS_KEY" not in result
