# High confidence on DB schema usage and credential byte construction. Moderate
# uncertainty on edge cases around duplicate credential_id (UNIQUE constraint
# behaviour tested directly via the DB). fido2 ceremonies are mocked; real
# ceremony interactions are covered in the unit tests.

import os
import struct
import pytest

from unittest.mock import patch, MagicMock

_KICK_USERS = "mail.mailconfig.sync.kick"
_DOVEADM = "mail.mailconfig.users.dovecot_quota_recalc"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _add_user(email: str, env: dict, pw: str = "Password123!") -> None:
	with patch(_KICK_USERS, return_value="ok"), patch(_DOVEADM):
		from mail.mailconfig.users import add_mail_user

		add_mail_user(email, pw, "", "0", env)


def _build_acd_bytes(cred_id: bytes | None = None) -> bytes:
	"""Build a minimal but valid AttestedCredentialData blob using a real EC key.

	Returns raw bytes that AttestedCredentialData(raw) can parse without error.
	"""
	from fido2 import cbor
	from cryptography.hazmat.primitives.asymmetric.ec import (
		generate_private_key,
		SECP256R1,
	)
	from cryptography.hazmat.backends import default_backend

	privkey = generate_private_key(SECP256R1(), default_backend())
	pub = privkey.public_key().public_numbers()
	x = pub.x.to_bytes(32, "big")
	y = pub.y.to_bytes(32, "big")
	cose_key = {1: 2, 3: -7, -1: 1, -2: x, -3: y}

	aaguid = b"\x00" * 16
	if cred_id is None:
		cred_id = os.urandom(16)
	cred_id_len = struct.pack(">H", len(cred_id))
	return aaguid + cred_id_len + cred_id + cbor.encode(cose_key)


def _insert_credential(env: dict, email: str, name: str = "Test Key", cred_id: bytes | None = None) -> tuple[bytes, bytes]:
	"""Insert a webauthn_credentials row directly. Returns (cred_id, acd_bytes)."""
	from mail.mailconfig import open_database
	from auth.mfa import get_user_id

	acd_bytes = _build_acd_bytes(cred_id=cred_id)
	# Extract cred_id from the acd bytes (offset 16, 2-byte len prefix)
	stored_cred_id = cred_id if cred_id is not None else acd_bytes[18 : 18 + 16]

	conn, c = open_database(env, with_connection=True)
	user_id = get_user_id(email, c)
	c.execute(
		"INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, aaguid, name) VALUES (?, ?, ?, ?, ?, ?)",
		(user_id, stored_cred_id, acd_bytes, 0, "00000000-0000-0000-0000-000000000000", name),
	)
	conn.commit()
	conn.close()
	return stored_cred_id, acd_bytes


def _make_fake_auth_data_result(acd_bytes: bytes):
	"""Return a MagicMock shaped like AuthenticatorData from register_complete."""
	from fido2.webauthn import AttestedCredentialData

	real_cred = AttestedCredentialData(acd_bytes)

	auth_data = MagicMock()
	auth_data.credential_data = real_cred
	return auth_data, real_cred


# ---------------------------------------------------------------------------
# get_webauthn_credentials
# ---------------------------------------------------------------------------


class TestGetWebauthnCredentials:
	def test_returns_empty_list_when_no_credentials(self, test_db):
		_add_user("nocreds@example.com", test_db)
		from auth.mfa import get_webauthn_credentials

		result = get_webauthn_credentials("nocreds@example.com", test_db)
		assert result == []

	def test_returns_attested_credential_data_objects(self, test_db):
		from fido2.webauthn import AttestedCredentialData

		_add_user("hascreds@example.com", test_db)
		_insert_credential(test_db, "hascreds@example.com")
		from auth.mfa import get_webauthn_credentials

		result = get_webauthn_credentials("hascreds@example.com", test_db)
		assert len(result) == 1
		assert isinstance(result[0], AttestedCredentialData)

	def test_returns_one_entry_per_stored_credential(self, test_db):
		_add_user("twocreds@example.com", test_db)
		_insert_credential(test_db, "twocreds@example.com", name="Key A")
		_insert_credential(test_db, "twocreds@example.com", name="Key B")
		from auth.mfa import get_webauthn_credentials

		result = get_webauthn_credentials("twocreds@example.com", test_db)
		assert len(result) == 2

	def test_raises_for_nonexistent_user(self, test_db):
		from auth.mfa import get_webauthn_credentials

		with pytest.raises(ValueError, match="User does not exist"):
			get_webauthn_credentials("ghost@example.com", test_db)


# ---------------------------------------------------------------------------
# get_public_webauthn_credentials
# ---------------------------------------------------------------------------


class TestGetPublicWebauthnCredentials:
	def test_returns_empty_list_when_no_credentials(self, test_db):
		_add_user("pubnone@example.com", test_db)
		from auth.mfa import get_public_webauthn_credentials

		result = get_public_webauthn_credentials("pubnone@example.com", test_db)
		assert result == []

	def test_returns_id_name_last_used_fields(self, test_db):
		_add_user("pubfields@example.com", test_db)
		_insert_credential(test_db, "pubfields@example.com", name="Passkey A")
		from auth.mfa import get_public_webauthn_credentials

		result = get_public_webauthn_credentials("pubfields@example.com", test_db)
		assert len(result) == 1
		row = result[0]
		assert set(row.keys()) == {"id", "name", "last_used"}

	def test_does_not_return_raw_public_key_bytes(self, test_db):
		_add_user("pubnokey@example.com", test_db)
		_insert_credential(test_db, "pubnokey@example.com", name="Safe Key")
		from auth.mfa import get_public_webauthn_credentials

		result = get_public_webauthn_credentials("pubnokey@example.com", test_db)
		row = result[0]
		assert "public_key" not in row
		assert "credential_id" not in row

	def test_name_matches_stored_name(self, test_db):
		_add_user("pubname@example.com", test_db)
		_insert_credential(test_db, "pubname@example.com", name="My Yubikey")
		from auth.mfa import get_public_webauthn_credentials

		result = get_public_webauthn_credentials("pubname@example.com", test_db)
		assert result[0]["name"] == "My Yubikey"

	def test_last_used_is_none_for_fresh_credential(self, test_db):
		_add_user("pubnew@example.com", test_db)
		_insert_credential(test_db, "pubnew@example.com")
		from auth.mfa import get_public_webauthn_credentials

		result = get_public_webauthn_credentials("pubnew@example.com", test_db)
		assert result[0]["last_used"] is None


# ---------------------------------------------------------------------------
# webauthn_register_complete -> get_webauthn_credentials round-trip
# ---------------------------------------------------------------------------


class TestWebauthnRegisterComplete:
	def test_credential_retrievable_after_register_complete(self, test_db):
		"""After a mocked register_complete, get_webauthn_credentials returns the new row."""
		from fido2.webauthn import AttestedCredentialData

		_add_user("regcomplete@example.com", test_db)

		acd_bytes = _build_acd_bytes()
		_, real_cred = _make_fake_auth_data_result(acd_bytes)

		auth_data_mock = MagicMock()
		auth_data_mock.credential_data = real_cred

		mock_server = MagicMock()
		mock_server.register_complete.return_value = auth_data_mock

		with patch("auth.mfa._get_fido2_server", return_value=mock_server), patch("fido2.webauthn.RegistrationResponse.from_dict", return_value=MagicMock()):
			from auth.mfa import webauthn_register_complete

			webauthn_register_complete("regcomplete@example.com", {"challenge": b"x"}, {}, "New Key", test_db)

		from auth.mfa import get_webauthn_credentials

		creds = get_webauthn_credentials("regcomplete@example.com", test_db)
		assert len(creds) == 1
		assert isinstance(creds[0], AttestedCredentialData)

	def test_public_credential_list_reflects_registered_key(self, test_db):
		_add_user("regpub@example.com", test_db)

		acd_bytes = _build_acd_bytes()
		_, real_cred = _make_fake_auth_data_result(acd_bytes)

		auth_data_mock = MagicMock()
		auth_data_mock.credential_data = real_cred

		mock_server = MagicMock()
		mock_server.register_complete.return_value = auth_data_mock

		with patch("auth.mfa._get_fido2_server", return_value=mock_server), patch("fido2.webauthn.RegistrationResponse.from_dict", return_value=MagicMock()):
			from auth.mfa import webauthn_register_complete

			webauthn_register_complete("regpub@example.com", {}, {}, "Public Key", test_db)

		from auth.mfa import get_public_webauthn_credentials

		pub = get_public_webauthn_credentials("regpub@example.com", test_db)
		assert len(pub) == 1
		assert pub[0]["name"] == "Public Key"

	def test_duplicate_credential_id_raises_integrity_error(self, test_db):
		"""Inserting a credential with an already-stored credential_id must fail."""
		import sqlite3

		_add_user("dupecred@example.com", test_db)

		cred_id = os.urandom(16)
		_insert_credential(test_db, "dupecred@example.com", name="Original", cred_id=cred_id)

		# Build acd bytes with the same cred_id
		acd_bytes = _build_acd_bytes(cred_id=cred_id)
		_, real_cred = _make_fake_auth_data_result(acd_bytes)

		auth_data_mock = MagicMock()
		auth_data_mock.credential_data = real_cred

		mock_server = MagicMock()
		mock_server.register_complete.return_value = auth_data_mock

		with patch("auth.mfa._get_fido2_server", return_value=mock_server), patch("fido2.webauthn.RegistrationResponse.from_dict", return_value=MagicMock()):
			from auth.mfa import webauthn_register_complete

			with pytest.raises(sqlite3.IntegrityError):
				webauthn_register_complete("dupecred@example.com", {}, {}, "Duplicate", test_db)


# ---------------------------------------------------------------------------
# webauthn_authenticate_begin
# ---------------------------------------------------------------------------


class TestWebauthnAuthenticateBegin:
	def test_returns_fake_challenge_when_user_has_no_credentials(self, test_db):
		# Returns synthetic challenge to prevent account enumeration - must not raise.
		_add_user("authnone@example.com", test_db)
		from auth.mfa import webauthn_authenticate_begin

		options, state = webauthn_authenticate_begin("authnone@example.com", test_db)
		assert isinstance(options, dict)
		assert options.get("allowCredentials") == []

	def test_returns_options_dict_and_state_when_credentials_exist(self, test_db):
		_add_user("authbegin@example.com", test_db)
		_insert_credential(test_db, "authbegin@example.com")

		fake_options = {"publicKey": {"challenge": "abc"}}
		fake_state = {"challenge": b"abc"}

		mock_server = MagicMock()
		mock_server.authenticate_begin.return_value = (fake_options, fake_state)

		with patch("auth.mfa._get_fido2_server", return_value=mock_server):
			from auth.mfa import webauthn_authenticate_begin

			options, state = webauthn_authenticate_begin("authbegin@example.com", test_db)

		assert isinstance(options, dict)
		assert state is not None

	def test_passes_stored_credentials_to_authenticate_begin(self, test_db):
		_add_user("authpass@example.com", test_db)
		_insert_credential(test_db, "authpass@example.com")

		mock_server = MagicMock()
		mock_server.authenticate_begin.return_value = ({"publicKey": {}}, {})

		with patch("auth.mfa._get_fido2_server", return_value=mock_server):
			from auth.mfa import webauthn_authenticate_begin

			webauthn_authenticate_begin("authpass@example.com", test_db)

		call_args = mock_server.authenticate_begin.call_args
		# First positional arg is the credentials list
		passed_creds = call_args.args[0] if call_args.args else call_args.kwargs.get("credentials")
		assert passed_creds is not None
		assert len(passed_creds) == 1


# ---------------------------------------------------------------------------
# webauthn_authenticate_complete (DB update side effects)
# ---------------------------------------------------------------------------


class TestWebauthnAuthenticateComplete:
	def test_updates_last_used_and_sign_count(self, test_db):
		_add_user("authcomp@example.com", test_db)
		cred_id = os.urandom(16)
		_insert_credential(test_db, "authcomp@example.com", cred_id=cred_id)

		fake_result = MagicMock()
		fake_result.credential_id = cred_id

		fake_response = MagicMock()
		fake_response.response.authenticator_data.counter = 99

		mock_server = MagicMock()
		mock_server.authenticate_complete.return_value = fake_result

		with patch("auth.mfa._get_fido2_server", return_value=mock_server), patch("fido2.webauthn.AuthenticationResponse.from_dict", return_value=fake_response):
			from auth.mfa import webauthn_authenticate_complete

			webauthn_authenticate_complete("authcomp@example.com", {}, {}, test_db)

		from mail.mailconfig import open_database

		conn, c = open_database(test_db, with_connection=True)
		c.execute(
			"SELECT sign_count, last_used FROM webauthn_credentials WHERE credential_id=?",
			(cred_id,),
		)
		row = c.fetchone()
		conn.close()

		assert row is not None
		assert row[0] == 99
		assert row[1] is not None  # last_used was set

	def test_returns_none(self, test_db):
		_add_user("authnone2@example.com", test_db)
		cred_id = os.urandom(16)
		_insert_credential(test_db, "authnone2@example.com", cred_id=cred_id)

		fake_result = MagicMock()
		fake_result.credential_id = cred_id
		fake_response = MagicMock()
		fake_response.response.authenticator_data.counter = 1

		mock_server = MagicMock()
		mock_server.authenticate_complete.return_value = fake_result

		with patch("auth.mfa._get_fido2_server", return_value=mock_server), patch("fido2.webauthn.AuthenticationResponse.from_dict", return_value=fake_response):
			from auth.mfa import webauthn_authenticate_complete

			result = webauthn_authenticate_complete("authnone2@example.com", {}, {}, test_db)

		assert result is None


# ---------------------------------------------------------------------------
# disable_mfa removes webauthn_credentials rows
# ---------------------------------------------------------------------------


class TestDisableMfaWebauthn:
	def test_disable_mfa_none_removes_webauthn_credentials(self, test_db):
		_add_user("dismfa@example.com", test_db)
		_insert_credential(test_db, "dismfa@example.com")

		from auth.mfa import disable_mfa, get_webauthn_credentials

		disable_mfa("dismfa@example.com", None, test_db)
		creds = get_webauthn_credentials("dismfa@example.com", test_db)
		assert creds == []

	def test_disable_mfa_specific_id_removes_webauthn_credential(self, test_db):
		_add_user("disone@example.com", test_db)
		_insert_credential(test_db, "disone@example.com", name="To Remove")
		_insert_credential(test_db, "disone@example.com", name="To Keep")

		from auth.mfa import get_public_webauthn_credentials, disable_mfa

		pub = get_public_webauthn_credentials("disone@example.com", test_db)
		assert len(pub) == 2
		remove_id = next(p["id"] for p in pub if p["name"] == "To Remove")

		disable_mfa("disone@example.com", remove_id, test_db)
		pub_after = get_public_webauthn_credentials("disone@example.com", test_db)
		assert len(pub_after) == 1
		assert pub_after[0]["name"] == "To Keep"
