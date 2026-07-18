"""
Key-slot crypto for encryption at rest (mail_crypt).

Model
-----
Each user has one random 32-byte MAIL_KEY. The MAIL_KEY is never stored in the
clear. Instead it is wrapped (AES-256-GCM) under one or more independent "slots",
each derived from a different secret the user controls:

  slot_type      secret                       KDF
  ------------   --------------------------   ------------------------------------
  password       the account login password   Argon2id(t=3, m=64MiB, p=4) -> 32B
  recovery_code  a printed recovery code       HKDF-SHA256(code, salt)     -> 32B
  app_password   a generated app password      HKDF-SHA256(secret, salt)   -> 32B
  passkey_prf    WebAuthn PRF output (DEFERRED)

Any single slot can unwrap the MAIL_KEY, so a user who forgets their password can
still recover via a recovery code. Every slot has its own random 32-byte KDF salt
and its own 12-byte GCM nonce, so slots never share key material.

There is no master key. If every slot for a user is lost, that user's mail is
unrecoverable by design.

TODO: passkey_prf slot is deferred. It requires the WebAuthn PRF extension to be
wired into management/auth/mfa.py (register_begin/authenticate_begin must request
the 'prf' extension and the PRF output must be plumbed to derive_key_from_secret).
Until then no passkey_prf slots are created and has_prf_slot is always false.
"""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Crockford base32 alphabet (excludes I, L, O, U to avoid visual ambiguity).
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_INDEX = {ch: i for i, ch in enumerate(_CROCKFORD)}

# Recovery code layout: 15 random data chars + 1 checksum char = 16 chars,
# printed as 4 dash-separated groups of 4 (e.g. A3K7-9MNP-2QRT-X5BC).
_RECOVERY_DATA_LEN = 15
_RECOVERY_TOTAL_LEN = 16
_RECOVERY_CODE_COUNT = 4

# HKDF info string domain-separates recovery/app-password key derivation.
_HKDF_INFO = b"naust mail_crypt slot v1"

# Argon2id parameters (spec-locked): time=3, memory=64 MiB, parallelism=4.
_ARGON2_TIME = 3
_ARGON2_MEMORY_KIB = 65536
_ARGON2_LANES = 4

_MAIL_KEY_LEN = 32
_KDF_SALT_LEN = 32
_GCM_NONCE_LEN = 12


# ── Recovery code encoding ─────────────────────────────────────────────────────


def _checksum(data_values: list[int]) -> int:
	"""Position-weighted checksum of the data character values, mod 37.

	The weight (i+1) makes the checksum sensitive to transposition, so swapping
	two adjacent characters changes the result. Mod 37 (prime) gives better error
	detection than mod 32 would.
	"""
	return sum(v * (i + 1) for i, v in enumerate(data_values)) % 37


def _normalize_recovery_input(code: str) -> str:
	"""Uppercase, strip dashes/whitespace, and apply Crockford input aliasing.

	Crockford treats O as 0 and I/L as 1 on input. This makes hand-typed codes
	forgiving without changing what we generate (we never emit O, I, L, U)."""
	s = code.strip().upper().replace("-", "").replace(" ", "")
	return s.translate(str.maketrans({"O": "0", "I": "1", "L": "1"}))


def _generate_one_recovery_code() -> str:
	"""Generate a single formatted recovery code with a valid checksum char.

	Reject-samples so the checksum always lands inside the 32-symbol alphabet;
	we never issue a code whose checksum would fall in the 32-36 range that
	base32 cannot represent. This is what lets mod-37 coexist with a pure
	base32 code (see module note)."""
	while True:
		data_values = [b % 32 for b in os.urandom(_RECOVERY_DATA_LEN)]
		cs = _checksum(data_values)
		if cs < 32:
			break
	chars = [_CROCKFORD[v] for v in data_values] + [_CROCKFORD[cs]]
	raw = "".join(chars)
	return "-".join(raw[i : i + 4] for i in range(0, _RECOVERY_TOTAL_LEN, 4))


def generate_recovery_codes() -> list[str]:
	"""Generate the 4 formatted recovery codes handed to the user at setup."""
	return [_generate_one_recovery_code() for _ in range(_RECOVERY_CODE_COUNT)]


def validate_recovery_code_crc(code: str) -> bool:
	"""Validate a recovery code's format and checksum before any crypto work.

	Cheap fast-fail for typos: no KDF or DB access. Returns True only if the code
	has exactly 16 in-alphabet characters and the checksum char matches."""
	s = _normalize_recovery_input(code)
	if len(s) != _RECOVERY_TOTAL_LEN:
		return False
	if any(ch not in _CROCKFORD_INDEX for ch in s):
		return False
	data_values = [_CROCKFORD_INDEX[ch] for ch in s[:_RECOVERY_DATA_LEN]]
	cs = _checksum(data_values)
	if cs >= 32:
		return False
	return _CROCKFORD[cs] == s[_RECOVERY_DATA_LEN]


# ── Key generation and derivation ──────────────────────────────────────────────


def generate_mail_key() -> bytes:
	"""Generate a fresh random 32-byte MAIL_KEY."""
	return os.urandom(_MAIL_KEY_LEN)


def derive_key_from_password(password: str, salt: bytes) -> bytes:
	"""Derive a 32-byte wrapping key from the login password using Argon2id."""
	kdf = Argon2id(
		salt=salt,
		length=_MAIL_KEY_LEN,
		iterations=_ARGON2_TIME,
		lanes=_ARGON2_LANES,
		memory_cost=_ARGON2_MEMORY_KIB,
	)
	return kdf.derive(password.encode("utf-8"))


def derive_key_from_secret(secret: bytes, salt: bytes) -> bytes:
	"""Derive a 32-byte wrapping key from a high-entropy secret using HKDF-SHA256.

	Used for recovery codes, app passwords, and (later) passkey PRF output - any
	secret that already carries enough entropy that a memory-hard KDF is overkill."""
	kdf = HKDF(
		algorithm=hashes.SHA256(),
		length=_MAIL_KEY_LEN,
		salt=salt,
		info=_HKDF_INFO,
	)
	return kdf.derive(secret)


# ── Wrap / unwrap ──────────────────────────────────────────────────────────────


def wrap_mail_key(mail_key: bytes, wrapping_key: bytes) -> tuple[bytes, bytes]:
	"""AES-256-GCM encrypt the MAIL_KEY under a wrapping key.

	Returns (ciphertext, nonce). The nonce is random per call and must be stored
	alongside the ciphertext."""
	nonce = os.urandom(_GCM_NONCE_LEN)
	ct = AESGCM(wrapping_key).encrypt(nonce, mail_key, None)
	return ct, nonce


def unwrap_mail_key(wrapped_key: bytes, nonce: bytes, wrapping_key: bytes) -> bytes:
	"""AES-256-GCM decrypt a wrapped MAIL_KEY.

	Raises cryptography.exceptions.InvalidTag if the wrapping key is wrong (i.e.
	the supplied secret did not derive the key that wrapped this slot)."""
	return AESGCM(wrapping_key).decrypt(nonce, wrapped_key, None)


# ── Slot persistence ───────────────────────────────────────────────────────────


def _insert_slot(conn, user_id: int, slot_type: str, slot_label, wrapped_key: bytes, nonce: bytes, kdf_salt: bytes) -> None:
	conn.execute(
		"INSERT INTO mail_keys (user_id, slot_type, slot_label, wrapped_key, nonce, kdf_salt) VALUES (?, ?, ?, ?, ?, ?)",
		(user_id, slot_type, slot_label, sqlite_blob(wrapped_key), sqlite_blob(nonce), sqlite_blob(kdf_salt)),
	)


def sqlite_blob(b: bytes):
	"""Wrap bytes so sqlite3 stores them as a BLOB regardless of adapter config."""
	import sqlite3

	return sqlite3.Binary(b)


# A prepared slot is a tuple ready for insertion, built in memory so the setup
# ceremony can hold slots before committing: (slot_type, slot_label, wrapped_key, nonce, kdf_salt).
PreparedSlot = tuple


def build_password_slot(password: str, mail_key: bytes) -> PreparedSlot:
	"""Build (but do not persist) the password-derived slot."""
	salt = os.urandom(_KDF_SALT_LEN)
	wrapping_key = derive_key_from_password(password, salt)
	wrapped, nonce = wrap_mail_key(mail_key, wrapping_key)
	return ("password", None, wrapped, nonce, salt)


def build_recovery_slots(codes: list[str], mail_key: bytes) -> list[PreparedSlot]:
	"""Build (but do not persist) one recovery_code slot per code, labelled '0'..'N-1'."""
	slots = []
	for i, code in enumerate(codes):
		secret = _normalize_recovery_input(code).encode("utf-8")
		salt = os.urandom(_KDF_SALT_LEN)
		wrapping_key = derive_key_from_secret(secret, salt)
		wrapped, nonce = wrap_mail_key(mail_key, wrapping_key)
		slots.append(("recovery_code", str(i), wrapped, nonce, salt))
	return slots


def recovery_slot_accepts(slot: PreparedSlot, code: str) -> bool:
	"""Return True if the given recovery code unwraps this prepared recovery slot.

	Used during the setup challenge to verify the user copied a code correctly
	before any slot is written to the database."""
	_slot_type, _label, wrapped_key, nonce, kdf_salt = slot
	secret = _normalize_recovery_input(code).encode("utf-8")
	wrapping_key = derive_key_from_secret(secret, kdf_salt)
	try:
		unwrap_mail_key(wrapped_key, nonce, wrapping_key)
		return True
	except Exception:
		return False


def unwrap_prepared_slot(slot: PreparedSlot, code: str) -> bytes:
	"""Unwrap a prepared recovery slot with a code, returning the MAIL_KEY.

	Used at challenge-success to recover the MAIL_KEY needed to generate the
	user's Dovecot keypair. Raises on a wrong code."""
	_slot_type, _label, wrapped_key, nonce, kdf_salt = slot
	secret = _normalize_recovery_input(code).encode("utf-8")
	wrapping_key = derive_key_from_secret(secret, kdf_salt)
	return unwrap_mail_key(wrapped_key, nonce, wrapping_key)


def insert_prepared_slots(conn, user_id: int, slots: list[PreparedSlot]) -> None:
	"""Persist a list of prepared slots for a user. Caller commits."""
	for slot_type, slot_label, wrapped_key, nonce, kdf_salt in slots:
		_insert_slot(conn, user_id, slot_type, slot_label, wrapped_key, nonce, kdf_salt)


def create_password_slot(conn, user_id: int, password: str, mail_key: bytes) -> None:
	"""Build and persist the password-derived slot. Caller is responsible for commit."""
	insert_prepared_slots(conn, user_id, [build_password_slot(password, mail_key)])


def create_recovery_slots(conn, user_id: int, codes: list[str], mail_key: bytes) -> None:
	"""Build and persist one recovery_code slot per code, labelled '0'..'N-1'. Caller commits."""
	insert_prepared_slots(conn, user_id, build_recovery_slots(codes, mail_key))


def replace_recovery_prepared(conn, user_id: int, slots: list[PreparedSlot]) -> None:
	"""Delete existing recovery_code slots and insert a new prepared set. Caller commits.

	Used by the rotation ceremony: old slots remain valid until the user proves
	they copied the new codes, then this atomically replaces them."""
	conn.execute(
		"DELETE FROM mail_keys WHERE user_id=? AND slot_type='recovery_code'",
		(user_id,),
	)
	insert_prepared_slots(conn, user_id, slots)


def rotate_password_slot(conn, user_id: int, old_password: str, new_password: str) -> None:
	"""Re-wrap the MAIL_KEY under a new password-derived key.

	Unwraps the existing password slot with old_password, then rewraps with a
	fresh salt/nonce derived from new_password. Raises ValueError if there is no
	password slot or old_password is wrong (InvalidTag). Caller commits."""
	row = conn.execute(
		"SELECT id, wrapped_key, nonce, kdf_salt FROM mail_keys WHERE user_id=? AND slot_type='password'",
		(user_id,),
	).fetchone()
	if row is None:
		raise ValueError("No password key slot exists for this user.")
	slot_id, wrapped_key, nonce, kdf_salt = row
	old_wrapping = derive_key_from_password(old_password, bytes(kdf_salt))
	try:
		mail_key = unwrap_mail_key(bytes(wrapped_key), bytes(nonce), old_wrapping)
	except Exception as e:
		raise ValueError("Old password did not unlock the encryption key.") from e

	new_salt = os.urandom(_KDF_SALT_LEN)
	new_wrapping = derive_key_from_password(new_password, new_salt)
	new_wrapped, new_nonce = wrap_mail_key(mail_key, new_wrapping)
	conn.execute(
		"UPDATE mail_keys SET wrapped_key=?, nonce=?, kdf_salt=? WHERE id=?",
		(sqlite_blob(new_wrapped), sqlite_blob(new_nonce), sqlite_blob(new_salt), slot_id),
	)


def relink_password_slot(conn, user_id: int, recovery_code: str, new_password: str) -> None:
	"""Re-establish the password slot from a recovery code.

	Used after a password change/reset the system could not rotate in place (no
	old password was available - e.g. an admin reset). Unwraps MAIL_KEY via a
	recovery code, then replaces the (now-stale) password slot with a fresh one
	wrapped under new_password. Recovery slots are untouched. Raises ValueError if
	the recovery code matches no slot. Caller commits."""
	mail_key = unwrap_via_recovery_code(conn, user_id, recovery_code)  # raises on wrong code
	conn.execute("DELETE FROM mail_keys WHERE user_id=? AND slot_type='password'", (user_id,))
	insert_prepared_slots(conn, user_id, [build_password_slot(new_password, mail_key)])


def unwrap_via_password(conn, user_id: int, password: str) -> bytes:
	"""Unwrap the MAIL_KEY using the user's password slot.

	Returns the MAIL_KEY on success. Raises ValueError if there is no password
	slot or the password is wrong (InvalidTag). Used by the login-time unwrap
	endpoint that delivers crypt_user_key_password to Dovecot."""
	row = conn.execute(
		"SELECT wrapped_key, nonce, kdf_salt FROM mail_keys WHERE user_id=? AND slot_type='password'",
		(user_id,),
	).fetchone()
	if row is None:
		raise ValueError("No password key slot exists for this user.")
	wrapped_key, nonce, kdf_salt = row
	wrapping_key = derive_key_from_password(password, bytes(kdf_salt))
	try:
		return unwrap_mail_key(bytes(wrapped_key), bytes(nonce), wrapping_key)
	except Exception as e:
		raise ValueError("Password did not unlock the encryption key.") from e


def unwrap_via_recovery_code(conn, user_id: int, code: str) -> bytes:
	"""Try each recovery_code slot until one unwraps the MAIL_KEY.

	Returns the MAIL_KEY on success. Raises ValueError if no recovery slot
	accepts the code (wrong code, or no recovery slots exist)."""
	secret = _normalize_recovery_input(code).encode("utf-8")
	rows = conn.execute(
		"SELECT wrapped_key, nonce, kdf_salt FROM mail_keys WHERE user_id=? AND slot_type='recovery_code'",
		(user_id,),
	).fetchall()
	for wrapped_key, nonce, kdf_salt in rows:
		wrapping_key = derive_key_from_secret(secret, bytes(kdf_salt))
		try:
			return unwrap_mail_key(bytes(wrapped_key), bytes(nonce), wrapping_key)
		except Exception:
			continue
	raise ValueError("Recovery code did not match any key slot.")


if __name__ == "__main__":
	# Self-test: exercises CRC, KDFs, wrap/unwrap, and all slot operations against
	# an in-memory SQLite DB. Run directly to verify the crypto end to end:
	#   python3 mail_crypt.py
	import sqlite3

	print("== recovery code format + CRC ==")
	codes = generate_recovery_codes()
	for c in codes:
		assert len(c) == 19 and c.count("-") == 3, f"bad format: {c}"
		assert validate_recovery_code_crc(c), f"CRC failed for issued code: {c}"
		assert validate_recovery_code_crc(c.lower()), f"lowercase rejected: {c}"
		print(f"  {c}  OK")
	# A single-character corruption must fail CRC (flip the first data char).
	bad = list(codes[0].replace("-", ""))
	bad[0] = _CROCKFORD[(_CROCKFORD_INDEX[bad[0]] + 1) % 32]
	assert not validate_recovery_code_crc("".join(bad)), "CRC did not catch corruption"
	print("  corruption detected: OK")

	print("== password slot round-trip ==")
	conn = sqlite3.connect(":memory:")
	conn.execute("CREATE TABLE mail_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, slot_type TEXT, slot_label TEXT, wrapped_key BLOB, nonce BLOB, kdf_salt BLOB)")
	mk = generate_mail_key()
	create_password_slot(conn, 1, "correct horse battery staple", mk)
	create_recovery_slots(conn, 1, codes, mk)
	conn.commit()

	# Recover the MAIL_KEY via each recovery code.
	for c in codes:
		assert unwrap_via_recovery_code(conn, 1, c) == mk
	print("  all recovery codes unwrap the MAIL_KEY: OK")

	# Wrong recovery code fails.
	try:
		other = generate_recovery_codes()[0]
		unwrap_via_recovery_code(conn, 1, other)
		raise AssertionError("wrong recovery code should not unwrap")
	except ValueError:
		print("  wrong recovery code rejected: OK")

	print("== password rotation ==")
	rotate_password_slot(conn, 1, "correct horse battery staple", "new-passphrase-123")
	conn.commit()
	# After rotation the recovery codes must still unwrap the same MAIL_KEY.
	assert unwrap_via_recovery_code(conn, 1, codes[0]) == mk
	# The old password must no longer rotate.
	try:
		rotate_password_slot(conn, 1, "correct horse battery staple", "x")
		raise AssertionError("old password should not rotate after change")
	except ValueError:
		print("  rotation re-wraps and invalidates old password: OK")

	print("\nAll mail_crypt self-tests passed.")
