import base64
import hmac
import json
import secrets
from datetime import timedelta

from expiringdict import ExpiringDict

from mail.mailconfig import get_mail_password, get_mail_user_privileges
from mail.mailconfig.users import verify_password, hash_password
from mail.mailconfig.database import open_database
from auth.mfa import get_hash_mfa_state, validate_auth_mfa

DEFAULT_KEY_PATH = '/var/lib/naust/api.key'
DEFAULT_AUTH_REALM = 'Naust Management Server'


def parse_http_authorization_basic(header: str) -> "tuple[str | None, str | None]":
	"""Parse an HTTP Basic Authorization header into (username, password).
	Returns (None, None) if the header is absent, malformed, or not Basic scheme."""
	if not header or " " not in header:
		return None, None
	scheme, credentials = header.split(maxsplit=1)
	if scheme != 'Basic':
		return None, None
	try:
		credentials = base64.b64decode(credentials.encode('ascii')).decode('ascii')
	except Exception:
		return None, None
	if ":" not in credentials:
		return None, None
	username, password = credentials.split(':', maxsplit=1)
	return username, password


# Placeholder hash used when an email address is not found, so that passlib
# still runs and response time is consistent regardless of whether the user exists.
# Generated lazily on first use so startup cost is paid only when needed.
_dummy_hash_cache: "str | None" = None


def _get_dummy_hash() -> str:
	global _dummy_hash_cache
	if _dummy_hash_cache is None:
		from passlib.hash import bcrypt

		_dummy_hash_cache = "{BLF-CRYPT}" + bcrypt.hash("naust-timing-dummy")
	return _dummy_hash_cache


class AuthService:
	def __init__(self):
		self.auth_realm = DEFAULT_AUTH_REALM
		self.key_path = DEFAULT_KEY_PATH
		self.max_session_duration = timedelta(hours=1)

		self.init_system_api_key()

		# Separate stores for login tokens (long-lived, admin sessions) and cookie
		# tokens (short-lived munin sessions). Keeping them apart prevents munin page
		# load churn from evicting active admin login sessions.
		duration = self.max_session_duration.total_seconds()
		self.login_sessions = ExpiringDict(max_len=1024, max_age_seconds=duration)
		self.cookie_sessions = ExpiringDict(max_len=1024, max_age_seconds=60 * 30)  # 30 min, mirrors daemon.py

		# In-process challenge store for WebAuthn registration and authentication flows.
		# The Flask daemon is assumed to run as a single process (no workers); if the
		# deployment model ever changes, this must be replaced with a shared store.
		self.webauthn_challenges = ExpiringDict(max_len=512, max_age_seconds=300)

		# In-process store for the encryption-at-rest setup ceremony. Holds the
		# pre-built (but uncommitted) key slots between /setup and /challenge so
		# the MAIL_KEY is never persisted until the user proves they saved a
		# recovery code. Same single-process assumption as webauthn_challenges.
		self.encryption_setups = ExpiringDict(max_len=256, max_age_seconds=600)

	def _session_store(self, session_type):
		if session_type == 'cookie':
			return self.cookie_sessions
		return self.login_sessions

	def init_system_api_key(self):
		"""Read the API key from disk. The key is used to authenticate local processes."""

		with open(self.key_path, encoding='utf-8') as file:
			self.key = file.read().strip()

	def authenticate(self, request, env, login_only=False, logout=False):
		"""Test if the HTTP Authorization header's username matches the system key, a session key,
		or if the username/password passed in the header matches a local user.
		Returns a tuple of the user's email address and list of user privileges (e.g.
		('my@email', []) or ('my@email', ['admin']); raises a ValueError on login failure.
		If the user used the system API key, the user's email is returned as None since
		this key is not associated with a user."""

		username, password = parse_http_authorization_basic(request.headers.get('Authorization', ''))
		if username in {None, ""}:
			msg = "Authorization header invalid."
			raise ValueError(msg)

		if username.strip() == "" and password.strip() == "":
			msg = "No email address, password, session key, or API key provided."
			raise ValueError(msg)

		# If user passed the system API key, grant administrative privs. This key
		# is not associated with a user.
		if hmac.compare_digest(username, self.key) and not login_only:
			return (None, ["admin"])

		# If the password corresponds with a session token for the user, grant access for that user.
		if self.get_session(username, password, "login", env) and not login_only:
			sessionid = password
			session = self.login_sessions[sessionid]
			if logout:
				# Clear the session and return immediately - no privilege lookup needed.
				del self.login_sessions[sessionid]
				return (username, [])
			# Re-up the session so that it does not expire.
			self.login_sessions[sessionid] = session

		# If no password was given, but a username was given, we're missing some information.
		elif password.strip() == "":
			msg = "Enter a password."
			raise ValueError(msg)

		else:
			# The user is trying to log in with a username and a password
			# (and possibly a MFA token). On failure, an exception is raised.
			self.check_user_auth(username, password, request, env)

		# Get privileges for authorization. This call should never fail because by this
		# point we know the email address is a valid user --- unless the user has been
		# deleted after the session was granted. On error the call will return a tuple
		# of an error message and an HTTP status code.
		privs = get_mail_user_privileges(username, env)
		if isinstance(privs, tuple):
			raise ValueError(privs[0])

		# Return the authorization information.
		return (username, privs)

	def check_user_auth(self, email, pw, request, env):
		# Validate a user's login email address and password. If MFA is enabled,
		# check the MFA token in the X-Auth-Token header.
		#
		# On login failure, raises a ValueError with a login error message. On
		# success, nothing is returned.

		# Authenticate.
		try:
			# Get the hashed password of the user. Raise a ValueError if the
			# email address does not correspond to a user. But wrap it in the
			# same exception as if a password fails so we don't easily reveal
			# if an email address is valid.
			pw_hash = get_mail_password(email, env)
			user_exists = True
		except ValueError:
			# Unknown user. Use a dummy hash so verify_password still runs and
			# response time is consistent - prevents email enumeration via timing.
			pw_hash = _get_dummy_hash()
			user_exists = False

		pw_ok = verify_password(pw_hash, pw)

		if not pw_ok or not user_exists:
			# Login failed.
			raise ValueError("Incorrect email address or password.")

		# Upgrade legacy SHA512-CRYPT hashes to BLF-CRYPT on successful login.
		if pw_hash.startswith("{SHA512-CRYPT}"):
			new_hash = hash_password(pw)
			conn, c = open_database(env, with_connection=True)
			c.execute("UPDATE users SET password=? WHERE email=?", (new_hash, email))
			conn.commit()
			conn.close()

		# If MFA is enabled, check that MFA passes.
		status, hints = validate_auth_mfa(email, request, env)
		if not status:
			# Login valid. Hints may have more info.
			raise ValueError(",".join(hints))

	def create_user_password_state_token(self, email, env):
		# Create a token that changes if the user's password or MFA options change
		# so that sessions become invalid if any of that information changes.
		msg = get_mail_password(email, env).encode("utf8")

		# Add to the message the current MFA state, which is a list of MFA information.
		# Turn it into a string stably.
		msg += b" " + json.dumps(get_hash_mfa_state(email, env), sort_keys=True).encode("utf8")

		# Make a HMAC using the system API key as a hash key.
		hash_key = self.key.encode('ascii')
		return hmac.new(hash_key, msg, digestmod="sha256").hexdigest()

	def create_session_key(self, username, env, session_type=None):
		# Create a new session.
		if not username:
			raise ValueError("Cannot create a session for an anonymous (API key) caller.")
		token = secrets.token_hex(32)
		self._session_store(session_type)[token] = {
			"email": username,
			"password_token": self.create_user_password_state_token(username, env),
			"type": session_type,
		}
		return token

	def get_session_by_key_only(self, session_key, env):
		"""Look up a login session by key alone - used for HttpOnly cookie auth
		where the email address is not available upfront.
		Re-inserts the session on a valid lookup so the idle timeout slides
		with activity rather than expiring from login time."""
		if not session_key or session_key not in self.login_sessions:
			return None
		session = self.login_sessions[session_key]
		email = session.get("email")
		if not email:
			return None
		# Re-validate via get_session to check password_token integrity.
		validated = self.get_session(email, session_key, "login", env)
		if validated:
			# Slide the expiry window on each authenticated request.
			self.login_sessions[session_key] = validated
		return validated

	def get_session(self, user_email, session_key, session_type, env):
		store = self._session_store(session_type)
		if session_key not in store:
			return None
		session = store[session_key]
		if session_type == "login" and not hmac.compare_digest(session["email"], user_email):
			return None
		if session["type"] != session_type:
			return None
		try:
			current_token = self.create_user_password_state_token(session["email"], env)
		except ValueError:
			# User no longer exists - invalidate the session.
			return None
		if not hmac.compare_digest(session["password_token"], current_token):
			return None
		return session
