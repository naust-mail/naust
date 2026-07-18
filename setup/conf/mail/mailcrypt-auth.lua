-- Dovecot Lua passdb for encryption at rest (mail_crypt).
--
-- Runs as the SECOND passdb after the passwd-file passdb has already verified
-- the password (configured with result_success = continue). This passdb does
-- not verify anything itself (returns nopassword=y); its only job is to fetch
-- the user's unwrapped mail key from managerd and hand it to mail_crypt as
-- crypt_user_key_password for the session.
--
-- The unwrap endpoint is on 127.0.0.1 and gated by a dedicated shared secret
-- (sent here via the X-Api-Key header) that authorizes nothing else. A wrong
-- password makes the endpoint return mail_key=null, so no key is delivered and
-- the user simply cannot decrypt (login still succeeds via the first passdb).
--
-- Everything is wrapped so a transport failure never blocks login: on any error
-- we return OK with no key and a mailcrypt_dbg field for troubleshooting.

local UNWRAP_URL = "http://127.0.0.1:10223/internal/mailcrypt/unwrap"
local KEY_FILE = "/var/lib/naust/mailcrypt-unwrap.key"

local http_client = nil

local function url_encode(s)
  return (tostring(s):gsub("[^%w%-_%.~]", function(c)
    return string.format("%%%02X", string.byte(c))
  end))
end

local function read_api_key()
  local f = io.open(KEY_FILE, "r")
  if not f then return nil end
  local k = f:read("*l")
  f:close()
  return k
end

-- Returns (mail_key_hex_or_nil, reason_string).
local function fetch_mail_key(user, password)
  if not user or not password then return nil, "missing-req-fields" end
  local key = read_api_key()
  if not key then return nil, "no-api-key" end
  if not http_client then
    -- Empty config uses Dovecot's http_client defaults. A correctly-named
    -- timeout setting can be added once confirmed for this build.
    http_client = dovecot.http.client({})
  end
  local r = http_client:request({ url = UNWRAP_URL, method = "POST" })
  r:add_header("Content-Type", "application/x-www-form-urlencoded")
  r:add_header("X-Api-Key", key)
  r:set_payload("user=" .. url_encode(user) .. "&password=" .. url_encode(password))
  local resp = r:submit()
  local status = resp:status()
  if status ~= 200 then return nil, "http-" .. tostring(status) end
  local body = resp:payload()
  local mk = body:match('"mail_key"%s*:%s*"(%x+)"')
  if mk then return mk, "ok" end
  return nil, "no-key"
end

function auth_passdb_lookup(req)
  local ok, mk, why = pcall(fetch_mail_key, req.user, req.password)
  local dbg = tostring(ok) .. "/" .. tostring(why or mk)
    .. "|u=" .. tostring(req.user)
    .. "|pw=" .. tostring(req.password ~= nil)
  if ok and mk then
    return dovecot.auth.PASSDB_RESULT_OK, {
      nopassword = "y",
      crypt_user_key_password = mk,
      mailcrypt_dbg = dbg,
    }
  end
  return dovecot.auth.PASSDB_RESULT_OK, { nopassword = "y", mailcrypt_dbg = dbg }
end
