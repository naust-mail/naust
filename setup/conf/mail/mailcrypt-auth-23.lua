-- Dovecot 2.3 Lua passdb for encryption at rest (mail_crypt).
--
-- 2.3 dialect of mailcrypt-auth.lua. The mail-key fetch (managerd's local
-- unwrap endpoint) is identical to the 2.4 script - see that file for the
-- full rationale. What differs is field delivery: 2.3 only expands
-- %{userdb:...} inside plugin{} settings (there is no %{passdb:...} at all,
-- confirmed on a real 2.3 box), and a successful prefetch userdb lookup
-- REPLACES the userdb answer rather than merging with the next userdb block.
-- So this script must also hand back the account's own uid/gid/home as
-- userdb_ fields, not just the key, or login itself breaks. Those three
-- fields are not secret (the same passwd-file already carries them in the
-- clear for Dovecot's own userdb lookups elsewhere), so this script reads
-- them straight off disk with a plain Lua file read - no shell-out, no
-- daemon involvement, no new privilege beyond what Dovecot's own auth
-- process already has on that file.
--
-- Runs as the SECOND passdb after the passwd-file passdb has already
-- verified the password (configured with pass = yes). Returns nopassword=y;
-- it never verifies anything itself.

local UNWRAP_URL = "http://127.0.0.1:10223/internal/mailcrypt/unwrap"
local KEY_FILE = "/var/lib/naust/mailcrypt-unwrap.key"
local USERS_FILE = "${STORAGE_ROOT}/mail/materialized/dovecot-users"

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

-- Plain-text field lookup, no shell involved: scans the same passwd-file
-- Dovecot's own passdb/userdb already reads, splits each line on ':', and
-- returns the uid/gid/home for the matching user. Returns nil if not found
-- (line-for-line the same format RenderDovecotUsers emits: user:hash:uid:
-- gid:gecos:home:shell:extra).
local function lookup_account_fields(user)
  local f = io.open(USERS_FILE, "r")
  if not f then return nil end
  for line in f:lines() do
    local fields = {}
    for field in line:gmatch("([^:]*):?") do
      fields[#fields + 1] = field
    end
    if fields[1] == user then
      f:close()
      return { uid = fields[3], gid = fields[4], home = fields[6] }
    end
  end
  f:close()
  return nil
end

function auth_passdb_lookup(req)
  local acct = lookup_account_fields(req.user)
  if not acct then
    return dovecot.auth.PASSDB_RESULT_USER_UNKNOWN, {}
  end

  local ok, mk, why = pcall(fetch_mail_key, req.user, req.password)
  local dbg = tostring(ok) .. "/" .. tostring(why or mk)
    .. "|u=" .. tostring(req.user)
    .. "|pw=" .. tostring(req.password ~= nil)

  local extra = {
    nopassword = "y",
    userdb_uid = acct.uid,
    userdb_gid = acct.gid,
    userdb_home = acct.home,
    mailcrypt_dbg = dbg,
  }
  if ok and mk then
    extra.userdb_mail_crypt_private_password = mk
  end
  return dovecot.auth.PASSDB_RESULT_OK, extra
end
