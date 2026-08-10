#!/usr/bin/lua

local jsonc = require "luci.jsonc"
local ok_nixio, nixio = pcall(require, "nixio")
local happ_decrypt = require "tproxy_manager.happ_decrypt"
local proxy_links = require "tproxy_manager.proxy_links"
-- The shared rollback store. Soft-required: this script also runs from cron and
-- from the init scripts, and a broken luci tree must not stop it from loading.
-- The two-file transaction below refuses to run without it rather than doing the
-- work unsafely.
local ok_utils, utils = pcall(require, "luci.model.cbi.tproxy_manager.utils")

local PKG = "tproxy-manager"
local DEFAULT_DB = "/etc/tproxy-manager/watchdog-subscriptions.json"
local DEFAULT_LINKS = "/etc/tproxy-manager/watchdog.links"
-- Locks live inside a root-only 0700 directory rather than directly in
-- world-writable /tmp (or /var/lock, which is 1777 too): otherwise any
-- local user could pre-create the lock path and permanently deny the
-- service its lock.
local LOCK_ROOT = "/var/lock/tproxy-manager"
local LOCK_DIR = LOCK_ROOT .. "/watchdog.lock"
-- The capture bookkeeping lives inside the root-only 0700 lock root, not
-- directly in world-writable /tmp. At fixed /tmp paths any local user could
-- pre-create them as symlinks and have this root process write through them,
-- or plant a PID for capture_stop() to kill. LOCK_ROOT is created and validated
-- by secure_lock_root() before either path is used.
local CAPTURE_DIR = LOCK_ROOT .. "/happ-capture"
local CAPTURE_PID = CAPTURE_DIR .. "/pid"
local CAPTURE_OUT = CAPTURE_DIR .. "/out"

local function trim(value)
  return tostring(value or ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
end

local function shellescape(value)
  value = tostring(value or "")
  if value == "" then return "''" end
  return "'" .. value:gsub("'", "'\\''") .. "'"
end

local function exec_ok(cmd)
  local rc = os.execute(cmd)
  return rc == true or rc == 0
end

local function current_pid()
  if ok_nixio and nixio and nixio.getpid then
    return tostring(nixio.getpid())
  end
  return "subscription"
end

local function read_file(path)
  local fh = io.open(path, "rb")
  if not fh then return "" end
  local data = fh:read("*a") or ""
  fh:close()
  return data
end

-- Reads at most `limit` bytes. Used for untrusted subscription responses so
-- an oversized body is never fully materialised as a Lua string just to be
-- rejected by a length check afterwards.
local function read_file_limited(path, limit)
  local fh = io.open(path, "rb")
  if not fh then return "" end
  local data = fh:read(limit) or ""
  fh:close()
  return data
end

-- Size of a file on disk, or nil. Uses nixio when available (it is on
-- OpenWrt) and falls back to a seek-to-end so this script keeps working
-- standalone without nixio, same defensive style as current_pid() above.
local function nixio_stat(path)
  if ok_nixio and nixio and nixio.fs and nixio.fs.stat then
    local st = nixio.fs.stat(path)
    return st and st.size or nil
  end
  local fh = io.open(path, "rb")
  if not fh then return nil end
  local size = fh:seek("end")
  fh:close()
  return size
end

local function ensure_dir(path)
  if path and path ~= "" then
    exec_ok("mkdir -p " .. shellescape(path) .. " >/dev/null 2>&1")
  end
end

local function write_file(path, data)
  local dir, base = tostring(path):match("^(.*)/([^/]+)$")
  if dir and dir ~= "" then ensure_dir(dir) end
  data = data or ""

  -- Temp file lives in an exclusively-created 0700 directory on the target's
  -- own filesystem: exclusive creation alone would still leave the path
  -- swappable between close() and rename in a shared directory.
  local workdir
  for _ = 1, 8 do
    local cand = string.format("%s/.tpm-w.%d.%d", dir or ".", math.random(1, 10 ^ 9), math.random(1, 10 ^ 9))
    if exec_ok("mkdir -m 0700 " .. shellescape(cand) .. " >/dev/null 2>&1") then workdir = cand; break end
  end
  assert(workdir, "could not create a private temp directory for " .. tostring(path))
  local tmp = workdir .. "/" .. (base or "tmp")

  local function drop_workdir()
    exec_ok("rm -rf " .. shellescape(workdir) .. " >/dev/null 2>&1")
  end

  if ok_nixio and nixio and nixio.open_flags then
    local fd = nixio.open(tmp, nixio.open_flags("wronly", "creat", "excl"), "600")
    if not fd then drop_workdir(); error("could not create temp file exclusively: " .. tmp) end
    -- write() may be short; compare against the full payload length instead
    -- of only asserting truthiness, otherwise a truncated file could be
    -- promoted over a good one.
    local n = fd:write(data)
    local closed = fd:close()
    if n ~= #data or not closed then
      drop_workdir()
      error("short write while saving " .. tostring(path))
    end
  else
    local fh = io.open(tmp, "wb")
    if not fh then drop_workdir(); error("could not open temp file: " .. tmp) end
    fh:write(data)
    fh:close()
    exec_ok("chmod 0600 " .. shellescape(tmp) .. " >/dev/null 2>&1")
    local check = io.open(tmp, "rb")
    local wrote = check and #(check:read("*a") or "") or -1
    if check then check:close() end
    if wrote ~= #data then drop_workdir(); error("short write while saving " .. tostring(path)) end
  end

  -- Plain os.rename() can fail with a stale-handle error (ESTALE) on some
  -- flash filesystems (observed: UBIFS/overlay); a `sync` reconciles that.
  -- `mv` is the last resort because it leaves both files intact on failure.
  -- Every branch verifies the RESULT, not the return code. If the target path
  -- has been replaced by a directory, `mv -f file dir` succeeds by moving the
  -- file INSIDE it and exits 0; the old code then chmod'ed the DIRECTORY to
  -- 0600 and reported the save as done. rename(2) refuses that case, the mv
  -- fallback does not, so the check has to cover both.
  local function landed()
    if ok_nixio and nixio and nixio.fs and nixio.fs.stat then
      local st = nixio.fs.stat(path)
      return st ~= nil and st.type == "reg"
    end
    return exec_ok("[ -f " .. shellescape(path) .. " ] >/dev/null 2>&1")
  end

  local moved = os.rename(tmp, path) and landed()
  if not moved then
    os.execute("sync")
    moved = os.rename(tmp, path) and landed()
    if not moved then
      if exec_ok("mv -f " .. shellescape(tmp) .. " " .. shellescape(path) .. " >/dev/null 2>&1") then
        moved = landed()
        if not moved then
          -- mv "succeeded" into a directory: remove what it dropped in there so
          -- the failed save leaves nothing behind.
          exec_ok("rm -f " .. shellescape(path .. "/" .. (base or "tmp")) .. " >/dev/null 2>&1")
        end
      end
    end
  end
  drop_workdir()
  assert(moved, "unable to move the new " .. tostring(path) .. " into place")
  exec_ok("chmod 0600 " .. shellescape(path) .. " >/dev/null 2>&1")
end

local function uci_get(key, fallback)
  local cmd = "uci -q get " .. shellescape(PKG .. ".main." .. key) .. " 2>/dev/null"
  local p = io.popen(cmd)
  if not p then return fallback end
  local out = trim(p:read("*a") or "")
  p:close()
  if out == "" then return fallback end
  return out
end

local function uci_set(key, value)
  return exec_ok("uci set " .. shellescape(PKG .. ".main." .. key .. "=" .. tostring(value or "")) .. " >/dev/null 2>&1")
end

local function uci_commit()
  return exec_ok("uci commit " .. shellescape(PKG) .. " >/dev/null 2>&1")
end

-- uci_revert: drop staged-but-uncommitted changes. Without it a partial stage
-- was left pending and the next unrelated `uci commit` from anywhere would
-- persist it.
local function uci_revert()
  return exec_ok("uci revert " .. shellescape(PKG) .. " >/dev/null 2>&1")
end

local function md5(value)
  local p = io.popen("printf %s " .. shellescape(value) .. " | md5sum 2>/dev/null | awk '{print $1}'")
  if not p then return "" end
  local out = trim(p:read("*a") or "")
  p:close()
  return out
end

local function now()
  return os.time()
end

local function now_human(ts)
  return os.date("%Y-%m-%d %H:%M:%S", ts or now())
end

local function parse_link_line(line)
  local parsed = proxy_links.parse_link_line(line)
  return parsed and parsed.raw_link or nil
end

local function parse_links_text(text)
  local links, seen = {}, {}
  for line in ((text or "") .. "\n"):gmatch("([^\n]*)\n") do
    local link = parse_link_line(line)
    if link then
      local hash = md5(link)
      if hash ~= "" and not seen[hash] then
        links[#links + 1] = { hash = hash, raw_link = link }
        seen[hash] = true
      end
    end
  end
  return links
end

local b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function base64_decode(data)
  data = tostring(data or ""):gsub("%s+", ""):gsub("-", "+"):gsub("_", "/")
  if data == "" or data:find("[^A-Za-z0-9%+/%=]") then return nil end
  local rem = #data % 4
  if rem > 0 then data = data .. string.rep("=", 4 - rem) end
  local bits = data:gsub("=", ""):gsub(".", function(c)
    local idx = b64_chars:find(c, 1, true)
    if not idx then return "" end
    local value = idx - 1
    local out = {}
    for i = 6, 1, -1 do
      out[#out + 1] = (value % 2 ^ i - value % 2 ^ (i - 1) > 0) and "1" or "0"
    end
    return table.concat(out)
  end)
  local decoded = bits:gsub("%d%d%d?%d?%d?%d?%d?%d?", function(byte)
    if #byte ~= 8 then return "" end
    local value = 0
    for i = 1, 8 do
      if byte:sub(i, i) == "1" then value = value + 2 ^ (8 - i) end
    end
    return string.char(value)
  end)
  return decoded ~= "" and decoded or nil
end

local function urlencode(value)
  return tostring(value or ""):gsub("([^A-Za-z0-9%-%._~])", function(c)
    return string.format("%%%02X", c:byte())
  end)
end

local function resolve_subscription_url(url)
  return happ_decrypt.resolve_subscription_url(url)
end

local function add_proxy_link(out, seen, link)
  link = trim(link)
  if not proxy_links.is_supported(link) then return end
  local hash = md5(link)
  if hash ~= "" and not seen[hash] then
    out[#out + 1] = { hash = hash, raw_link = link }
    seen[hash] = true
  end
end

local function host_for_vless(address)
  address = tostring(address or "")
  if address:find(":", 1, true) and not address:match("^%[.*%]$") then
    return "[" .. address .. "]"
  end
  return address
end

local function host_for_uri(address)
  return host_for_vless(address)
end

local function value_or_empty(value)
  if value == nil then return "" end
  return tostring(value)
end

local function csv_value(value)
  if type(value) == "table" then
    local out = {}
    for _, item in ipairs(value) do out[#out + 1] = tostring(item) end
    return table.concat(out, ",")
  end
  return value_or_empty(value)
end

local function add_query(params, key, value)
  value = value_or_empty(value)
  if value ~= "" then params[#params + 1] = urlencode(key) .. "=" .. urlencode(value) end
end

local function outbound_to_vless(config, outbound, suffix)
  if type(outbound) ~= "table" or outbound.protocol ~= "vless" then return nil end
  local settings = type(outbound.settings) == "table" and outbound.settings or {}
  local vnext = type(settings.vnext) == "table" and settings.vnext[1] or nil
  if type(vnext) ~= "table" then return nil end
  local users = type(vnext.users) == "table" and vnext.users[1] or nil
  if type(users) ~= "table" then return nil end
  local address = value_or_empty(vnext.address)
  local port = tonumber(vnext.port)
  local uuid = value_or_empty(users.id)
  if address == "" or not port or uuid == "" then return nil end

  local stream = type(outbound.streamSettings) == "table" and outbound.streamSettings or {}
  local params = {}
  add_query(params, "security", stream.security or "none")
  add_query(params, "encryption", users.encryption or "none")
  add_query(params, "type", stream.network or "tcp")
  add_query(params, "flow", users.flow)

  local reality = type(stream.realitySettings) == "table" and stream.realitySettings or {}
  add_query(params, "sni", reality.serverName)
  add_query(params, "pbk", reality.publicKey)
  add_query(params, "fp", reality.fingerprint)
  add_query(params, "sid", reality.shortId)
  add_query(params, "spx", reality.spiderX)

  local tls = type(stream.tlsSettings) == "table" and stream.tlsSettings or {}
  if value_or_empty(reality.serverName) == "" then add_query(params, "sni", tls.serverName) end
  if value_or_empty(reality.fingerprint) == "" then add_query(params, "fp", tls.fingerprint) end
  add_query(params, "alpn", csv_value(tls.alpn))
  if tls.allowInsecure ~= nil then add_query(params, "allowInsecure", tls.allowInsecure and "1" or "0") end

  local tcp = type(stream.tcpSettings) == "table" and stream.tcpSettings or {}
  local header = type(tcp.header) == "table" and tcp.header or {}
  add_query(params, "headerType", header.type)

  local ws = type(stream.wsSettings) == "table" and stream.wsSettings or {}
  add_query(params, "path", ws.path)
  if type(ws.headers) == "table" then add_query(params, "host", ws.headers.Host or ws.headers.host) end

  local grpc = type(stream.grpcSettings) == "table" and stream.grpcSettings or {}
  add_query(params, "serviceName", grpc.serviceName)
  add_query(params, "mode", grpc.mode or (grpc.multiMode and "multi" or ""))

  local remarks = value_or_empty(type(config) == "table" and config.remarks or "")
  if suffix and suffix ~= "" then
    remarks = remarks ~= "" and (remarks .. " " .. suffix) or suffix
  end
  return string.format("vless://%s@%s:%d?%s#%s",
    urlencode(uuid),
    host_for_vless(address),
    port,
    table.concat(params, "&"),
    urlencode(remarks))
end

local function first_hysteria_server(settings)
  if type(settings.servers) == "table" and type(settings.servers[1]) == "table" then
    return settings.servers[1]
  end
  if type(settings.server) == "table" then
    return settings.server
  end
  return settings
end

local function outbound_to_hysteria(config, outbound, suffix)
  if type(outbound) ~= "table" or outbound.protocol ~= "hysteria" then return nil end
  local settings = type(outbound.settings) == "table" and outbound.settings or {}
  local server = first_hysteria_server(settings)
  local address = value_or_empty(server.address or server.host)
  local port = tonumber(server.port)
  if address == "" or not port then return nil end

  local stream = type(outbound.streamSettings) == "table" and outbound.streamSettings or {}
  local hysteria = type(stream.hysteriaSettings) == "table" and stream.hysteriaSettings or {}
  local auth = value_or_empty(hysteria.auth or settings.auth or server.auth)
  local params = {}
  local tls = type(stream.tlsSettings) == "table" and stream.tlsSettings or {}
  add_query(params, "sni", tls.serverName or server.sni)
  if tls.allowInsecure ~= nil then add_query(params, "insecure", tls.allowInsecure and "1" or "0") end
  add_query(params, "pinSHA256", tls.pinSHA256 or tls.pinnedPeerCertSha256)
  add_query(params, "ech", tls.ech or tls.echConfigList)
  if type(tls.alpn) == "table" then
    local alpn = {}
    for _, item in ipairs(tls.alpn) do
      if value_or_empty(item) ~= "" then alpn[#alpn + 1] = value_or_empty(item) end
    end
    add_query(params, "alpn", table.concat(alpn, ","))
  else
    add_query(params, "alpn", tls.alpn)
  end

  local remarks = value_or_empty(type(config) == "table" and config.remarks or "")
  if suffix and suffix ~= "" then
    remarks = remarks ~= "" and (remarks .. " " .. suffix) or suffix
  end
  local query = table.concat(params, "&")
  local userinfo = auth ~= "" and (urlencode(auth) .. "@") or ""
  local query_part = query ~= "" and ("?" .. query) or ""
  return string.format("hysteria2://%s%s:%d/%s#%s",
    userinfo,
    host_for_uri(address),
    port,
    query_part,
    urlencode(remarks))
end

local function extract_json_proxy_links(node, out, seen)
  local function walk(value)
    if type(value) ~= "table" then return end
    if type(value.outbounds) == "table" then
      local vless_outbounds = {}
      local hysteria_outbounds = {}
      for _, outbound in ipairs(value.outbounds) do
        if type(outbound) == "table" and outbound.protocol == "vless" then
          vless_outbounds[#vless_outbounds + 1] = outbound
        elseif type(outbound) == "table" and outbound.protocol == "hysteria" then
          hysteria_outbounds[#hysteria_outbounds + 1] = outbound
        end
      end
      for _, outbound in ipairs(vless_outbounds) do
        local suffix = #vless_outbounds > 1 and value_or_empty(outbound.tag) or ""
        add_proxy_link(out, seen, outbound_to_vless(value, outbound, suffix) or "")
      end
      for _, outbound in ipairs(hysteria_outbounds) do
        local suffix = #hysteria_outbounds > 1 and value_or_empty(outbound.tag) or ""
        add_proxy_link(out, seen, outbound_to_hysteria(value, outbound, suffix) or "")
      end
    else
      for _, child in pairs(value) do walk(child) end
    end
  end
  walk(node)
end

local function extract_proxy_links(text)
  local out, seen = {}, {}
  local function add_from(source)
    source = tostring(source or "")
    for _, item in ipairs(proxy_links.extract_from_text(source)) do
      add_proxy_link(out, seen, item.raw_link)
    end
    local ok, parsed = pcall(jsonc.parse, source)
    if ok and type(parsed) == "table" then
      extract_json_proxy_links(parsed, out, seen)
    end
  end
  add_from(text)
  local decoded = base64_decode(text)
  if decoded then add_from(decoded) end
  return out
end

local function classify_subscription_response(text)
  if #extract_proxy_links(text) > 0 then
    local ok, parsed = pcall(jsonc.parse, text)
    if ok and type(parsed) == "table" then return "json" end
    local decoded = base64_decode(text)
    if decoded then
      local ok_decoded, parsed_decoded = pcall(jsonc.parse, decoded)
      if ok_decoded and type(parsed_decoded) == "table" then return "base64-json" end
      return "base64-text"
    end
    return "text"
  end
  return "unknown"
end

local function normalize_db(db)
  if type(db) ~= "table" then db = {} end
  db.version = tonumber(db.version) or 1
  db.next_id = tonumber(db.next_id) or 1
  if type(db.subscriptions) ~= "table" then db.subscriptions = {} end
  if type(db.links) ~= "table" then db.links = {} end
  if type(db.excluded) ~= "table" then db.excluded = {} end
  if type(db.removed) ~= "table" then db.removed = {} end
  return db
end

local function db_path()
  return os.getenv("TPROXY_MANAGER_SUBSCRIPTIONS_FILE") or uci_get("watchdog_subscriptions_file", DEFAULT_DB)
end

local function links_path()
  return os.getenv("TPROXY_MANAGER_LINKS_FILE") or uci_get("watchdog_links_file", DEFAULT_LINKS)
end

local function load_db()
  local raw = read_file(db_path())
  if raw == "" then return normalize_db(nil) end
  local ok, parsed = pcall(jsonc.parse, raw)
  if not ok or type(parsed) ~= "table" then return normalize_db(nil) end
  return normalize_db(parsed)
end

local function save_db(db)
  write_file(db_path(), jsonc.stringify(normalize_db(db), true) .. "\n")
end

local function find_subscription(db, id)
  id = tonumber(id)
  if not id then return nil end
  for _, sub in ipairs(db.subscriptions) do
    if tonumber(sub.id) == id then return sub end
  end
  return nil
end

local function source_key(sub)
  return tostring(sub.type or "happ") .. ":" .. tostring(sub.id)
end

local function source_label(sub)
  return tostring(sub.type or "happ") .. " " .. tostring(sub.id)
end

local function subscription_enabled(sub)
  return sub.enabled == true or sub.enabled == "1" or sub.enabled == 1
end

local function header_list(sub)
  local headers = {}
  local map = type(sub.headers) == "table" and sub.headers or {}
  local ordered = {
    "User-Agent",
    "X-Device-Os",
    "X-Device-Locale",
    "X-Device-Model",
    "X-Ver-Os",
    "Accept-Encoding",
    "Connection",
    "X-Hwid",
    "X-Real-Ip",
    "X-Forwarded-For",
  }
  local used = {}
  for _, name in ipairs(ordered) do
    local value = trim(map[name])
    if value ~= "" then
      headers[#headers + 1] = name .. ": " .. value
      used[name] = true
    end
  end
  for name, value in pairs(map) do
    if not used[name] and trim(value) ~= "" then
      headers[#headers + 1] = tostring(name) .. ": " .. trim(value)
    end
  end
  for line in tostring(sub.extra_headers or ""):gmatch("[^\r\n]+") do
    line = trim(line)
    if line:match("^[^:]+:%s*.+$") then headers[#headers + 1] = line end
  end
  return headers
end

-- A subscription server is an untrusted third party by definition (it's
-- whatever URL the user configured, and it can be redirected by whoever
-- controls that URL at fetch time) - bound both the raw download and the
-- decompressed payload so a malicious/compromised endpoint can't fill the
-- router's tmpfs with an oversized or gzip-bomb response.
local MAX_SUBSCRIPTION_DOWNLOAD_BYTES = 4 * 1024 * 1024
local MAX_SUBSCRIPTION_DECODED_BYTES  = 8 * 1024 * 1024

local function fetch_url(sub, resolved_url)
  -- Both files live inside an exclusively-created 0700 directory. curl has
  -- to (re)open them by path, so an exclusive create alone would still leave
  -- a window in world-writable /tmp where the path could be swapped; inside
  -- a private directory no other user can even resolve the names.
  local workdir
  for _ = 1, 8 do
    local cand = string.format("/tmp/.tpm-sub.%d.%d", math.random(1, 10 ^ 9), math.random(1, 10 ^ 9))
    if exec_ok("mkdir -m 0700 " .. shellescape(cand) .. " >/dev/null 2>&1") then workdir = cand; break end
  end
  if not workdir then
    return "000", "", "could not create a private working directory for the download"
  end
  local body = workdir .. "/body"
  local err  = workdir .. "/err"
  local decoded_path = workdir .. "/decoded"
  -- Create both files EXCLUSIVELY (O_CREAT|O_EXCL, mode 0600) before curl
  -- writes into them. Plain io.open() would follow a pre-planted symlink and
  -- let this root process clobber the link target; O_EXCL fails with EEXIST
  -- on a symlink whether or not its target exists.
  if ok_nixio and nixio and nixio.open_flags then
    local flags = nixio.open_flags("wronly", "creat", "excl")
    for _, path in ipairs({ body, err }) do
      local fd = nixio.open(path, flags, "600")
      if not fd then
        return "000", "", "could not create a private temp file for the download"
      end
      fd:close()
    end
  else
    for _, path in ipairs({ body, err }) do
      local fh = io.open(path, "wb")
      if fh then fh:close() end
      exec_ok("chmod 0600 " .. shellescape(path) .. " >/dev/null 2>&1")
    end
  end
  local parts = {
    "curl -L -sS",
    "-o", shellescape(body),
    "-w", shellescape("%{http_code}"),
    "--connect-timeout", "15",
    "--max-time", tostring(tonumber(sub.timeout) or 30),
    "--max-filesize", tostring(MAX_SUBSCRIPTION_DOWNLOAD_BYTES),
    -- The URL itself is already checked for http(s):// before we get here
    -- (see resolve_subscription_url); --proto-redir stops a redirect from
    -- jumping to a different scheme (file://, etc.) that -L would
    -- otherwise happily follow.
    "--proto", "=http,https",
    "--proto-redir", "=http,https",
  }
  for _, header in ipairs(header_list(sub)) do
    parts[#parts + 1] = "--header"
    parts[#parts + 1] = shellescape(header)
  end
  parts[#parts + 1] = shellescape(resolved_url or sub.url or "")
  -- Append curl's own exit status on its own line after the -w http_code so
  -- a transport-level failure (--max-filesize tripped, blocked protocol,
  -- TLS error) is distinguishable from a successful fetch: without it,
  -- io.popen's exit status is not reliably surfaced and a truncated or
  -- refused download would be parsed as if it were a valid response body.
  local cmd = "{ " .. table.concat(parts, " ") .. "; printf '\\n%s' \"$?\"; } 2>" .. shellescape(err)

  local function cleanup()
    exec_ok("rm -rf " .. shellescape(workdir) .. " >/dev/null 2>&1")
  end

  local p = io.popen(cmd)
  local raw = p and (p:read("*a") or "") or ""
  if p then p:close() end
  local code, curl_rc = raw:match("^(%S*)%s*\n(%d+)%s*$")
  code = trim(code or "")
  curl_rc = tonumber(curl_rc)
  if code == "" then code = "000" end

  if curl_rc ~= nil and curl_rc ~= 0 then
    local detail = trim(read_file(err))
    cleanup()
    if curl_rc == 63 then
      return "000", "", "subscription response exceeds the download size limit"
    end
    return "000", "", detail ~= "" and detail or ("curl failed with exit code " .. tostring(curl_rc))
  end

  -- --max-filesize only applies when the server declares Content-Length;
  -- a chunked response is not capped by it at all, so check what actually
  -- landed on disk before reading any of it into memory.
  local body_st = nixio_stat(body)
  if body_st and body_st > MAX_SUBSCRIPTION_DOWNLOAD_BYTES then
    cleanup()
    return "000", "", "subscription response exceeds the download size limit"
  end

  local response = read_file_limited(body, MAX_SUBSCRIPTION_DECODED_BYTES + 1)
  if #response > MAX_SUBSCRIPTION_DECODED_BYTES then
    cleanup()
    return "000", "", "subscription response exceeds the size limit"
  end
  if response:byte(1) == 31 and response:byte(2) == 139 then
    -- `gzip -t` used to run first, to tell a corrupt stream from a valid one.
    -- The problem is that it decompresses the WHOLE stream with no consumer:
    -- measured on the target, a 2 MB body expanding to 2 GiB burned 20 seconds
    -- of CPU before a single byte had been length-checked. A bomb costs the
    -- attacker nothing to offer, so that is a remote CPU-exhaustion primitive.
    --
    -- The fix is to decompress exactly ONCE, streaming, with the byte cap as
    -- the bound: `head -c LIMIT+1` closes the pipe the moment the cap is
    -- passed, gzip dies of SIGPIPE, and the expansion stops there. That bounds
    -- the work by construction - the same 2 GiB bomb now finishes in under a
    -- second, having produced 8 MiB. (No wall-clock timer: `timeout` is not
    -- part of this busybox build, and with output capped it would have nothing
    -- left to protect against.)
    --
    -- Integrity is judged by gzip's own exit status, which the shell writes to
    -- a side file so it survives the pipeline:
    --   0   - clean stream
    --   141 - killed by SIGPIPE, i.e. the cap was hit (reported as too large)
    --   else- the stream itself is broken
    local rcfile = workdir .. "/gzrc"
    local ok_run = exec_ok(string.format(
      "sh -c %s >%s 2>/dev/null",
      shellescape(string.format("{ gzip -dc %s; echo $? >%s; } | head -c %d",
        shellescape(body), shellescape(rcfile), MAX_SUBSCRIPTION_DECODED_BYTES + 1)),
      shellescape(decoded_path)))
    local decoded = read_file_limited(decoded_path, MAX_SUBSCRIPTION_DECODED_BYTES + 1)
    local gz_rc = tonumber(trim(read_file(rcfile)))

    if #decoded > MAX_SUBSCRIPTION_DECODED_BYTES then
      cleanup()
      return "000", "", "decompressed subscription response exceeds the size limit"
    end
    if not ok_run and #decoded == 0 then
      cleanup()
      return "000", "", "subscription response could not be decompressed"
    end
    if gz_rc == nil or (gz_rc ~= 0 and gz_rc ~= 141) then
      cleanup()
      return "000", "", "subscription response is not a valid gzip stream"
    end
    if decoded ~= "" then response = decoded end
  end
  local error_text = trim(read_file(err))
  cleanup()
  return code, response, error_text
end

local function clear_source(db, sub, new_hashes)
  local skey = source_key(sub)
  for hash, item in pairs(db.links) do
    if type(item) == "table" and type(item.sources) == "table" and item.sources[skey] and not new_hashes[hash] then
      item.sources[skey] = nil
      db.excluded[skey .. "|" .. hash] = nil
      local has_source = false
      for _ in pairs(item.sources) do has_source = true; break end
      if not has_source then
        db.links[hash] = nil
        db.removed[hash] = now()
      end
    end
  end
end

local function apply_subscription_links(db, sub, links)
  local ts = now()
  local skey = source_key(sub)
  local new_hashes = {}
  for _, link in ipairs(links) do new_hashes[link.hash] = true end
  clear_source(db, sub, new_hashes)
  for _, link in ipairs(links) do
    local item = db.links[link.hash]
    if type(item) ~= "table" then
      item = { hash = link.hash, raw_link = link.raw_link, sources = {}, first_seen = ts }
      db.links[link.hash] = item
    end
    item.raw_link = link.raw_link or item.raw_link
    item.last_seen = ts
    item.sources = type(item.sources) == "table" and item.sources or {}
    item.sources[skey] = {
      type = sub.type or "happ",
      id = tonumber(sub.id) or sub.id,
      label = source_label(sub),
      last_seen = ts,
    }
    db.removed[link.hash] = nil
  end
end

local function active_subscription_links(db)
  local active = {}
  for hash, item in pairs(db.links or {}) do
    if type(item) == "table" and type(item.sources) == "table" then
      local has_active_source = false
      for skey in pairs(item.sources) do
        if not db.excluded[skey .. "|" .. hash] then
          has_active_source = true
          break
        end
      end
      if has_active_source and item.raw_link and item.raw_link ~= "" then
        active[hash] = item.raw_link
      end
    end
  end
  return active
end

local function sync_links_file(db)
  local active = active_subscription_links(db)
  local managed = {}
  for hash, item in pairs(db.links or {}) do
    if type(item) == "table" and type(item.sources) == "table" then
      for _ in pairs(item.sources) do
        managed[hash] = true
        break
      end
    end
  end
  local used, out = {}, {}
  for _, entry in ipairs(parse_links_text(read_file(links_path()))) do
    if active[entry.hash] then
      if not used[entry.hash] then
        out[#out + 1] = active[entry.hash]
        used[entry.hash] = true
      end
    elseif managed[entry.hash] then
      -- Subscription links disabled through exclusions remain in the DB, but not in rotation.
    elseif not db.removed[entry.hash] then
      out[#out + 1] = entry.raw_link
    end
  end
  local hashes = {}
  for hash in pairs(active) do hashes[#hashes + 1] = hash end
  table.sort(hashes)
  for _, hash in ipairs(hashes) do
    if not used[hash] then out[#out + 1] = active[hash] end
  end
  write_file(links_path(), table.concat(out, "\n") .. (#out > 0 and "\n" or ""))
end

-- save_db_and_links: the database and the links file are ONE unit. The links
-- file is generated from the database, so a saved database with a stale links
-- file leaves the watchdog probing links the database no longer knows about --
-- which is exactly what two independent writes with no way back produced.
--
-- `sync` false means only the database is written; that is a single atomic write
-- and needs no rollback.
local function save_db_and_links(db, sync)
  if not sync then
    save_db(db)
    return
  end
  if not ok_utils or not utils or not utils.snapshot_begin then
    error("rollback support is unavailable; refusing to write the database and the link list without it")
  end

  local store, serr = utils.snapshot_begin("subs-sync")
  if store then
    for _, path in ipairs({ db_path(), links_path() }) do
      if not store then break end
      local ok_s, aerr = utils.snapshot_add(store, path)
      if not ok_s then serr = aerr; utils.snapshot_discard(store); store = nil end
    end
  end
  if not store then
    error("could not create a rollback snapshot: " .. tostring(serr))
  end
  local armed, aerr = utils.snapshot_arm(store)
  if not armed then
    utils.snapshot_discard(store)
    error("could not arm the rollback snapshot: " .. tostring(aerr))
  end

  local ok, err = pcall(function()
    save_db(db)
    sync_links_file(db)
  end)
  if ok then
    utils.snapshot_discard(store)
    return
  end

  local failed = utils.snapshot_restore(store)
  if #failed > 0 then
    local names = {}
    for _, f in ipairs(failed) do names[#names + 1] = f.path end
    local kept = utils.snapshot_keep(store) or store.dir
    error(string.format("%s - ROLLBACK INCOMPLETE for %s; originals kept in %s",
      tostring(err), table.concat(names, ", "), kept))
  end
  utils.snapshot_discard(store)
  error(tostring(err))
end

local function fetch_subscription(db, sub)
  if not sub then return false, "подписка не найдена" end
  if sub.type == "json" then
    sub.last_status = "error"
    sub.last_error = "JSON x-ui parser пока не активен: нужен пример реального JSON-ответа"
    sub.last_update = now()
    sub.last_update_human = now_human(sub.last_update)
    return false, sub.last_error
  end
  if sub.type ~= "happ" then
    sub.last_status = "error"
    sub.last_error = "неподдерживаемый тип подписки"
    sub.last_update = now()
    sub.last_update_human = now_human(sub.last_update)
    return false, sub.last_error
  end
  if trim(sub.url) == "" then
    sub.last_status = "error"
    sub.last_error = "URL подписки пуст"
    sub.last_update = now()
    sub.last_update_human = now_human(sub.last_update)
    return false, sub.last_error
  end

  local resolved_url, resolve_err = resolve_subscription_url(sub.url)
  if not resolved_url then
    sub.last_status = "error"
    sub.last_error = resolve_err or "не удалось обработать URL подписки"
    sub.last_update = now()
    sub.last_update_human = now_human(sub.last_update)
    return false, sub.last_error
  end

  local code, response, err = fetch_url(sub, resolved_url)
  if code ~= "200" or response == "" then
    sub.last_status = "error"
    sub.last_error = err ~= "" and err or ("HTTP " .. tostring(code))
    sub.last_update = now()
    sub.last_update_human = now_human(sub.last_update)
    return false, sub.last_error
  end

  local response_kind = classify_subscription_response(response)
  local links = extract_proxy_links(response)
  if #links == 0 then
    sub.last_status = "error"
    sub.last_error = "ответ не содержит валидных proxy-ссылок"
    sub.last_update = now()
    sub.last_update_human = now_human(sub.last_update)
    return false, sub.last_error
  end

  apply_subscription_links(db, sub, links)
  sub.last_status = "ok"
  sub.last_error = ""
  sub.last_count = #links
  sub.last_response_type = response_kind
  sub.last_update = now()
  sub.last_update_human = now_human(sub.last_update)
  return true, tostring(#links)
end

local LOCK_OWNERLESS_GRACE = 300  -- seconds

local function lock_write_pid()
  -- Written directly, not through write_file(): that helper creates a temp
  -- directory next to the target and would recurse into the very locking
  -- logic we are setting up here.
  local fh = io.open(LOCK_DIR .. "/pid", "w")
  if not fh then return false end
  local pid = current_pid() .. "\n"
  local okw = fh:write(pid)
  local okc = fh:close()
  return okw ~= nil and okc ~= nil and okc ~= false
end

-- Same validation as the LuCI side: /var/lock is 1777, so the path can be
-- pre-created by any local user. mkdir is atomic and proves we made it; an
-- existing path is accepted only if lstat shows a real root-owned 0700
-- directory (never a symlink or someone else's).
local function secure_lock_root()
  if exec_ok("mkdir -m 0700 " .. shellescape(LOCK_ROOT) .. " >/dev/null 2>&1") then
    return true
  end
  if not (ok_nixio and nixio and nixio.fs and nixio.fs.lstat) then
    return exec_ok("[ -d " .. shellescape(LOCK_ROOT) .. " ]")
  end
  local st = nixio.fs.lstat(LOCK_ROOT)
  if not st then return false end
  if st.type ~= "dir" and st.type ~= "directory" then return false end
  if (st.uid or -1) ~= 0 then return false end
  if (st.modedec or 0) ~= 700 then
    exec_ok("chmod 0700 " .. shellescape(LOCK_ROOT) .. " >/dev/null 2>&1")
    local again = nixio.fs.lstat(LOCK_ROOT)
    if not again or (again.modedec or 0) ~= 700 then return false end
  end
  return true
end

local function acquire_lock()
  if not secure_lock_root() then
    io.stderr:write("refusing to run: unsafe lock directory " .. LOCK_ROOT .. "\n")
    return false
  end

  if exec_ok("mkdir " .. shellescape(LOCK_DIR) .. " >/dev/null 2>&1") then
    -- If the owner PID cannot be recorded, release the lock immediately
    -- rather than leaving an ownerless one that nobody can attribute.
    if not lock_write_pid() then
      exec_ok("rm -rf " .. shellescape(LOCK_DIR) .. " >/dev/null 2>&1")
      return false
    end
    return true
  end

  local pid = trim(read_file(LOCK_DIR .. "/pid"))
  local stale = false
  if pid:match("^%d+$") then
    -- Owner known: stale only if that process is gone.
    stale = not exec_ok("kill -0 " .. shellescape(pid) .. " >/dev/null 2>&1")
  else
    -- Ownerless: either another process is between its mkdir and its pid
    -- write (a moment ago), or it died in that window and the lock would
    -- otherwise survive until reboot. A short grace period separates the
    -- two without stealing a lock that is being acquired right now.
    local st = ok_nixio and nixio and nixio.fs and nixio.fs.stat(LOCK_DIR) or nil
    local age = st and st.mtime and (os.time() - st.mtime) or 0
    stale = age > LOCK_OWNERLESS_GRACE
  end

  if stale then
    exec_ok("rm -rf " .. shellescape(LOCK_DIR) .. " >/dev/null 2>&1")
    if exec_ok("mkdir " .. shellescape(LOCK_DIR) .. " >/dev/null 2>&1") then
      if not lock_write_pid() then
        exec_ok("rm -rf " .. shellescape(LOCK_DIR) .. " >/dev/null 2>&1")
        return false
      end
      return true
    end
  end
  return false
end

local function release_lock()
  os.remove(LOCK_DIR .. "/pid")
  exec_ok("rmdir " .. shellescape(LOCK_DIR) .. " >/dev/null 2>&1")
end

-- caller_holds_lock: the LuCI side runs read-modify-sync as ONE transaction
-- and has to hold this same lock across all of it. Without a way to say so,
-- the sync-links it invokes would deadlock against its caller.
--
-- The claim is verified, not trusted: the pid in the lock directory must
-- match what the caller passed. Only root can write there (0700 root-owned,
-- checked by secure_lock_root), and only our own parent can set the
-- environment variable, so a forged claim would already require root.
local function caller_holds_lock()
  local claimed = trim(os.getenv("TPM_SUBS_LOCK_PID") or "")
  if not claimed:match("^%d+$") then return false end
  if trim(read_file(LOCK_DIR .. "/pid")) ~= claimed then return false end
  -- The owner must still be alive; a stale pid file must not grant entry.
  return exec_ok("kill -0 " .. shellescape(claimed) .. " >/dev/null 2>&1")
end

local function with_lock(fn)
  if caller_holds_lock() then
    -- Neither acquired nor released here: the caller owns the lock for the
    -- whole transaction, including its rollback.
    local ok, a, b = pcall(fn)
    if not ok then return false, tostring(a) end
    return a, b
  end
  if not acquire_lock() then
    return false, "watchdog занят другой операцией"
  end
  local ok, a, b = pcall(fn)
  release_lock()
  if not ok then return false, tostring(a) end
  return a, b
end

local function command_status()
  local db = load_db()
  local enabled = 0
  for _, sub in ipairs(db.subscriptions) do
    if subscription_enabled(sub) then enabled = enabled + 1 end
  end
  local link_count = 0
  for _ in pairs(db.links) do link_count = link_count + 1 end
  print("SUBSCRIPTIONS_FILE=" .. db_path())
  print("SUBSCRIPTIONS_TOTAL=" .. tostring(#db.subscriptions))
  print("SUBSCRIPTIONS_ENABLED=" .. tostring(enabled))
  print("SUBSCRIPTION_LINKS=" .. tostring(link_count))
  print("LINKS_FILE=" .. links_path())
end

local function command_fetch(id)
  return with_lock(function()
    local db = load_db()
    local sub = find_subscription(db, id)
    local ok, detail = fetch_subscription(db, sub)
    save_db_and_links(db, ok)
    return ok, detail
  end)
end

local function command_fetch_all()
  return with_lock(function()
    local db = load_db()
    local total, ok_count, err_count = 0, 0, 0
    for _, sub in ipairs(db.subscriptions) do
      if subscription_enabled(sub) then
        total = total + 1
        local ok = fetch_subscription(db, sub)
        if ok then ok_count = ok_count + 1 else err_count = err_count + 1 end
      end
    end
    save_db_and_links(db, total > 0)
    return err_count == 0, string.format("updated=%d ok=%d error=%d", total, ok_count, err_count)
  end)
end

local function command_fetch_due()
  return with_lock(function()
    local db = load_db()
    local current = now()
    local total, ok_count, err_count = 0, 0, 0
    for _, sub in ipairs(db.subscriptions) do
      local interval = tonumber(sub.refresh_interval) or 0
      local last = tonumber(sub.last_update) or 0
      if subscription_enabled(sub) and interval > 0 and (last == 0 or current - last >= interval) then
        total = total + 1
        local ok = fetch_subscription(db, sub)
        if ok then ok_count = ok_count + 1 else err_count = err_count + 1 end
      end
    end
    if total > 0 then
      save_db_and_links(db, true)
      return err_count == 0, string.format("subscriptions due updated=%d ok=%d error=%d", total, ok_count, err_count)
    end
    return true, ""
  end)
end

local function command_sync_links()
  return with_lock(function()
    local db = load_db()
    sync_links_file(db)
    return true, "links synced"
  end)
end

local function command_exclude_link(hash)
  return with_lock(function()
    local db = load_db()
    local item = db.links[hash]
    if type(item) ~= "table" or type(item.sources) ~= "table" then
      return false, "subscription link not found"
    end
    for skey in pairs(item.sources) do
      db.excluded[skey .. "|" .. hash] = now()
    end
    db.removed[hash] = nil
    save_db_and_links(db, true)
    return true, "link excluded"
  end)
end

local function command_include_link(hash)
  return with_lock(function()
    local db = load_db()
    local item = db.links[hash]
    if type(item) ~= "table" or type(item.sources) ~= "table" then
      return false, "subscription link not found"
    end
    local changed = false
    for skey in pairs(item.sources) do
      local key = skey .. "|" .. hash
      if db.excluded[key] then
        db.excluded[key] = nil
        changed = true
      end
    end
    db.removed[hash] = nil
    save_db_and_links(db, true)
    return true, changed and "link included" or "link already included"
  end)
end

-- This token is the ONLY authorization on the capture endpoint, which is
-- reachable without a LuCI login. The previous construction hashed
-- time+math.random+pid: all three are low-entropy and partly known to an
-- attacker, making the token brute-forceable despite looking like a random
-- MD5. Read 32 bytes from the kernel CSPRNG instead, and refuse to start
-- the endpoint at all if that is not possible - a weak token would be
-- indistinguishable from a strong one in the UI.
local function capture_token()
  local fh = io.open("/dev/urandom", "rb")
  if not fh then return nil end
  local raw = fh:read(32)
  fh:close()
  if not raw or #raw ~= 32 then return nil end
  return (raw:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

-- capture_pid_is_ours: only ever signal a process that is actually one of our
-- capture servers. A planted or recycled PID would otherwise let this kill an
-- unrelated process as root.
local function capture_pid_is_ours(pid)
  if not pid:match("^%d+$") then return false end
  local cmdline = read_file("/proc/" .. pid .. "/cmdline")
  if cmdline == "" then return false end
  cmdline = cmdline:gsub("%z", " ")
  return cmdline:find("tproxy-manager-subscriptions.lua", 1, true) ~= nil
    and cmdline:find("capture-serve", 1, true) ~= nil
end

-- capture_disable: clear the enabled flag and REPORT whether it stuck. The
-- endpoint gates on this flag, so "stopped" while it is still 1 means the URL
-- keeps answering after the user was told the capture is over.
local function capture_disable()
  if not uci_set("watchdog_happ_capture_enabled", "0") then
    uci_revert()
    return false, "could not stage the capture shutdown"
  end
  if not uci_commit() then
    uci_revert()
    return false, "could not save the capture shutdown"
  end
  if trim(uci_get("watchdog_happ_capture_enabled", "")) ~= "0" then
    return false, "the capture is still marked enabled"
  end
  return true
end

local function capture_stop()
  local pid = trim(read_file(CAPTURE_PID))
  if capture_pid_is_ours(pid) then
    exec_ok("kill " .. shellescape(pid) .. " >/dev/null 2>&1")
  end
  os.remove(CAPTURE_PID)
end

local function parse_raw_http_request(raw)
  raw = tostring(raw or "")
  local head, body = raw:match("^(.-)\r?\n\r?\n(.*)$")
  head = head or raw
  body = body or ""
  local lines = {}
  for line in (head .. "\n"):gmatch("([^\n]*)\n") do
    lines[#lines + 1] = line:gsub("\r$", "")
  end
  local request_line = table.remove(lines, 1) or "GET / HTTP/1.1"
  local out = {
    string.format("[%s]", os.date("!%Y-%m-%dT%H:%M:%SZ")),
    request_line,
    "",
    "HTTP HEADERS:",
  }
  for _, line in ipairs(lines) do
    if trim(line) ~= "" then out[#out + 1] = line end
  end
  out[#out + 1] = ""
  out[#out + 1] = "REQUEST BODY:"
  out[#out + 1] = body
  out[#out + 1] = ""
  return table.concat(out, "\n")
end

local function capture_serve(token, until_ts, port, log_path)
  if not ok_nixio or not nixio then
    io.stderr:write("nixio is required for raw capture service\n")
    return false
  end
  token = tostring(token or "")
  until_ts = tonumber(until_ts) or 0
  port = tonumber(port) or 18088
  log_path = tostring(log_path or "/tmp/tproxy-manager-happ-capture.log")
  local server = nixio.socket("inet", "stream")
  if not server then return false end
  pcall(function() server:setsockopt("socket", "reuseaddr", 1) end)
  local ok, err = server:bind("0.0.0.0", port)
  if not ok then
    io.stderr:write("bind failed: " .. tostring(err) .. "\n")
    return false
  end
  server:listen(5)
  -- The accept() below used to block with no deadline: after the TTL expired the
  -- process kept listening until someone connected, and that late connection was
  -- then served — verified on the target, an expired token got HTTP 200 three
  -- seconds after a TTL of one. Two independent bounds fix it:
  --
  --   * a receive timeout on the LISTENING socket, so accept() itself returns
  --     periodically and the loop can re-evaluate the deadline;
  --   * a re-check of the deadline after accept() returns, so a connection that
  --     arrives in the last instant is refused rather than served.
  pcall(function() server:setsockopt("socket", "rcvtimeo", 1) end)
  while now() <= until_ts do
    local client = server:accept()
    if client and now() > until_ts then
      -- Arrived after expiry: close without looking at the request at all.
      pcall(function() client:close() end)
      client = nil
    end
    if client then
      pcall(function() client:setsockopt("socket", "rcvtimeo", 5) end)
      local chunks = {}
      local first = client:recv(65535)
      if first and first ~= "" then chunks[#chunks + 1] = first end
      local raw = table.concat(chunks)
      local path_token = raw:match("^[A-Z]+%s+/([^%s%?]*)")
      local query_token = raw:match("^[A-Z]+%s+[^%s%?]*%?[^%s]*token=([^%s&]+)")
      local got_token = trim(path_token or query_token or "")
      local status = "403 Forbidden"
      local body = "capture endpoint is disabled or token expired\n"
      -- Expiry is re-checked here too: parsing the request takes time, and the
      -- TTL must hold at the moment the capture is actually written.
      if got_token == token and got_token ~= "" and now() <= until_ts then
        write_file(log_path, parse_raw_http_request(raw))
        status = "200 OK"
        body = "OK\n"
      end
      client:send("HTTP/1.1 " .. status .. "\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-cache, max-age=0\r\n\r\n" .. body)
      client:close()
    end
  end
  server:close()
  os.remove(CAPTURE_PID)
  return true
end

local function command_capture_start(ttl, port, log_path)
  ttl = tonumber(ttl) or tonumber(uci_get("watchdog_happ_capture_ttl", "600")) or 600
  port = tonumber(port) or tonumber(uci_get("watchdog_happ_capture_port", "18088")) or 18088
  log_path = tostring(log_path or uci_get("watchdog_happ_capture_log", "/tmp/tproxy-manager-happ-capture.log"))
  if ttl < 1 then ttl = 600 end
  if port < 1 or port > 65535 then port = 18088 end
  capture_stop()
  local token = capture_token()
  if not token then
    io.stderr:write("unable to read enough randomness for a secure capture token\n")
    os.exit(1)
  end
  local until_ts = now() + ttl

  -- Everything that can refuse is checked BEFORE a single UCI value is staged.
  -- The old order committed enabled=1 first and only then validated the
  -- directories: a failure there left the capture marked active in the config
  -- with no server behind it, and the UI offered a URL that answered nothing.
  if not secure_lock_root() then
    io.stderr:write("refusing to start capture: unsafe lock directory " .. LOCK_ROOT .. "\n")
    os.exit(1)
  end
  exec_ok("mkdir -m 0700 " .. shellescape(CAPTURE_DIR) .. " >/dev/null 2>&1")
  if not exec_ok("[ -d " .. shellescape(CAPTURE_DIR) .. " ]") then
    io.stderr:write("refusing to start capture: could not prepare " .. CAPTURE_DIR .. "\n")
    os.exit(1)
  end

  -- Every result is checked, and a partial stage is reverted rather than left
  -- pending for someone else's commit to pick up.
  -- enabled=1 is deliberately NOT part of this stage; it is committed after the
  -- server is confirmed running (see below).
  local staged = uci_set("watchdog_happ_capture_token", token)
    and uci_set("watchdog_happ_capture_until", tostring(until_ts))
    and uci_set("watchdog_happ_capture_ttl", tostring(ttl))
    and uci_set("watchdog_happ_capture_port", tostring(port))
    and uci_set("watchdog_happ_capture_log", log_path)
  if not staged then
    uci_revert()
    io.stderr:write("could not stage the capture settings\n")
    os.exit(1)
  end
  if not uci_commit() then
    uci_revert()
    io.stderr:write("could not save the capture settings\n")
    os.exit(1)
  end
  local cmd = string.format("(%s capture-serve %s %s %s %s >%s 2>&1 </dev/null & echo $! >%s)",
    shellescape("/usr/bin/tproxy-manager-subscriptions.lua"),
    shellescape(token),
    shellescape(tostring(until_ts)),
    shellescape(tostring(port)),
    shellescape(log_path),
    shellescape(CAPTURE_OUT),
    shellescape(CAPTURE_PID))
  exec_ok(cmd)
  exec_ok("sleep 1")
  local pid = trim(read_file(CAPTURE_PID))
  if not pid:match("^%d+$") or not exec_ok("kill -0 " .. shellescape(pid) .. " >/dev/null 2>&1") then
    local out = trim(read_file(CAPTURE_OUT))
    local reason = out ~= "" and out or "capture service did not start"
    -- The flag was never set to 1 above (see the ordering comment there), but
    -- clear it explicitly in case an earlier run left it on, and say so if that
    -- fails: reporting only "did not start" would hide a live endpoint.
    local cleared, cerr = capture_disable()
    if not cleared then
      return false, reason .. "; " .. tostring(cerr)
    end
    return false, reason
  end

  -- enabled=1 is committed ONLY now, once the server is confirmed listening.
  -- Committing it before the spawn left a window in which the endpoint was
  -- active with nothing behind it.
  if not uci_set("watchdog_happ_capture_enabled", "1") or not uci_commit() then
    uci_revert()
    capture_stop()
    return false, "capture started but the enabled flag could not be saved"
  end
  print("TOKEN=" .. token)
  print("PORT=" .. tostring(port))
  print("UNTIL=" .. tostring(until_ts))
  return true, ""
end

local function command_capture_status()
  local pid = trim(read_file(CAPTURE_PID))
  local running = pid:match("^%d+$") and exec_ok("kill -0 " .. shellescape(pid) .. " >/dev/null 2>&1")
  print("CAPTURE_RUNNING=" .. (running and "1" or "0"))
  print("CAPTURE_PID=" .. (pid ~= "" and pid or "-"))
  print("CAPTURE_TOKEN=" .. uci_get("watchdog_happ_capture_token", ""))
  print("CAPTURE_UNTIL=" .. uci_get("watchdog_happ_capture_until", "0"))
  print("CAPTURE_PORT=" .. uci_get("watchdog_happ_capture_port", "18088"))
  print("CAPTURE_LOG=" .. uci_get("watchdog_happ_capture_log", "/tmp/tproxy-manager-happ-capture.log"))
end

local function usage()
  io.stderr:write([[
Usage:
  tproxy-manager-subscriptions.lua status
  tproxy-manager-subscriptions.lua fetch <id>
  tproxy-manager-subscriptions.lua fetch-all
  tproxy-manager-subscriptions.lua fetch-due
  tproxy-manager-subscriptions.lua sync-links
  tproxy-manager-subscriptions.lua exclude-link <hash>
  tproxy-manager-subscriptions.lua include-link <hash>
  tproxy-manager-subscriptions.lua capture-start [ttl] [port] [log]
  tproxy-manager-subscriptions.lua capture-stop
  tproxy-manager-subscriptions.lua capture-status
  tproxy-manager-subscriptions.lua capture-serve <token> <until_ts> <port> <log>
]])
end

math.randomseed(os.time())

local mode = arg[1] or "status"
local ok, detail
if mode == "status" then
  command_status()
  os.exit(0)
elseif mode == "fetch" then
  if not arg[2] then usage(); os.exit(1) end
  ok, detail = command_fetch(arg[2])
elseif mode == "fetch-all" then
  ok, detail = command_fetch_all()
elseif mode == "fetch-due" then
  ok, detail = command_fetch_due()
elseif mode == "sync-links" then
  ok, detail = command_sync_links()
elseif mode == "exclude-link" then
  if not arg[2] then usage(); os.exit(1) end
  ok, detail = command_exclude_link(arg[2])
elseif mode == "include-link" then
  if not arg[2] then usage(); os.exit(1) end
  ok, detail = command_include_link(arg[2])
elseif mode == "capture-start" then
  ok, detail = command_capture_start(arg[2], arg[3], arg[4])
elseif mode == "capture-stop" then
  capture_stop()
  local cleared, cerr = capture_disable()
  if cleared then
    ok, detail = true, "capture stopped"
  else
    -- The server is down but the endpoint is still marked enabled: saying
    -- "stopped" here is exactly the false success this reports on.
    ok, detail = false, tostring(cerr)
  end
elseif mode == "capture-status" then
  command_capture_status()
  os.exit(0)
elseif mode == "capture-serve" then
  if not arg[2] or not arg[3] or not arg[4] or not arg[5] then usage(); os.exit(1) end
  ok = capture_serve(arg[2], arg[3], arg[4], arg[5])
  os.exit(ok and 0 or 1)
elseif mode == "help" or mode == "-h" or mode == "--help" then
  usage()
  os.exit(0)
else
  usage()
  os.exit(1)
end

if detail and detail ~= "" then print(detail) end
os.exit(ok and 0 or 1)
