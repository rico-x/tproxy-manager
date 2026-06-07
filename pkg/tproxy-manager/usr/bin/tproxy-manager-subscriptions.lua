#!/usr/bin/lua

local jsonc = require "luci.jsonc"
local ok_nixio, nixio = pcall(require, "nixio")
local happ_decrypt = require "tproxy_manager.happ_decrypt"

local PKG = "tproxy-manager"
local DEFAULT_DB = "/etc/tproxy-manager/watchdog-subscriptions.json"
local DEFAULT_LINKS = "/etc/tproxy-manager/watchdog.links"
local LOCK_DIR = "/tmp/tproxy-manager-watchdog.lock"
local CAPTURE_PID = "/tmp/tproxy-manager-happ-capture.pid"
local CAPTURE_OUT = "/tmp/tproxy-manager-happ-capture.out"

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

local function ensure_dir(path)
  if path and path ~= "" then
    exec_ok("mkdir -p " .. shellescape(path) .. " >/dev/null 2>&1")
  end
end

local function write_file(path, data)
  local dir, base = tostring(path):match("^(.*)/([^/]+)$")
  if dir and dir ~= "" then ensure_dir(dir) end
  local tmp = string.format("%s/.%s.%d.%d.tmp", dir or ".", base or "tmp", os.time(), math.random(1, 1000000))
  local fh = assert(io.open(tmp, "wb"))
  fh:write(data or "")
  fh:close()
  assert(os.rename(tmp, path))
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
  local value = trim(line)
  if value == "" or value:match("^#") then return nil end
  local raw_link = value
  if value:find(" # ", 1, true) then
    raw_link = value:match("^(.-) # ") or value
  end
  raw_link = trim(raw_link)
  if not raw_link:match("^vless://") then return nil end
  return raw_link
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

local function add_vless_link(out, seen, link)
  link = trim(link)
  if not link:match("^vless://") then return end
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

local function extract_json_vless(node, out, seen)
  local function walk(value)
    if type(value) ~= "table" then return end
    if type(value.outbounds) == "table" then
      local vless_outbounds = {}
      for _, outbound in ipairs(value.outbounds) do
        if type(outbound) == "table" and outbound.protocol == "vless" then
          vless_outbounds[#vless_outbounds + 1] = outbound
        end
      end
      for _, outbound in ipairs(vless_outbounds) do
        local suffix = #vless_outbounds > 1 and value_or_empty(outbound.tag) or ""
        add_vless_link(out, seen, outbound_to_vless(value, outbound, suffix) or "")
      end
    else
      for _, child in pairs(value) do walk(child) end
    end
  end
  walk(node)
end

local function extract_vless_links(text)
  local out, seen = {}, {}
  local function add_from(source)
    source = tostring(source or "")
    for link in source:gmatch("(vless://[^%s\"'<>]+)") do
      add_vless_link(out, seen, link)
    end
    local ok, parsed = pcall(jsonc.parse, source)
    if ok and type(parsed) == "table" then
      extract_json_vless(parsed, out, seen)
    end
  end
  add_from(text)
  local decoded = base64_decode(text)
  if decoded then add_from(decoded) end
  return out
end

local function classify_subscription_response(text)
  if #extract_vless_links(text) > 0 then
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

local function fetch_url(sub, resolved_url)
  local body = string.format("/tmp/tproxy-manager-subscription.%d.%d.body", os.time(), math.random(1, 1000000))
  local err = body .. ".err"
  local parts = {
    "curl -L -sS",
    "-o", shellescape(body),
    "-w", shellescape("%{http_code}"),
    "--connect-timeout", "15",
    "--max-time", tostring(tonumber(sub.timeout) or 30),
  }
  for _, header in ipairs(header_list(sub)) do
    parts[#parts + 1] = "--header"
    parts[#parts + 1] = shellescape(header)
  end
  parts[#parts + 1] = shellescape(resolved_url or sub.url or "")
  local cmd = table.concat(parts, " ") .. " 2>" .. shellescape(err)
  local p = io.popen(cmd)
  local code = p and trim(p:read("*a") or "") or "000"
  if p then p:close() end
  local response = read_file(body)
  if response:byte(1) == 31 and response:byte(2) == 139 then
    local pz = io.popen("gzip -dc " .. shellescape(body) .. " 2>/dev/null")
    if pz then
      local decoded = pz:read("*a") or ""
      pz:close()
      if decoded ~= "" then response = decoded end
    end
  end
  local error_text = trim(read_file(err))
  os.remove(body)
  os.remove(err)
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
  local links = extract_vless_links(response)
  if #links == 0 then
    sub.last_status = "error"
    sub.last_error = "ответ не содержит валидных VLESS-ссылок"
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

local function acquire_lock()
  if exec_ok("mkdir " .. shellescape(LOCK_DIR) .. " >/dev/null 2>&1") then
    write_file(LOCK_DIR .. "/pid", current_pid() .. "\n")
    return true
  end
  local pid = trim(read_file(LOCK_DIR .. "/pid"))
  if pid:match("^%d+$") and not exec_ok("kill -0 " .. shellescape(pid) .. " >/dev/null 2>&1") then
    os.remove(LOCK_DIR .. "/pid")
    exec_ok("rmdir " .. shellescape(LOCK_DIR) .. " >/dev/null 2>&1")
    if exec_ok("mkdir " .. shellescape(LOCK_DIR) .. " >/dev/null 2>&1") then
      write_file(LOCK_DIR .. "/pid", current_pid() .. "\n")
      return true
    end
  end
  return false
end

local function release_lock()
  os.remove(LOCK_DIR .. "/pid")
  exec_ok("rmdir " .. shellescape(LOCK_DIR) .. " >/dev/null 2>&1")
end

local function with_lock(fn)
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
    save_db(db)
    if ok then sync_links_file(db) end
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
    save_db(db)
    if total > 0 then sync_links_file(db) end
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
      save_db(db)
      sync_links_file(db)
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
    save_db(db)
    sync_links_file(db)
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
    save_db(db)
    sync_links_file(db)
    return true, changed and "link included" or "link already included"
  end)
end

local function capture_token()
  return md5(tostring(now()) .. ":" .. tostring(math.random(1, 1000000000)) .. ":" .. current_pid())
end

local function capture_stop()
  local pid = trim(read_file(CAPTURE_PID))
  if pid:match("^%d+$") then
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
  while now() <= until_ts do
    local client = server:accept()
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
      if got_token == token then
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
  local until_ts = now() + ttl
  uci_set("watchdog_happ_capture_enabled", "1")
  uci_set("watchdog_happ_capture_token", token)
  uci_set("watchdog_happ_capture_until", tostring(until_ts))
  uci_set("watchdog_happ_capture_ttl", tostring(ttl))
  uci_set("watchdog_happ_capture_port", tostring(port))
  uci_set("watchdog_happ_capture_log", log_path)
  uci_commit()
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
    uci_set("watchdog_happ_capture_enabled", "0")
    uci_commit()
    local out = trim(read_file(CAPTURE_OUT))
    return false, out ~= "" and out or "capture service did not start"
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
  uci_set("watchdog_happ_capture_enabled", "0")
  uci_commit()
  ok, detail = true, "capture stopped"
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
