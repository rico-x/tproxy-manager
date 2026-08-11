local cbi = require "luci.cbi"
local SimpleSection, DummyValue = cbi.SimpleSection, cbi.DummyValue

local sys = require "luci.sys"
local http = require "luci.http"
local xml = require "luci.xml"
local jsonc = require "luci.jsonc"
local disp = require "luci.dispatcher"
local helpers = require "luci.model.cbi.tproxy_manager.modules.watchdog_helpers"
local utils = require "luci.model.cbi.tproxy_manager.utils"
local happ_decrypt = require "tproxy_manager.happ_decrypt"
local share = require "tproxy_manager.subscription_share"
local proxy_links = require "tproxy_manager.proxy_links"
local _ = require "luci.model.cbi.tproxy_manager.i18n"

local pcdata = xml.pcdata

local SUBSCRIPTIONS_SCRIPT = "/usr/bin/tproxy-manager-subscriptions.lua"
local WATCHDOG_LINK_STATE_DIR = "/tmp/tproxy-manager-watchdog-links"
local DEFAULT_SUBSCRIPTIONS_FILE = "/etc/tproxy-manager/watchdog-subscriptions.json"
local DEFAULT_CAPTURE_LOG = "/tmp/tproxy-manager-happ-capture.log"
local DEFAULT_SHARE_FILE = "/etc/tproxy-manager/watchdog-share.json"

local function read_file(path)
  return utils.read_file(path)
end

-- Returns the writer's result: callers now branch on it, and swallowing it
-- here made every checked save report a false failure while the file was
-- actually written.
local function write_file(path, data)
  return utils.write_file(path, data or "")
end

local function shellescape(s)
  return utils.shellescape(s)
end

local function trim(s)
  return utils.trim(s)
end

local function parse_int(v, fallback)
  if not v or not tostring(v):match("^%d+$") then return fallback end
  return tonumber(v)
end

local function urldecode_component(s)
  s = tostring(s or ""):gsub("+", " ")
  return (s:gsub("%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end))
end

local function parse_query(query)
  local out = {}
  for pair in (query or ""):gmatch("([^&]+)") do
    local k, v = pair:match("^([^=]+)=(.*)$")
    if k then
      out[urldecode_component(k)] = urldecode_component(v)
    else
      out[urldecode_component(pair)] = ""
    end
  end
  return out
end

local function run_cmd_capture(cmd)
  local marker = "__TPM_WD_RC__:"
  local wrapped = string.format("(%s) 2>&1; printf '\\n%s%%s' \"$?\"", cmd, marker)
  local out = sys.exec(wrapped) or ""
  local rc = tonumber(out:match(marker .. "([%-%d]+)%s*$")) or 1
  out = out:gsub("\n?" .. marker .. "[%-%d]+%s*$", "")
  return rc, trim(out)
end

-- lock_pid, when given, tells the script that this process already owns the
-- shared subscription lock, so it runs inside our transaction instead of
-- deadlocking while trying to take the same lock.
local function run_subscription_command(args, lock_pid)
  local parts = {}
  if lock_pid then
    parts[#parts + 1] = "TPM_SUBS_LOCK_PID=" .. shellescape(tostring(lock_pid))
  end
  parts[#parts + 1] = shellescape(SUBSCRIPTIONS_SCRIPT)
  for __, arg in ipairs(args or {}) do
    parts[#parts + 1] = shellescape(arg)
  end
  return run_cmd_capture(table.concat(parts, " "))
end

local function default_subscription_db()
  return {
    version = 1,
    next_id = 1,
    subscriptions = {},
    links = {},
    excluded = {},
    removed = {},
  }
end

local function normalize_subscription_db(db)
  if type(db) ~= "table" then db = default_subscription_db() end
  db.version = tonumber(db.version) or 1
  db.next_id = tonumber(db.next_id) or 1
  if type(db.subscriptions) ~= "table" then db.subscriptions = {} end
  if type(db.links) ~= "table" then db.links = {} end
  if type(db.excluded) ~= "table" then db.excluded = {} end
  if type(db.removed) ~= "table" then db.removed = {} end
  return db
end

local function read_subscription_db(path)
  local raw = read_file(path)
  if raw == "" then return default_subscription_db() end
  local ok, parsed = pcall(jsonc.parse, raw)
  if not ok or type(parsed) ~= "table" then return default_subscription_db() end
  return normalize_subscription_db(parsed)
end

-- Returns the writer's tri-state so callers can distinguish "not written"
-- from "written but mode not set" instead of always claiming success.
local function write_subscription_db(path, db)
  return write_file(path, jsonc.stringify(normalize_subscription_db(db), true) .. "\n")
end

local function next_subscription_id(db)
  local id = tonumber(db.next_id) or 1
  local max_id = 0
  for __, sub in ipairs(db.subscriptions or {}) do
    local sub_id = tonumber(sub.id) or 0
    if sub_id > max_id then max_id = sub_id end
  end
  if id <= max_id then id = max_id + 1 end
  db.next_id = id + 1
  return id
end

local function find_subscription(db, id)
  id = tonumber(id)
  if not id then return nil, nil end
  for idx, sub in ipairs(db.subscriptions or {}) do
    if tonumber(sub.id) == id then return sub, idx end
  end
  return nil, nil
end

local function subscription_source_key(sub)
  return tostring(sub.type or "happ") .. ":" .. tostring(sub.id)
end

local function remove_subscription_sources(db, sub)
  local skey = subscription_source_key(sub)
  for hash, item in pairs(db.links or {}) do
    if type(item) == "table" and type(item.sources) == "table" and item.sources[skey] then
      item.sources[skey] = nil
      db.excluded[skey .. "|" .. hash] = nil
      local has_source = false
      for __ in pairs(item.sources) do has_source = true; break end
      if not has_source then
        db.links[hash] = nil
        db.removed[hash] = os.time()
      end
    end
  end
end

local function subscription_source_entries_for_hash(db, hash)
  local item = db.links and db.links[hash]
  local entries = {}
  if type(item) == "table" and type(item.sources) == "table" then
    for skey, source in pairs(item.sources) do
      local typ = tostring(source.type or "happ")
      local id = tostring(source.id or "")
      entries[#entries + 1] = {
        key = skey,
        label = trim((source.label and tostring(source.label) ~= "" and source.label) or (typ .. " " .. id)),
        excluded = db.excluded and db.excluded[skey .. "|" .. hash] ~= nil
      }
    end
  end
  table.sort(entries, function(a, b) return tostring(a.label) < tostring(b.label) end)
  return entries
end

local function subscription_sources_for_hash(db, hash)
  local entries = subscription_source_entries_for_hash(db, hash)
  local labels = {}
  for __, source in ipairs(entries) do
    labels[#labels + 1] = source.label
  end
  table.sort(labels)
  return labels
end

local function is_subscription_link(db, hash)
  return #subscription_sources_for_hash(db, hash) > 0
end

local function is_subscription_link_excluded(db, hash)
  local entries = subscription_source_entries_for_hash(db, hash)
  if #entries == 0 then return false end
  for __, source in ipairs(entries) do
    if not source.excluded then return false end
  end
  return true
end

local function source_badges(db, hash)
  local entries = subscription_source_entries_for_hash(db, hash)
  if #entries == 0 then return "<span class='svc-badge'>local</span>", false end
  local out = {}
  for __, source in ipairs(entries) do
    local class = source.excluded and "svc-badge" or "svc-badge ok"
    out[#out + 1] = "<span class='" .. class .. "'>" .. pcdata(source.label) .. "</span>"
  end
  if is_subscription_link_excluded(db, hash) then
    out[#out + 1] = "<span class='svc-badge'>" .. _("Excluded") .. "</span>"
  end
  return table.concat(out, " "), true
end

local TEMPLATE_CHOICES = {
  {
    id = "vless_outbound",
    key = "watchdog_template_file",
    label = "VLESS outbound template",
    fallback = "/etc/tproxy-manager/watchdog-outbound.template.jsonc"
  },
  {
    id = "vless_test",
    key = "watchdog_test_template_file",
    label = "VLESS test template",
    fallback = "/etc/tproxy-manager/watchdog-test-config.template.jsonc"
  },
  {
    id = "vless_batch",
    key = "watchdog_batch_test_template_file",
    label = "VLESS batch test template",
    fallback = "/etc/tproxy-manager/watchdog-batch-test-config.template.jsonc"
  },
  {
    id = "hy2_outbound",
    key = "watchdog_hysteria_template_file",
    label = "Hysteria 2 outbound template",
    fallback = "/etc/tproxy-manager/watchdog-hysteria-outbound.template.jsonc"
  },
  {
    id = "hy2_test",
    key = "watchdog_hysteria_test_template_file",
    label = "Hysteria 2 test template",
    fallback = "/etc/tproxy-manager/watchdog-hysteria-test-config.template.jsonc"
  },
  {
    id = "hy2_batch",
    key = "watchdog_hysteria_batch_test_template_file",
    label = "Hysteria 2 batch test template",
    fallback = "/etc/tproxy-manager/watchdog-hysteria-batch-test-config.template.jsonc"
  }
}

local function template_choice_by_id(id)
  id = trim(id)
  for __, choice in ipairs(TEMPLATE_CHOICES) do
    if choice.id == id then return choice end
  end
  return TEMPLATE_CHOICES[1]
end

local function active_source_text(db, entry)
  if not entry then return "-" end
  local labels = subscription_sources_for_hash(db, entry.hash)
  local source = #labels > 0 and table.concat(labels, ", ") or "local"
  local comment = trim(entry.comment or "")
  local hash = tostring(entry.hash or "")
  local short_hash = hash ~= "" and hash:sub(1, 8) or "-"
  if comment ~= "" then
    return string.format("%s · %s · %s", source, comment, short_hash)
  end
  return string.format("%s · %s", source, short_hash)
end

local function vless_signature(raw_link)
  raw_link = trim(raw_link)
  local scheme = proxy_links.scheme(raw_link)
  if scheme == "hysteria2" or scheme == "hy2" then
    local without_fragment = raw_link:gsub("#.*$", "")
    local base, query = without_fragment, ""
    if without_fragment:find("?", 1, true) then
      base = without_fragment:match("^(.-)%?") or without_fragment
      query = without_fragment:match("%?(.*)$") or ""
    end
    local _, body = base:match("^([A-Za-z][A-Za-z0-9+.-]*)://(.+)$")
    local authority = (body or ""):gsub("/.*$", "")
    local userinfo, hostport = authority:match("^(.-)@(.+)$")
    if not hostport then
      userinfo = ""
      hostport = authority
    end
    local address, port
    if hostport:match("^%[") then
      address, port = hostport:match("^%[([^%]]+)%]:(%d+)")
      if not address then
        address = hostport:match("^%[([^%]]+)%]$")
        port = "443"
      end
    else
      address, port = hostport:match("^([^:]+):(%d+)")
      if not address then
        address = hostport
        port = "443"
      end
    end
    local params = parse_query(query)
    return {
      protocol = "hy2",
      auth = trim(urldecode_component(userinfo or "")),
      address = trim(address or ""),
      port = tostring(port or "443"),
      server_name = trim(params.sni or "")
    }
  end
  local without_fragment = raw_link:gsub("#.*$", "")
  local base, query = without_fragment, ""
  if without_fragment:find("?", 1, true) then
    base = without_fragment:match("^(.-)%?") or without_fragment
    query = without_fragment:match("%?(.*)$") or ""
  end
  local auth = base:match("^vless://(.+)$")
  if not auth then return nil end
  local uuid, hostport = auth:match("^(.-)@(.+)$")
  if not uuid or not hostport then return nil end
  local address, port
  if hostport:match("^%[") then
    address, port = hostport:match("^%[([^%]]+)%]:(%d+)$")
  else
    address, port = hostport:match("^([^:]+):(%d+)$")
  end
  if not address or not port then return nil end
  local params = parse_query(query)
  return {
    protocol = "vless",
    uuid = trim(uuid),
    address = trim(address),
    port = tostring(port),
    public_key = trim(params.pbk ~= "" and params.pbk or params.publicKey or ""),
    short_id = trim(params.sid ~= "" and params.sid or params.shortId or ""),
    server_name = trim(params.sni ~= "" and params.sni or params.serverName or params.host or "")
  }
end

local function config_contains_signature(config_text, sig)
  if not sig or config_text == "" then return false end
  if sig.address == "" or sig.port == "" then return false end
  if not config_text:find(sig.address, 1, true) then return false end
  if not config_text:find(sig.port, 1, true) then return false end
  if sig.protocol == "hy2" then
    if sig.auth ~= "" and not config_text:find(sig.auth, 1, true) then return false end
    if sig.server_name ~= "" and not config_text:find(sig.server_name, 1, true) then return false end
    return true
  end
  if sig.uuid == "" or not config_text:find(sig.uuid, 1, true) then return false end
  local strong = 0
  if sig.public_key ~= "" and config_text:find(sig.public_key, 1, true) then strong = strong + 1 end
  if sig.short_id ~= "" and config_text:find(sig.short_id, 1, true) then strong = strong + 1 end
  if sig.server_name ~= "" and config_text:find(sig.server_name, 1, true) then strong = strong + 1 end
  return strong > 0 or (sig.public_key == "" and sig.short_id == "" and sig.server_name == "")
end

local function first_proxy_outbound(config_text)
  local ok, parsed = pcall(jsonc.parse, config_text)
  if not ok or type(parsed) ~= "table" then return nil end
  local outbounds = parsed.outbounds
  if type(outbounds) ~= "table" then return nil end
  for __, outbound in ipairs(outbounds) do
    if type(outbound) == "table" and tostring(outbound.tag or "") == "proxy" then
      return outbound
    end
  end
  return type(outbounds[1]) == "table" and outbounds[1] or nil
end

local function outbound_value_signature(outbound)
  if type(outbound) ~= "table" then return nil end
  local protocol = trim(outbound.protocol or "")
  local settings = type(outbound.settings) == "table" and outbound.settings or {}
  local stream = type(outbound.streamSettings) == "table" and outbound.streamSettings or {}

  if protocol == "hysteria" then
    local hysteria = type(stream.hysteriaSettings) == "table" and stream.hysteriaSettings or {}
    local tls = type(stream.tlsSettings) == "table" and stream.tlsSettings or {}
    return {
      protocol = "hy2",
      address = trim(settings.address or ""),
      port = tostring(settings.port or ""),
      auth = trim(hysteria.auth or settings.auth or ""),
      server_name = trim(tls.serverName or "")
    }
  end

  if protocol == "vless" then
    local vnext = type(settings.vnext) == "table" and settings.vnext[1] or nil
    if type(vnext) ~= "table" then return nil end
    local user = type(vnext.users) == "table" and vnext.users[1] or nil
    user = type(user) == "table" and user or {}
    local reality = type(stream.realitySettings) == "table" and stream.realitySettings or {}
    local tls = type(stream.tlsSettings) == "table" and stream.tlsSettings or {}
    return {
      protocol = "vless",
      address = trim(vnext.address or ""),
      port = tostring(vnext.port or ""),
      uuid = trim(user.id or ""),
      public_key = trim(reality.publicKey or ""),
      short_id = trim(reality.shortId or ""),
      server_name = trim(reality.serverName or tls.serverName or "")
    }
  end

  return nil
end

local function signatures_match(active, candidate)
  if not active or not candidate then return false end
  if active.protocol ~= candidate.protocol then return false end
  if active.address == "" or candidate.address == "" or active.address ~= candidate.address then return false end
  if active.port == "" or candidate.port == "" or active.port ~= candidate.port then return false end

  if active.protocol == "hy2" then
    if active.auth ~= "" and candidate.auth ~= "" and active.auth ~= candidate.auth then return false end
    if active.server_name ~= "" and candidate.server_name ~= "" and active.server_name ~= candidate.server_name then return false end
    return true
  end

  if active.uuid == "" or candidate.uuid == "" or active.uuid ~= candidate.uuid then return false end
  if active.public_key ~= "" and candidate.public_key ~= "" and active.public_key ~= candidate.public_key then return false end
  if active.short_id ~= "" and candidate.short_id ~= "" and active.short_id ~= candidate.short_id then return false end
  if active.server_name ~= "" and candidate.server_name ~= "" and active.server_name ~= candidate.server_name then return false end
  return true
end

local function find_active_entry(links, status)
  local outbound_file = trim(status.OUTBOUND_FILE or "")
  if outbound_file ~= "" then
    local config_text = read_file(outbound_file)
    if config_text ~= "" then
      local active_sig = outbound_value_signature(first_proxy_outbound(config_text))
      if active_sig then
        for __, entry in ipairs(links or {}) do
          if signatures_match(active_sig, vless_signature(entry.raw_link or entry.link or "")) then
            return entry, "config"
          end
        end
      else
        for __, entry in ipairs(links or {}) do
          if config_contains_signature(config_text, vless_signature(entry.raw_link or entry.link or "")) then
            return entry, "config"
          end
        end
      end
    end
  end

  local applied_hash = trim(status.LAST_APPLIED_HASH or "")
  if applied_hash ~= "" then
    for __, entry in ipairs(links or {}) do
      if entry.hash == applied_hash then
        return entry, "state"
      end
    end
  end
  return nil, ""
end

local function parse_capture_headers(path)
  local headers = {}
  local raw = read_file(path)
  local in_headers = false
  local aliases = {
    ["user-agent"] = "User-Agent",
    ["accept-encoding"] = "Accept-Encoding",
    ["connection"] = "Connection",
    ["x-device-os"] = "X-Device-Os",
    ["x-device-locale"] = "X-Device-Locale",
    ["x-device-model"] = "X-Device-Model",
    ["x-ver-os"] = "X-Ver-Os",
    ["x-hwid"] = "X-Hwid",
    ["x-real-ip"] = "X-Real-Ip",
    ["x-forwarded-for"] = "X-Forwarded-For",
  }
  for line in (raw .. "\n"):gmatch("([^\n]*)\n") do
    line = trim(line)
    if line == "HTTP HEADERS:" then
      in_headers = true
    elseif line == "REQUEST BODY:" then
      break
    elseif in_headers and line ~= "" then
      local name, value = line:match("^([^:]+):%s*(.*)$")
      if name and value then
        local key = aliases[trim(name):lower()] or trim(name)
        headers[key] = value
      end
    end
  end
  return headers
end

local function capture_url(token, port)
  if token == "" then return "" end
  local host = http.getenv("HTTP_HOST") or "192.168.1.1"
  host = host:gsub(":%d+$", "")
  port = tostring(port or "18088")
  return "http://" .. host .. ":" .. port .. "/" .. token
end

local function public_luci_url(...)
  local scheme = trim(http.getenv("REQUEST_SCHEME"))
  if scheme ~= "http" and scheme ~= "https" then
    scheme = http.getenv("HTTPS") == "on" and "https" or "http"
  end
  local host = http.getenv("HTTP_HOST") or "192.168.1.1"
  return scheme .. "://" .. host .. disp.build_url(...)
end

local function subscription_enabled(sub)
  return sub.enabled == true or sub.enabled == "1" or sub.enabled == 1
end

local function default_happ_headers(captured)
  captured = captured or {}
  return {
    ["User-Agent"] = captured["User-Agent"] or "Happ/3.13.0",
    ["X-Device-Os"] = captured["X-Device-Os"] or "Android",
    ["X-Device-Locale"] = captured["X-Device-Locale"] or "ru",
    ["X-Device-Model"] = captured["X-Device-Model"] or "ELP-NX1",
    ["X-Ver-Os"] = captured["X-Ver-Os"] or "15",
    ["Accept-Encoding"] = captured["Accept-Encoding"] or "gzip",
    ["Connection"] = captured["Connection"] or "close",
    ["X-Hwid"] = captured["X-Hwid"] or "",
    ["X-Real-Ip"] = captured["X-Real-Ip"] or "",
    ["X-Forwarded-For"] = captured["X-Forwarded-For"] or "",
  }
end

local function collect_subscription_form(existing)
  existing = existing or {}
  local typ = trim(http.formvalue("sub_type"))
  if typ ~= "happ" and typ ~= "json" then typ = "happ" end
  return {
    id = tonumber(http.formvalue("sub_id")) or existing.id,
    type = typ,
    name = trim(http.formvalue("sub_name")),
    enabled = http.formvalue("sub_enabled") and true or false,
    url = trim(http.formvalue("sub_url")),
    timeout = parse_int(http.formvalue("sub_timeout"), 30),
    refresh_interval = parse_int(http.formvalue("sub_refresh_interval"), 10800),
    headers = {
      ["User-Agent"] = trim(http.formvalue("sub_h_user_agent")),
      ["X-Device-Os"] = trim(http.formvalue("sub_h_device_os")),
      ["X-Device-Locale"] = trim(http.formvalue("sub_h_device_locale")),
      ["X-Device-Model"] = trim(http.formvalue("sub_h_device_model")),
      ["X-Ver-Os"] = trim(http.formvalue("sub_h_ver_os")),
      ["Accept-Encoding"] = trim(http.formvalue("sub_h_accept_encoding")),
      ["Connection"] = trim(http.formvalue("sub_h_connection")),
      ["X-Hwid"] = trim(http.formvalue("sub_h_hwid")),
      ["X-Real-Ip"] = trim(http.formvalue("sub_h_real_ip")),
      ["X-Forwarded-For"] = trim(http.formvalue("sub_h_forwarded_for")),
    },
    extra_headers = trim(http.formvalue("sub_extra_headers")),
    last_update = existing.last_update,
    last_update_human = existing.last_update_human,
    last_status = existing.last_status,
    last_error = existing.last_error,
    last_count = existing.last_count,
    last_response_type = existing.last_response_type,
  }
end

local function merge_excluded_subscription_links(entries, db)
  local seen, extra = {}, {}
  for __, entry in ipairs(entries or {}) do
    if entry.hash and entry.hash ~= "" then seen[entry.hash] = true end
  end
  for hash, item in pairs(db.links or {}) do
    if not seen[hash] and is_subscription_link_excluded(db, hash) and type(item) == "table" and trim(item.raw_link or "") ~= "" then
      local parsed = helpers.parse_link_line(item.raw_link)
      if parsed then
        local state = utils.parse_kv_text(read_file(WATCHDOG_LINK_STATE_DIR .. "/" .. hash .. ".state"))
        local labels = subscription_sources_for_hash(db, hash)
        extra[#extra + 1] = {
          index = #entries + #extra + 1,
          hash = hash,
          raw_link = parsed.raw_link,
          link = parsed.display_link,
          comment = parsed.comment,
          state = state,
          excluded = true,
          sort_key = table.concat(labels, ",") .. "|" .. (parsed.comment or "") .. "|" .. hash
        }
      end
    end
  end
  table.sort(extra, function(a, b) return tostring(a.sort_key) < tostring(b.sort_key) end)
  for __, entry in ipairs(extra) do
    entry.sort_key = nil
    entries[#entries + 1] = entry
  end
  return entries
end

local function render(ctx)
  local m = ctx.m
  local uci = ctx.uci
  local PKG = ctx.PKG
  local service_block = ctx.service_block
  local set_err, set_info = ctx.set_err, ctx.set_info

  local function getu(k, def)
    local v = uci:get(PKG, "main", k)
    if v ~= nil and v ~= false and v ~= "" then return v end

    local out = sys.exec("uci -q get " .. shellescape(PKG .. ".main." .. k) .. " 2>/dev/null") or ""
    out = trim(out)
    if out ~= "" then return out end

    if v == nil or v == false or v == "" then return def or "" end
    return v
  end

  local links_path = getu("watchdog_links_file", "/etc/tproxy-manager/watchdog.links")
  local subscriptions_path = getu("watchdog_subscriptions_file", DEFAULT_SUBSCRIPTIONS_FILE)
  local share_file = getu("watchdog_share_file", DEFAULT_SHARE_FILE)
  local capture_log = getu("watchdog_happ_capture_log", DEFAULT_CAPTURE_LOG)
  local capture_defaults = nil
  local show_capture_details = false
  local happ_decrypt_input = http.formvalue("happ_decrypt_input") or ""
  local happ_decrypt_output = ""
  local happ_decrypt_open = false

  math.randomseed(os.time())

  if http.formvalue("_happ_decrypt_clear") == "1" then
    happ_decrypt_input = ""
    happ_decrypt_output = ""
    happ_decrypt_open = true
  elseif http.formvalue("_happ_decrypt_run") == "1" then
    happ_decrypt_input = tostring(happ_decrypt_input or ""):gsub("\r\n", "\n")
    happ_decrypt_output = happ_decrypt.decrypt_lines(happ_decrypt_input)
    if happ_decrypt_output == "" then
      happ_decrypt_output = _("Error: no data to decrypt")
    end
    happ_decrypt_open = true
  end

  if http.formvalue("_sub_start_capture") == "1" then
    local ttl = parse_int(http.formvalue("happ_capture_start_ttl"), parse_int(getu("watchdog_happ_capture_ttl", "600"), 600))
    if ttl < 1 then ttl = 600 end
    local port = parse_int(http.formvalue("happ_capture_start_port"), parse_int(getu("watchdog_happ_capture_port", "18088"), 18088))
    if port < 1 or port > 65535 then port = 18088 end
    local form_capture_log = trim(http.formvalue("happ_capture_start_log"))
    if form_capture_log ~= "" then
      if not utils.is_abs_path(form_capture_log) then
        set_err(_("Capture log path must be absolute."))
        helpers.redirect_watchdog()
        return m
      end
      capture_log = form_capture_log
    end
    local rc, out = run_subscription_command({ "capture-start", tostring(ttl), tostring(port), capture_log })
    if rc == 0 then
      set_err(nil)
      set_info(_("Happ capture enabled. Copy the link from the subscriptions block and open it from the phone.") .. "\n" .. out)
    else
      set_err(out ~= "" and out or _("Failed to start Happ capture."))
    end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_sub_stop_capture") == "1" then
    local rc, out = run_subscription_command({ "capture-stop" })
    if rc == 0 then
      set_err(nil)
      set_info(out ~= "" and out or _("Happ capture disabled."))
    else
      set_err(out ~= "" and out or _("Failed to stop Happ capture."))
    end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_sub_fill_happ_capture") == "1" then
    capture_defaults = parse_capture_headers(capture_log)
    show_capture_details = true
    if next(capture_defaults) then
      set_err(nil)
      set_info(_("Happ fields were filled from the last capture request. Check the subscription URL and save the subscription."))
    else
      set_err(_("Capture log does not contain saved headers."))
    end
  end

  if http.formvalue("_sub_show_capture") == "1" then
    show_capture_details = true
  end

  -- A share token guards real proxy credentials, so it must come from a
  -- CSPRNG. There is deliberately NO math.random fallback: a predictable
  -- token would look identical to a strong one in the UI while being
  -- brute-forceable, so failing to read 32 bytes from /dev/urandom aborts
  -- the operation instead of silently downgrading the guarantee.
  -- Returns nil on failure; every caller must handle that.
  local function generate_share_token()
    local fh = io.open("/dev/urandom", "rb")
    if not fh then return nil end
    local raw = fh:read(32)
    fh:close()
    if not raw or #raw ~= 32 then return nil end
    return (raw:gsub(".", function(c) return string.format("%02x", c:byte()) end))
  end

  -- save_uci_and_file: one checked transaction for the "set a path in UCI +
  -- write that file" pattern used by the template and links editors. All
  -- three results (uci:set, file write, commit) used to be discarded and the
  -- UI reported success unconditionally.
  -- Returns true on success, or false plus a message.
  local function save_uci_and_file(key, path, text, ok_message)
    -- On-disk snapshot, like every other transaction here: the in-memory copy
    -- this used to hold died with the request, so a CGI killed between the file
    -- write and the commit left the previous template nowhere at all.
    local store, serr = utils.snapshot_begin("tmpl")
    if store then
      local ok_s, aerr = utils.snapshot_add(store, path)
      if not ok_s then serr = aerr; utils.snapshot_discard(store); store = nil end
    end
    if not store then
      return false, _("Failed to save settings.") .. "\n" ..
        string.format(_("Could not create a rollback snapshot: %s"), tostring(serr or "unknown error"))
    end

    if not utils.uci_stage(uci, PKG, "main", key, path) then
      uci:revert(PKG)
      utils.snapshot_discard(store)
      return false, _("Failed to save settings.")
    end

    -- Armed before the first live write: from here on a crash must leave the
    -- snapshot behind instead of having it swept as harmless.
    local armed, aerr = utils.snapshot_arm(store)
    if not armed then
      uci:revert(PKG)
      utils.snapshot_discard(store)
      return false, _("Failed to save settings.") .. "\n" ..
        string.format(_("Could not create a rollback snapshot: %s"), tostring(aerr or ""))
    end

    local wrote, wwhy = write_file(path, text)
    if not wrote and wwhy ~= "permissions" then
      -- The file was NOT replaced, so undoing the staged UCI is correct.
      uci:revert(PKG)
      utils.snapshot_discard(store)
      return false, _("Failed to save settings.")
    end

    local ok_commit, why = utils.commit_uci(uci, PKG)
    if not ok_commit and why == "commit" then
      uci:revert(PKG)
      -- Restoring the previous file is itself checked: silently failing here
      -- would leave the new content on disk under the old configuration.
      local failed = utils.snapshot_restore(store)
      if #failed > 0 then
        local msg = _("Failed to save settings, and the previous file could not be restored:").." " .. path
        if failed[1].state == "permissions" then
          msg = _("Failed to save settings; the previous file was restored but its permissions could not be secured:").." " .. path
        else
          local kept = utils.snapshot_keep(store)
          if kept then
            msg = msg .. "\n" .. string.format(_("The previous contents are kept here: %s"), kept)
          end
        end
        if failed[1].state == "permissions" then utils.snapshot_discard(store) end
        return false, msg
      end
      utils.snapshot_discard(store)
      return false, _("Failed to save settings.")
    end

    utils.snapshot_discard(store)
    if not wrote and wwhy == "permissions" then
      return false, _("Settings saved, but the configuration file permissions could not be secured.")
    end
    if not ok_commit then
      -- Committed, only the chmod failed: the save stands, report the
      -- permissions problem rather than pretending nothing happened.
      return false, _("Settings saved, but the configuration file permissions could not be secured.")
    end
    return true, ok_message
  end

  -- share_rollback: put the shared JSON back from its on-disk snapshot and
  -- turn the outcome into a message. The snapshot directory is kept only when
  -- the file could NOT be restored - it is then the only copy left.
  local function share_rollback(store, path)
    local failed = utils.snapshot_restore(store)
    if #failed == 0 then
      utils.snapshot_discard(store)
      return _("Failed to save shared subscription settings.")
    end
    local f = failed[1]
    if f.state == "permissions" then
      utils.snapshot_discard(store)
      return _("Failed to save shared subscription settings; the previous file was restored but its permissions could not be secured:").." " .. path
    end
    return _("Failed to save shared subscription settings, and the previous file could not be restored:").." " .. path ..
      "\n" .. string.format(_("The previous contents are kept here: %s"), utils.snapshot_keep(store) or store.dir)
  end

  -- report_links_write: single place that turns write_links_file's tri-state
  -- into a message. Every link mutation used to discard the result and show
  -- "Link added/updated/deleted" even when nothing reached the disk.
  local function report_links_write(wrote, wwhy, ok_message)
    if wrote then
      set_err(nil); set_info(ok_message)
    elseif wwhy == "permissions" then
      set_info(nil)
      set_err(_("Settings saved, but the configuration file permissions could not be secured."))
    else
      set_info(nil)
      set_err(_("Failed to save settings."))
    end
  end

  if http.formvalue("_share_rotate_token") == "1" then
    -- An old token is invalidated the moment a new one is saved, so any URL
    -- shared before the rotation stops working immediately.
    local new_token = generate_share_token()
    if not new_token then
      set_info(nil)
      set_err(_("Could not read enough randomness to generate a secure token."))
      helpers.redirect_watchdog()
      return m
    end
    -- Checked: committing a set that never landed would persist a
    -- half-formed configuration and report success.
    if not uci:set(PKG, "main", "watchdog_share_token", new_token) then
      uci:revert(PKG)
      set_info(nil)
      set_err(_("Failed to save the new token."))
      helpers.redirect_watchdog()
      return m
    end
    local committed, why = utils.commit_uci(uci, PKG)
    if committed then
      set_err(nil)
      set_info(_("Shared subscription token rotated. Update it on any client using the old link."))
    elseif why == "permissions" then
      set_info(nil)
      set_err(_("Settings saved, but the configuration file permissions could not be secured."))
    else
      set_info(nil)
      set_err(_("Failed to save the new token."))
    end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_share_save") == "1" then
    local mode = trim(http.formvalue("share_selection_mode"))
    local path = trim(http.formvalue("watchdog_share_file"))
    -- Anything that is not an explicit "public" is treated as token auth, the
    -- same way the endpoint decides. Defaulting the other way round is how an
    -- unset value ended up serving the list to anyone.
    local auth_mode = trim(http.formvalue("watchdog_share_auth_mode"))
    if auth_mode ~= "public" then auth_mode = "token" end
    local current_cfg = share.read_config(path ~= "" and path or share_file)
    local selected = current_cfg.selected or {}
    if mode ~= "selected" then mode = "all" end
    if path == "" then
      set_err(_("Shared subscription file path is required."))
    elseif not utils.is_abs_path(path) then
      set_err(_("Shared subscription file path must be absolute."))
    else
      if mode == "selected" then
        selected = {}
        local allowed = {}
        for __, entry in ipairs(helpers.parse_links_file(links_path)) do
          if entry.hash and entry.hash ~= "" then allowed[entry.hash] = true end
        end
        local values = http.formvalue("share_selected_hash")
        if type(values) ~= "table" then values = values and { values } or {} end
        for __, hash in ipairs(values) do
          hash = trim(hash):lower()
          if allowed[hash] then selected[hash] = true end
        end
      end
      -- Transactional: the JSON file and UCI must move together.
      -- The token is generated FIRST: if entropy is unavailable we must
      -- fail before the JSON is rewritten, otherwise disk would already
      -- hold the new config while the operation reports failure.
      local pending_token = nil
      if auth_mode == "token" and trim(getu("watchdog_share_token", "")) == "" then
        pending_token = generate_share_token()
        if not pending_token then
          set_info(nil)
          set_err(_("Could not read enough randomness to generate a secure token."))
          helpers.redirect_watchdog()
          return m
        end
      end
      -- Existence is captured with stat, not by content: an existing but
      -- EMPTY file must be restored as an empty file rather than deleted on
      -- rollback. The mode travels with it so a rollback cannot silently
      -- loosen the permissions of a file holding proxy links.
      local share_store, share_serr = utils.snapshot_begin("share")
      if share_store then
        local ok_s, aerr = utils.snapshot_add(share_store, path)
        if not ok_s then share_serr = aerr; utils.snapshot_discard(share_store); share_store = nil end
      end
      if not share_store then
        set_info(nil)
        set_err(_("Failed to save shared subscription settings.") .. "\n" ..
          string.format(_("Could not create a rollback snapshot: %s"), tostring(share_serr or "")))
        helpers.redirect_watchdog()
        return m
      end
      local share_armed, share_aerr = utils.snapshot_arm(share_store)
      if not share_armed then
        utils.snapshot_discard(share_store)
        set_info(nil)
        set_err(_("Failed to save shared subscription settings.") .. "\n" ..
          string.format(_("Could not create a rollback snapshot: %s"), tostring(share_aerr or "")))
        helpers.redirect_watchdog()
        return m
      end
      local saved, save_why = share.write_config(path, {
        version = 1,
        selection_mode = mode,
        selected = selected,
      })
      -- "permissions" means the JSON IS on disk - only chmod failed. Aborting
      -- here used to leave the new file in place while reporting failure and
      -- rolling nothing back, so UCI and disk drifted apart. The transaction
      -- continues and the warning is carried to the final message.
      local share_perm_warning = false
      if not saved then
        if save_why ~= "permissions" then
          utils.snapshot_discard(share_store)
          set_info(nil)
          set_err(_("Failed to save shared subscription settings."))
          helpers.redirect_watchdog()
          return m
        end
        share_perm_warning = true
      end
      -- Every staged set is checked: a failure here must undo the JSON
      -- write too, otherwise disk and UCI drift apart.
      local staged =
        utils.uci_stage(uci, PKG, "main", "watchdog_share_enabled", http.formvalue("watchdog_share_enabled") and "1" or "0")
        and utils.uci_stage(uci, PKG, "main", "watchdog_share_file", path)
        and utils.uci_stage(uci, PKG, "main", "watchdog_share_auth_mode", auth_mode)
      if not staged then
        uci:revert(PKG)
        set_info(nil)
        set_err(share_rollback(share_store, path))
        helpers.redirect_watchdog()
        return m
      end
      -- Switching into token mode with no token yet would otherwise leave
      -- the feature silently non-functional (every URL 404s) until the
      -- user notices and clicks "Generate / rotate token" separately.
      -- Uses the token generated BEFORE the JSON was rewritten. Generating
      -- it again here would defeat that ordering: a second /dev/urandom
      -- read could fail after the file is already on disk, leaving the new
      -- config committed to disk while the operation reports failure.
      if pending_token then
        if not utils.uci_stage(uci, PKG, "main", "watchdog_share_token", pending_token) then
          uci:revert(PKG)
          set_info(nil)
          set_err(share_rollback(share_store, path))
          helpers.redirect_watchdog()
          return m
        end
      end
      local committed, why = utils.commit_uci(uci, PKG)
      if committed and not share_perm_warning then
        utils.snapshot_discard(share_store)
        set_err(nil)
        set_info(_("Shared subscription settings saved."))
      elseif committed or why == "permissions" then
        -- UCI is already durable here: rolling the JSON back would be the
        -- corrupting move, not the safe one. Report the real problem, and
        -- name the shared file when it is the one left unsecured.
        utils.snapshot_discard(share_store)
        set_info(nil)
        if share_perm_warning then
          set_err(_("Shared subscription settings saved, but the file permissions could not be secured:").." " .. path)
        else
          set_err(_("Settings saved, but the configuration file permissions could not be secured."))
        end
      else
        -- Not committed - roll the JSON back so file and UCI cannot drift
        -- apart, and report if THAT failed too.
        uci:revert(PKG)
        set_info(nil)
        set_err(share_rollback(share_store, path))
      end
      helpers.redirect_watchdog()
      return m
    end
  end

  -- rollback_incomplete_message: one wording for every transaction that could
  -- not undo itself, and it always names the kept snapshot directory — that
  -- directory is the only remaining copy of the previous state.
  local function rollback_incomplete_message(head, failed, store)
    local names = {}
    for __, f in ipairs(failed) do
      names[#names + 1] = f.path .. (f.state == "permissions" and " (mode)" or "")
    end
    local msg = head .. "\n" .. string.format(
      _("ROLLBACK INCOMPLETE: the previous state of these files could not be restored: %s"),
      table.concat(names, ", "))
    local kept = utils.snapshot_keep(store)
    if kept then
      msg = msg .. "\n" .. string.format(_("The previous contents are kept here: %s"), kept)
    end
    return msg
  end

  -- The subscription database is also written by background fetch runs, which
  -- take /var/lock/tproxy-manager/watchdog.lock. Editing it here without that
  -- lock meant a fetch that finished mid-request had its results overwritten
  -- by the copy this request had read before it started.
  -- Returns (locked, result). The two are kept separate on purpose: a handler
  -- body may legitimately return nil or false, so a single return value could
  -- not tell "the lock was busy" from "the body ran and said no" - and the
  -- caller would redirect a second time on top of the redirect issued here.
  local function with_subscription_lock(fn)
    local lock, lerr = utils.lock_acquire(utils.SUBSCRIPTIONS_LOCK)
    if not lock then
      set_info(nil)
      if lerr == "busy" then
        set_err(_("The subscription list is busy with another operation. Try again in a moment."))
      else
        set_err(_("Failed to save settings.") .. " " .. tostring(lerr))
      end
      helpers.redirect_watchdog()
      return false
    end
    local ok, res = pcall(fn, lock)
    -- Released on the error path too: an escaping error must not leave the
    -- lock held until its owner pid disappears.
    lock.release()
    if not ok then error(res, 0) end
    return true, res
  end

  if http.formvalue("_sub_save") == "1" then
    -- Validation runs before the lock: a rejected form must not make a
    -- concurrent fetch wait.
    local probe = read_subscription_db(subscriptions_path)
    local probe_id = tonumber(http.formvalue("sub_id"))
    local probe_sub = collect_subscription_form(probe_id and find_subscription(probe, probe_id) or nil)
    if probe_sub.url == "" then
      set_err(_("Subscription URL is required."))
    elseif probe_sub.timeout < 1 then
      set_err(_("Subscription timeout must be at least 1 second."))
    elseif probe_sub.refresh_interval < 1 then
      set_err(_("Subscription refresh timer must be at least 1 second."))
    else
      local locked = with_subscription_lock(function()
        -- Re-read INSIDE the lock: the copy fetched for validation may
        -- already be stale, and writing it back would drop whatever a fetch
        -- committed in the meantime.
        local db = read_subscription_db(subscriptions_path)
        local id = tonumber(http.formvalue("sub_id"))
        local existing = id and find_subscription(db, id) or nil
        if id and not existing then
          -- The entry disappeared between the form being rendered and this
          -- save — a concurrent delete. Falling through would re-create it
          -- under a fresh id, silently resurrecting what the other operation
          -- removed.
          set_info(nil); set_err(_("Subscription not found."))
          return
        end
        local sub = collect_subscription_form(existing)
        if existing then
          sub.id = existing.id
          local _unused, idx = find_subscription(db, existing.id)
          db.subscriptions[idx] = sub
        else
          sub.id = next_subscription_id(db)
          db.subscriptions[#db.subscriptions + 1] = sub
        end

        local store, serr = utils.snapshot_begin("sub-save")
        if store then
          local ok, aerr = utils.snapshot_add(store, subscriptions_path)
          if not ok then serr = aerr; utils.snapshot_discard(store); store = nil end
        end
        if not store then
          set_info(nil)
          set_err(_("Failed to save settings.") .. "\n" ..
            string.format(_("Could not create a rollback snapshot: %s"), tostring(serr or "unknown error")))
          return
        end

        local armed, aerr = utils.snapshot_arm(store)
        if not armed then
          utils.snapshot_discard(store)
          set_info(nil)
          set_err(_("Failed to save settings.") .. "\n" ..
            string.format(_("Could not create a rollback snapshot: %s"), tostring(aerr or "")))
          return
        end

        local wrote, wwhy = write_subscription_db(subscriptions_path, db)
        if not wrote and wwhy ~= "permissions" then
          local failed = utils.snapshot_restore(store)
          if #failed > 0 then
            set_info(nil)
            set_err(rollback_incomplete_message(_("Failed to save settings."), failed, store))
            return
          end
          utils.snapshot_discard(store)
          set_info(nil); set_err(_("Failed to save settings."))
          return
        end

        utils.snapshot_discard(store)
        if wrote then
          set_err(nil); set_info(_("Subscription saved."))
        else
          set_info(nil); set_err(_("Settings saved, but the configuration file permissions could not be secured."))
        end
      end)
      -- with_subscription_lock already redirected when the lock was busy;
      -- redirecting again would emit a second Location header.
      if locked then helpers.redirect_watchdog() end
      return m
    end
  end

  if http.formvalue("_sub_delete") then
    local locked, found = with_subscription_lock(function(lock)
      -- Read inside the lock: a fetch that completed since the page was
      -- rendered must be part of what we edit, not something we overwrite.
      local db = read_subscription_db(subscriptions_path)
      local sub, idx = find_subscription(db, http.formvalue("_sub_delete"))
      if not (sub and idx) then return false end

      -- Deleting a subscription touches TWO files: the database and the links
      -- file that sync-links rewrites from it. Both are copied to a private
      -- 0700 directory BEFORE anything changes, so the previous state exists
      -- outside this process even if it dies mid-transaction.
      local store, serr = utils.snapshot_begin("sub-delete")
      if store then
        for __, path in ipairs({ subscriptions_path, links_path }) do
          if not store then break end
          local ok, aerr = utils.snapshot_add(store, path)
          if not ok then serr = aerr; utils.snapshot_discard(store); store = nil end
        end
      end
      if not store then
        set_info(nil)
        set_err(_("Failed to delete the subscription.") .. "\n" ..
          string.format(_("Could not create a rollback snapshot: %s"), tostring(serr or "unknown error")))
        return true
      end

      local armed, aerr = utils.snapshot_arm(store)
      if not armed then
        utils.snapshot_discard(store)
        set_info(nil)
        set_err(_("Failed to delete the subscription.") .. "\n" ..
          string.format(_("Could not create a rollback snapshot: %s"), tostring(aerr or "")))
        return true
      end

      remove_subscription_sources(db, sub)
      table.remove(db.subscriptions, idx)
      local wrote, wwhy = write_subscription_db(subscriptions_path, db)
      if not wrote and wwhy ~= "permissions" then
        -- The database was not written: the subscription is still there, so
        -- do not resync links or claim it was deleted.
        utils.snapshot_discard(store)
        set_info(nil); set_err(_("Failed to save settings."))
        return true
      end

      -- The resync result decides whether the deletion actually completed;
      -- it used to be discarded, so a failed sync-links still reported
      -- "Subscription deleted" with the dead links left in place. It runs
      -- under OUR lock - the pid is passed so the script joins this
      -- transaction instead of blocking on the lock we already hold.
      local sync_rc, sync_out = run_subscription_command({ "sync-links" }, lock.pid)
      if sync_rc ~= 0 then
        local failed = utils.snapshot_restore(store)
        set_info(nil)
        if #failed > 0 then
          set_err(rollback_incomplete_message(_("Failed to delete the subscription."), failed, store) ..
            (sync_out ~= "" and ("\n" .. sync_out) or ""))
        else
          utils.snapshot_discard(store)
          set_err(_("Failed to delete the subscription: the link list could not be resynchronised; the previous state was restored.") ..
            (sync_out ~= "" and ("\n" .. sync_out) or ""))
        end
        return true
      end

      utils.snapshot_discard(store)
      if wrote then
        set_err(nil); set_info(_("Subscription deleted."))
      else
        set_info(nil); set_err(_("Settings saved, but the configuration file permissions could not be secured."))
      end
      return true
    end)
    if not locked then return m end
    if found then
      helpers.redirect_watchdog()
      return m
    end
    set_err(_("Subscription not found."))
  end

  if http.formvalue("_sub_fetch") then
    local id = trim(http.formvalue("_sub_fetch"))
    local rc, out = run_subscription_command({ "fetch", id })
    if rc == 0 then set_info(out ~= "" and out or (_("Subscription updated:").." " .. id)) else set_err(out ~= "" and out or (_("Failed to update subscription:").." " .. id)) end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_sub_fetch_all") == "1" then
    local rc, out = run_subscription_command({ "fetch-all" })
    if rc == 0 then set_info(out ~= "" and out or _("Subscriptions updated.")) else set_err(out ~= "" and out or _("Failed to update subscriptions.")) end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_sub_edit_start") then
    helpers.redirect_watchdog("sub_edit_id=" .. http.urlencode(trim(http.formvalue("_sub_edit_start"))))
    return m
  end

  if http.formvalue("_sub_edit_cancel") == "1" then
    -- Drop any banner from the previous action: a cancel that leaves the
    -- earlier "saved" message on screen reads as if it had saved something.
    set_err(nil); set_info(nil)
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_watchdog_save_settings") == "1" then
    if helpers.save_watchdog_settings(ctx) then
      helpers.redirect_watchdog()
      return m
    end
  end

  if http.formvalue("_watchdog_save_template") == "1" then
    local choice = template_choice_by_id(http.formvalue("watchdog_template_kind"))
    local path = trim(http.formvalue("watchdog_template_path"))
    local text = http.formvalue("watchdog_template_text") or ""
    if path == "" then
      set_err(_("Template file path is required."))
    elseif not utils.is_abs_path(path) then
      set_err(_("Template file path must be absolute."))
    elseif not helpers.validate_template_jsonc_text(text) then
      set_err(_("Invalid template JSON/JSONC."))
    else
      -- Uses the same checked transaction as every other editor instead of
      -- its own hand-rolled copy: the local version treated the writer's
      -- "permissions" status as "not written" and rolled back a file that
      -- had in fact already been replaced.
      local okc, msg = save_uci_and_file(choice.key, path, text,
        _("Watchdog template saved:").." " .. path)
      if okc then set_err(nil); set_info(msg) else set_info(nil); set_err(msg) end
      helpers.redirect_watchdog("watchdog_template_kind=" .. http.urlencode(choice.id))
      return m
    end
  end

  if http.formvalue("_watchdog_save_test_template") == "1" then
    local choice = template_choice_by_id("vless_test")
    local path = trim(http.formvalue("watchdog_test_template_file"))
    local text = http.formvalue("watchdog_test_template_text") or ""
    if path == "" then
      set_err(_("Test template file path is required."))
    elseif not utils.is_abs_path(path) then
      set_err(_("Test template file path must be absolute."))
    elseif not helpers.validate_template_jsonc_text(text) then
      set_err(_("Invalid template JSON/JSONC."))
    else
      local okc, msg = save_uci_and_file(choice.key, path, text, _("Test template saved:").." " .. path)
      if okc then set_err(nil); set_info(msg) else set_info(nil); set_err(msg) end
      helpers.redirect_watchdog("watchdog_template_kind=" .. http.urlencode(choice.id))
      return m
    end
  end

  if http.formvalue("_watchdog_save_links_text") == "1" then
    local path = trim(http.formvalue("watchdog_links_file"))
    local text = (http.formvalue("watchdog_links_text") or ""):gsub("\r\n", "\n")
    local ok, bad_line = helpers.validate_links_text(text)
    if path == "" then
      set_err(_("LINKS_FILE path is required."))
    elseif not utils.is_abs_path(path) then
      set_err(_("LINKS_FILE path must be absolute."))
    elseif not ok then
      set_err(_("Invalid line in LINKS_FILE:").." " .. tostring(bad_line))
    else
      local body = text ~= "" and (text:gsub("\n*$", "") .. "\n") or ""
      local okc, msg = save_uci_and_file("watchdog_links_file", path, body, _("LINKS_FILE saved:").." " .. path)
      if okc then set_err(nil); set_info(msg) else set_info(nil); set_err(msg) end
      helpers.redirect_watchdog()
      return m
    end
  end

  if http.formvalue("_watchdog_clear_log") == "1" then
    -- The writer's result decides what to report: clearing the banner and
    -- redirecting regardless read as success even when nothing was written.
    local cleared, cwhy = helpers.clear_watchdog_log()
    if cleared then
      set_err(nil); set_info(_("Watchdog log cleared."))
    elseif cwhy == "permissions" then
      set_info(nil)
      set_err(_("Settings saved, but the configuration file permissions could not be secured."))
    else
      set_info(nil); set_err(_("Failed to clear the log."))
    end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_watchdog_once") == "1" then
    local rc, out = helpers.run_watchdog_command({ "once" })
    if rc == 0 then set_info(out ~= "" and out or _("Watchdog check completed.")) else set_err(out ~= "" and out or _("Watchdog check failed.")) end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_watchdog_reset") == "1" then
    local rc, out = helpers.run_watchdog_command({ "reset" })
    if rc == 0 then set_info(out ~= "" and out or _("Failure counter reset.")) else set_err(out ~= "" and out or _("Failed to reset failure counter.")) end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_watchdog_test_rotate") == "1" then
    local rotate_mode = trim(http.formvalue("watchdog_selection_mode"))
    local env = {}
    if rotate_mode == "random" or rotate_mode == "ordered" or rotate_mode == "fastest" then
      env.WATCHDOG_SELECTION_MODE = rotate_mode
    end
    local rc, out = helpers.run_watchdog_command({ "test-rotate" }, env)
    if rc == 0 then set_info(out ~= "" and out or _("Rotation completed.")) else set_err(out ~= "" and out or _("Rotation failed.")) end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_watchdog_check_all") == "1" then
    -- Detached on purpose: the scan takes about two seconds per link, so with a
    -- realistic list it outlives uhttpd's 60 s CGI limit and the request died
    -- with "Bad Gateway" while the scan kept running invisibly. Each link's
    -- result is written to its own state file as it completes, which is what the
    -- table below reads, so reloading the page shows the progress.
    if helpers.watchdog_command_running("check-all") then
      set_info(nil)
      set_err(_("A full link check is already running."))
    elseif helpers.run_watchdog_command_detached({ "check-all" }) then
      set_err(nil)
      set_info(_("Full link check started in the background; reload the page to see results as they arrive."))
    else
      set_info(nil)
      set_err(_("Links check failed."))
    end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_wd_apply") then
    local hash = trim(http.formvalue("_wd_apply"))
    local rc, out = helpers.run_watchdog_command({ "apply-link", hash })
    if rc == 0 then set_info(out ~= "" and out or (_("Link applied:").." " .. hash)) else set_err(out ~= "" and out or (_("Failed to apply link:").." " .. hash)) end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_wd_test") then
    local hash = trim(http.formvalue("_wd_test"))
    local rc, out = helpers.run_watchdog_command({ "test-link", hash })
    if rc == 0 then set_info(out ~= "" and out or (_("Link checked:").." " .. hash)) else set_err(out ~= "" and out or (_("Link check failed:").." " .. hash)) end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_wd_exclude") then
    local hash = trim(http.formvalue("_wd_exclude"))
    local rc, out = run_subscription_command({ "exclude-link", hash })
    if rc == 0 then set_info(out ~= "" and out or _("Link excluded from subscriptions.")) else set_err(out ~= "" and out or _("Failed to exclude link from subscriptions.")) end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_wd_include") then
    local hash = trim(http.formvalue("_wd_include"))
    local rc, out = run_subscription_command({ "include-link", hash })
    if rc == 0 then set_info(out ~= "" and out or _("Link returned to rotation.")) else set_err(out ~= "" and out or _("Failed to return link to rotation.")) end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_wd_edit_start") then
    local hash = trim(http.formvalue("_wd_edit_start"))
    helpers.redirect_watchdog("wd_edit_hash=" .. http.urlencode(hash))
    return m
  end

  if http.formvalue("_wd_edit_cancel") == "1" then
    -- Drop any banner from the previous action: a cancel that leaves the
    -- earlier "saved" message on screen reads as if it had saved something.
    set_err(nil); set_info(nil)
    helpers.redirect_watchdog()
    return m
  end

  -- links_mutate: read-modify-write of the links file under the SAME lock the
  -- background sync uses, re-reading inside it. Reading at render time and
  -- writing later meant a sync-links that landed in between was silently
  -- overwritten by a stale copy of the list.
  --
  -- `fn(entries, db)` returns the success message, or nil plus the message to
  -- show instead of writing. write_links_file is a single atomic write, so a
  -- failed write leaves the previous file untouched and there is nothing to
  -- roll back — no snapshot is needed here.
  local function links_mutate(fn)
    local locked, done = with_subscription_lock(function()
      local entries = helpers.parse_links_file(links_path)
      local db = read_subscription_db(subscriptions_path)
      local ok_message, err_message = fn(entries, db)
      if not ok_message then
        set_info(nil); set_err(err_message or _("Failed to save settings."))
        return false
      end
      -- `true` means the request was valid but changes nothing: writing the
      -- file unchanged and announcing a change would be a false success.
      if ok_message == true then return true end
      local wrote, wwhy = helpers.write_links_file(links_path, entries)
      report_links_write(wrote, wwhy, ok_message)
      return true
    end)
    if not locked then return nil end
    return done
  end

  if http.formvalue("_wd_add") == "1" then
    local done = links_mutate(function(entries)
      local parsed = helpers.parse_link_line(trim(http.formvalue("wd_add_link")))
      if not parsed then
        return nil, _("Added line must start with vless://, hysteria2:// or hy2://")
      end
      entries[#entries + 1] = { raw_link = parsed.raw_link }
      return _("Link added.")
    end)
    if done == nil then return m end
    if done then helpers.redirect_watchdog(); return m end
  end

  if http.formvalue("_wd_edit_save") == "1" then
    local done = links_mutate(function(entries, db)
      local hash = trim(http.formvalue("wd_edit_hash"))
      local idx = helpers.find_entry_index(entries, hash)
      local parsed = helpers.parse_link_line(trim(http.formvalue("wd_edit_link")))
      if not idx then
        return nil, _("Editable link not found.")
      elseif is_subscription_link(db, hash) then
        return nil, _("Subscription links cannot be edited directly. Exclude the link or edit the subscription.")
      elseif not parsed then
        return nil, _("Link must start with vless://, hysteria2:// or hy2://")
      end
      entries[idx].raw_link = parsed.raw_link
      return _("Link updated.")
    end)
    if done == nil then return m end
    if done then helpers.redirect_watchdog(); return m end
  end

  if http.formvalue("_wd_delete") then
    local done = links_mutate(function(entries)
      local idx = helpers.find_entry_index(entries, trim(http.formvalue("_wd_delete")))
      if not idx then return nil, _("Link to delete was not found.") end
      table.remove(entries, idx)
      return _("Link deleted.")
    end)
    if done == nil then return m end
    if done then helpers.redirect_watchdog(); return m end
  end

  if http.formvalue("_wd_move_up") or http.formvalue("_wd_move_down") then
    local done = links_mutate(function(entries)
      local hash = trim(http.formvalue("_wd_move_up") or http.formvalue("_wd_move_down"))
      local idx = helpers.find_entry_index(entries, hash)
      if not idx then return nil, _("Link to reorder was not found.") end
      local swap_idx = http.formvalue("_wd_move_up") and (idx - 1) or (idx + 1)
      if swap_idx < 1 or swap_idx > #entries then
        -- Already at the end of the list: nothing to write, and reporting a
        -- reorder that did not happen would be a false success.
        return true
      end
      entries[idx], entries[swap_idx] = entries[swap_idx], entries[idx]
      return _("Link order updated.")
    end)
    if done == nil then return m end
    if done then helpers.redirect_watchdog(); return m end
  end

  local status_rc, status_out = helpers.run_watchdog_command({ "status" })
  local status = status_rc == 0 and helpers.parse_kv_text(status_out) or {}
  local edit_hash = trim(http.formvalue("wd_edit_hash"))
  local edit_sub_id = trim(http.formvalue("sub_edit_id"))
  local sub_db = read_subscription_db(subscriptions_path)
  local edit_sub = edit_sub_id ~= "" and find_subscription(sub_db, edit_sub_id) or nil
  local links = helpers.parse_links_file(links_path)
  links = merge_excluded_subscription_links(links, sub_db)
  local share_enabled = getu("watchdog_share_enabled", "0") == "1"
  -- Defaults to token auth so a config predating this option renders (and then
  -- saves) the safe mode rather than the public one.
  local share_auth_mode = getu("watchdog_share_auth_mode", "token")
  if share_auth_mode ~= "public" then share_auth_mode = "token" end
  if share_auth_mode ~= "token" then share_auth_mode = "public" end
  local share_token = trim(getu("watchdog_share_token", ""))
  local share_cfg = share.read_config(share_file)
  local share_export_entries = share.selected_entries(share.parse_links_file(links_path), share_cfg)
  local active_entry, active_detected_by = find_active_entry(links, status)
  local active_hash = active_entry and active_entry.hash or ""
  local active_text = active_entry and active_source_text(sub_db, active_entry) or "-"
  local active_subscriptions = {}

  if active_entry then
    local active_item = sub_db.links and sub_db.links[active_hash]
    if type(active_item) == "table" and type(active_item.sources) == "table" then
      for __, source in pairs(active_item.sources) do
        local key = tostring(source.type or "happ") .. ":" .. tostring(source.id or "")
        active_subscriptions[key] = true
      end
    end
    if active_detected_by == "config" then
      active_text = active_text .. " · config"
    elseif active_detected_by == "state" then
      active_text = active_text .. " · state"
    end
  end

  do
    local css = m:section(SimpleSection)
    local dv = css:option(DummyValue, "_watchdog_css")
    dv.rawhtml = true
    function dv.cfgvalue()
      return [[
<style>
.wd-grid{display:grid;grid-template-columns:minmax(220px,340px) 1fr;gap:.35rem .6rem;align-items:center;max-width:960px}
.wd-grid input[type="text"], .wd-grid input[type="number"], .wd-grid select{width:100%}
.wd-table{width:100%;border-collapse:collapse;table-layout:fixed;word-break:break-word}
.wd-table th,.wd-table td{border:1px solid #e5e7eb;padding:.35rem;vertical-align:top}
.wd-table th{background:#f9fafb}
.wd-table tr.wd-active-row td{background:#ecfdf5!important;border-color:#86efac}
.wd-table tr.wd-excluded-row td{background:#f3f4f6!important;color:#6b7280}
.wd-table tr.wd-excluded-row .wd-code{color:#9ca3af}
.wd-table .actions .cbi-button{margin:0 .2rem .2rem 0}
.wd-code{font-family:monospace;font-size:.92em}
.wd-details{margin-top:.6rem}
.wd-details summary{cursor:pointer;font-weight:600}
.wd-textarea{width:100%;font-family:monospace;font-size:.92em}
.wd-active-badge{display:inline-block;margin-left:.25rem;padding:.05rem .32rem;border-radius:.3rem;background:#16a34a;color:#fff;font-size:.78em;font-weight:700}
.happ-decrypt-actions{margin-top:.6rem;display:flex;gap:.35rem;flex-wrap:wrap}
.wd-subblock{border:1px solid #e5e7eb;border-radius:.45rem;padding:.75rem;margin:.75rem 0}
.wd-subblock h4{margin-top:0}
.wd-share-url{display:flex;gap:.35rem}
.wd-share-url input{width:100%}
.wd-share-url button{min-width:2.4rem;padding-left:.45rem;padding-right:.45rem}
</style>
]]
    end
  end

  do
    local ss = m:section(SimpleSection, _("Watchdog service status and controls"))
    service_block(ss, "tproxy-manager-watchdog", "Watchdog", "watchdog")
  end

  do
    local sec = m:section(SimpleSection)
    local dv = sec:option(DummyValue, "_watchdog_runtime")
    dv.rawhtml = true
    function dv.cfgvalue()
      local running = status.RUNNING or "no"
      local failcount = status.FAILCOUNT or "0"
      local code = status.LAST_HTTP_CODE or "-"
      local st = status.LAST_STATUS or "-"
      local ts = status.LAST_TS_HUMAN or status.LAST_TS or "-"
      local scan = status.LAST_LINK_SCAN_HUMAN or "-"
      local scan_status = status.LAST_LINK_SCAN_STATUS or "-"
      local active = active_text
      local scan_alive_num = 0
      for __, entry in ipairs(links or {}) do
        if entry.state and entry.state.LAST_STATUS == "alive" then
          scan_alive_num = scan_alive_num + 1
        end
      end
      local scan_alive = tostring(scan_alive_num)
      local scan_total = tostring(#(links or {}))
      return string.format([[
<div class="box" style="max-width:960px">
  <div class="inline-row" style="flex-wrap:wrap; gap:.8rem">
    <span><strong>RUNNING:</strong> %s</span>
    <span><strong>FAILCOUNT:</strong> %s</span>
    <span><strong>LAST_HTTP_CODE:</strong> %s</span>
    <span><strong>LAST_STATUS:</strong> %s</span>
    <span><strong>LAST_TS:</strong> %s</span>
    <span><strong>LAST_LINK_SCAN:</strong> %s</span>
    <span><strong>SCAN_RESULT:</strong> %s (%s/%s)</span>
    <span><strong>ACTIVE:</strong> %s</span>
  </div>
  <div style="margin-top:.5rem">
    <button class="cbi-button cbi-button-apply" name="_watchdog_once" value="1">%s</button>
    <button class="cbi-button cbi-button-action" name="_watchdog_check_all" value="1">%s</button>
    <button class="cbi-button cbi-button-action" name="_watchdog_test_rotate" value="1">%s</button>
    <button class="cbi-button cbi-button-remove" name="_watchdog_reset" value="1">%s</button>
  </div>
</div>]],
        pcdata(running), pcdata(failcount), pcdata(code), pcdata(st), pcdata(ts),
        pcdata(scan), pcdata(scan_status), pcdata(scan_alive), pcdata(scan_total),
        pcdata(active),
        pcdata(_("Check now")),
        pcdata(_("Check all links")),
        pcdata(_("Force rotation")),
        pcdata(_("Reset counter")))
    end
  end

  do
    local sec = m:section(SimpleSection, _("Subscriptions"))
    local dv = sec:option(DummyValue, "_watchdog_subscriptions")
    dv.rawhtml = true
    function dv.cfgvalue()
      local rows = {}
      local capture_enabled = getu("watchdog_happ_capture_enabled", "0") == "1"
      local capture_token = getu("watchdog_happ_capture_token", "")
      local capture_until = tonumber(getu("watchdog_happ_capture_until", "0")) or 0
      local capture_port = getu("watchdog_happ_capture_port", "18088")
      local cap_rc, cap_out = run_subscription_command({ "capture-status" })
      local cap_status = cap_rc == 0 and helpers.parse_kv_text(cap_out) or {}
      local capture_running = cap_status.CAPTURE_RUNNING == "1"
      if cap_status.CAPTURE_TOKEN and cap_status.CAPTURE_TOKEN ~= "" then capture_token = cap_status.CAPTURE_TOKEN end
      if cap_status.CAPTURE_PORT and cap_status.CAPTURE_PORT ~= "" then capture_port = cap_status.CAPTURE_PORT end
      if cap_status.CAPTURE_LOG and cap_status.CAPTURE_LOG ~= "" then capture_log = cap_status.CAPTURE_LOG end
      if cap_status.CAPTURE_UNTIL and cap_status.CAPTURE_UNTIL ~= "" then capture_until = tonumber(cap_status.CAPTURE_UNTIL) or capture_until end
      local capture_active = capture_enabled and capture_running and capture_token ~= "" and os.time() <= capture_until
      local capture_link = capture_active and capture_url(capture_token, capture_port) or ""
      local ttl = getu("watchdog_happ_capture_ttl", "600")
      local until_text = capture_until > 0 and os.date("%Y-%m-%d %H:%M:%S", capture_until) or "-"
      local form_sub = edit_sub or {
        type = "happ",
        enabled = true,
        timeout = 30,
        refresh_interval = 10800,
        headers = default_happ_headers(capture_defaults),
      }
      if capture_defaults then
        form_sub.headers = default_happ_headers(capture_defaults)
      else
        form_sub.headers = type(form_sub.headers) == "table" and form_sub.headers or default_happ_headers()
      end
      local h = form_sub.headers
      local form_title = edit_sub and (_("Edit subscription #") .. tostring(edit_sub.id)) or _("New subscription")
      local happ_open = (show_capture_details or capture_defaults or capture_active or happ_decrypt_open) and " open" or ""

      rows[#rows + 1] = "<div class='box'>"
      rows[#rows + 1] = "<details class='wd-details'" .. happ_open .. "><summary>Happ</summary>"
      rows[#rows + 1] = "<div class='wd-subblock'><h4>Happ capture</h4>"
      rows[#rows + 1] = "<div style='color:#6b7280;margin-bottom:.5rem'>" .. _("Click Start capture, copy the link and open it from the phone in the app/browser that performs the subscription request. The router will save headers and body of the last request, then they can be used to fill the Happ subscription form.") .. "</div>"
      rows[#rows + 1] = string.format([[
<div class="wd-grid">
  <label>%s</label><div>%s, %s: %s</div>
  <label>%s</label><input type="number" min="1" name="happ_capture_start_ttl" value="%s">
  <label>%s</label><input type="number" min="1" max="65535" name="happ_capture_start_port" value="%s">
  <label>%s</label><input type="text" name="happ_capture_start_log" value="%s">
  <label>%s</label>
  <div class="inline-row" style="gap:.4rem">
    <input id="happ_capture_url" type="text" readonly value="%s" style="width:100%%" onclick="this.select()">
    <button type="button" class="cbi-button cbi-button-action" title="%s" style="min-width:2.4rem;padding-left:.45rem;padding-right:.45rem" onclick="var e=document.getElementById('happ_capture_url');e.select();if(navigator.clipboard){navigator.clipboard.writeText(e.value);}else{document.execCommand('copy');}">📋</button>
  </div>
</div>
<div style="margin-top:.6rem">
  <button class="cbi-button cbi-button-apply" name="_sub_start_capture" value="1">%s</button>
  <button class="cbi-button cbi-button-remove" name="_sub_stop_capture" value="1">%s</button>
  <button class="cbi-button cbi-button-action" name="_sub_show_capture" value="1">%s</button>
  <button class="cbi-button cbi-button-action" name="_sub_fill_happ_capture" value="1">%s</button>
</div>]],
        pcdata(_("Status")),
        capture_active and "<span class='svc-badge ok'>" .. _("enabled") .. "</span>" or "<span class='svc-badge'>" .. _("disabled") .. "</span>",
        pcdata(_("valid until")),
        pcdata(until_text),
        pcdata(_("TTL, sec")),
        pcdata(ttl),
        pcdata(_("Capture service port")),
        pcdata(capture_port),
        pcdata(_("Capture log")),
        pcdata(capture_log),
        pcdata(_("Phone link")),
        pcdata(capture_link),
        pcdata(_("Copy")),
        pcdata(_("Start capture")),
        pcdata(_("Stop capture")),
        pcdata(_("Show last request")),
        pcdata(_("Fill Happ form from the last request")))

      if show_capture_details then
        local last_request = read_file(capture_log)
        if last_request ~= "" then
          rows[#rows + 1] = "<details class='wd-details' open><summary>" .. _("Last capture request") .. "</summary><pre style='white-space:pre-wrap;max-height:18rem;overflow:auto;margin-top:.5rem'>" .. pcdata(last_request) .. "</pre></details>"
        else
          rows[#rows + 1] = "<div style='margin-top:.5rem;color:#6b7280'>" .. _("No capture request has been saved yet.") .. "</div>"
        end
      end
      rows[#rows + 1] = "</div>"

      rows[#rows + 1] = string.format([[
<div class="wd-subblock">
  <h4>Happ decrypt</h4>
  <div style="color:#6b7280;margin-bottom:.5rem">
    %s
    %s
  </div>
  <label style="display:block;font-weight:600;margin-bottom:.25rem">Happ link(s)</label>
  <textarea name="happ_decrypt_input" class="wd-textarea" rows="5" spellcheck="false" placeholder="happ://crypt/...&#10;happ://crypt5/...">%s</textarea>
  <div class="happ-decrypt-actions">
    <button class="cbi-button cbi-button-apply" name="_happ_decrypt_run" value="1">%s</button>
    <button class="cbi-button cbi-button-reset" name="_happ_decrypt_clear" value="1">%s</button>
  </div>
  <label style="display:block;font-weight:600;margin:.65rem 0 .25rem">%s</label>
  <textarea class="wd-textarea" rows="6" spellcheck="false" readonly>%s</textarea>
</div>
</details>]],
        pcdata(_("Decrypts happ://crypt/, crypt2, crypt3, crypt4 and crypt5 through the shared server-side mechanism.")),
        pcdata(_("The result is only displayed and is not added to the link list or subscriptions.")),
        pcdata(happ_decrypt_input),
        pcdata(_("Decrypt")),
        pcdata(_("Clear")),
        pcdata(_("Result")),
        pcdata(happ_decrypt_output))

      rows[#rows + 1] = "<h4>" .. _("Subscription list") .. "</h4>"
      rows[#rows + 1] = "<table class='wd-table'><thead><tr><th style='width:8%'>" .. _("Type") .. "</th><th style='width:6%'>ID</th><th style='width:16%'>" .. _("Name") .. "</th><th style='width:28%'>URL</th><th style='width:8%'>" .. _("Enabled") .. "</th><th style='width:10%'>" .. _("Timer") .. "</th><th style='width:12%'>" .. _("Status") .. "</th><th style='width:12%'>" .. _("Action") .. "</th></tr></thead><tbody>"
      if #sub_db.subscriptions == 0 then
        rows[#rows + 1] = "<tr><td colspan='8' style='color:#6b7280'>" .. _("No subscriptions configured") .. "</td></tr>"
      end
      for __, sub in ipairs(sub_db.subscriptions) do
        local st = sub.last_status or "never"
        local st_html = st == "ok" and "<span class='svc-badge ok'>OK</span>" or (st == "error" and "<span class='svc-badge err'>Error</span>" or "<span class='svc-badge'>never</span>")
        local is_active_sub = active_subscriptions[subscription_source_key(sub)] == true
        local row_class = is_active_sub and " class='wd-active-row'" or ""
        if is_active_sub then
          st_html = st_html .. " <span class='wd-active-badge'>ACTIVE</span>"
        end
        local detail = sub.last_error and sub.last_error ~= "" and ("<div style='color:#b91c1c'>" .. pcdata(sub.last_error) .. "</div>") or ""
        rows[#rows + 1] = string.format([[
<tr%s>
  <td>%s</td>
  <td>%s</td>
  <td>%s</td>
  <td class="wd-code" title="%s">%s</td>
  <td>%s</td>
  <td>%s %s</td>
  <td>%s<div style="color:#6b7280">links: %s<br>%s</div>%s</td>
  <td class="actions">
    <button class="cbi-button cbi-button-action" name="_sub_fetch" value="%s">%s</button>
    <button class="cbi-button cbi-button-action" name="_sub_edit_start" value="%s">%s</button>
    <button class="cbi-button cbi-button-remove" name="_sub_delete" value="%s" onclick="return confirm('%s')">%s</button>
  </td>
</tr>]],
          row_class,
          pcdata(sub.type or "happ"),
          pcdata(sub.id or ""),
          pcdata(sub.name ~= "" and sub.name or "—"),
          pcdata(sub.url or ""),
          pcdata(sub.url or ""),
          subscription_enabled(sub) and _("yes") or _("no"),
          pcdata(sub.refresh_interval or "0"),
          pcdata(_("sec")),
          st_html,
          pcdata(sub.last_count or "0"),
          pcdata(sub.last_update_human or "-"),
          detail,
          pcdata(sub.id or ""), pcdata(_("Update")),
          pcdata(sub.id or ""), pcdata(_("Edit")),
          pcdata(sub.id or ""), pcdata(_("Delete subscription and its links?")), pcdata(_("Delete")))
      end
      rows[#rows + 1] = "</tbody></table>"
      rows[#rows + 1] = "<div style='margin-top:.5rem'><button class='cbi-button cbi-button-action' name='_sub_fetch_all' value='1'>" .. _("Update all subscriptions") .. "</button></div>"

      rows[#rows + 1] = string.format([[
<details class="wd-details" %s>
  <summary>%s</summary>
  <div class="box" style="margin-top:.5rem">
    <input type="hidden" name="sub_id" value="%s">
    <input type="hidden" name="sub_type" value="happ">
    <div class="wd-grid">
      <label>%s</label><div><span class="svc-badge ok">happ</span></div>
      <label>%s</label><input type="checkbox" name="sub_enabled" value="1" %s>
      <label>%s</label><input type="text" name="sub_name" value="%s">
      <label>%s</label><input type="text" name="sub_url" value="%s">
      <label>%s</label><input type="number" min="1" name="sub_refresh_interval" value="%s">
      <label>%s</label><input type="number" min="1" name="sub_timeout" value="%s">
    </div>
    <details class="wd-details" open>
      <summary>Happ headers</summary>
      <div class="wd-grid" style="margin-top:.5rem">
        <label>User-Agent</label><input type="text" name="sub_h_user_agent" value="%s">
        <label>X-Device-Os</label><input type="text" name="sub_h_device_os" value="%s">
        <label>X-Device-Locale</label><input type="text" name="sub_h_device_locale" value="%s">
        <label>X-Device-Model</label><input type="text" name="sub_h_device_model" value="%s">
        <label>X-Ver-Os</label><input type="text" name="sub_h_ver_os" value="%s">
        <label>Accept-Encoding</label><input type="text" name="sub_h_accept_encoding" value="%s">
        <label>Connection</label><input type="text" name="sub_h_connection" value="%s">
        <label>X-Hwid</label><input type="text" name="sub_h_hwid" value="%s">
        <label>X-Real-Ip</label><input type="text" name="sub_h_real_ip" value="%s">
        <label>X-Forwarded-For</label><input type="text" name="sub_h_forwarded_for" value="%s">
      </div>
      <div style="margin-top:.5rem;color:#6b7280">%s</div>
      <textarea class="wd-textarea" name="sub_extra_headers" rows="4" spellcheck="false">%s</textarea>
    </details>
    <div style="margin-top:.6rem">
      <button class="cbi-button cbi-button-apply" name="_sub_save" value="1">%s</button>
      <button class="cbi-button cbi-button-reset" name="_sub_edit_cancel" value="1">%s</button>
    </div>
    <div style="margin-top:.5rem;color:#6b7280">%s</div>
  </div>
</details>]],
        (edit_sub or capture_defaults) and "open" or "",
        pcdata(form_title),
        pcdata(form_sub.id or ""),
        pcdata(_("Type")),
        pcdata(_("Enabled")),
        subscription_enabled(form_sub) and "checked" or "",
        pcdata(_("Name")),
        pcdata(form_sub.name or ""),
        pcdata(_("URL or Happ link")),
        pcdata(form_sub.url or ""),
        pcdata(_("Refresh timer, sec")),
        pcdata(form_sub.refresh_interval or "10800"),
        pcdata(_("Request timeout, sec")),
        pcdata(form_sub.timeout or "30"),
        pcdata(h["User-Agent"] or ""),
        pcdata(h["X-Device-Os"] or ""),
        pcdata(h["X-Device-Locale"] or ""),
        pcdata(h["X-Device-Model"] or ""),
        pcdata(h["X-Ver-Os"] or ""),
        pcdata(h["Accept-Encoding"] or ""),
        pcdata(h["Connection"] or ""),
        pcdata(h["X-Hwid"] or ""),
        pcdata(h["X-Real-Ip"] or ""),
        pcdata(h["X-Forwarded-For"] or ""),
        pcdata(_("Additional headers: one Name: value pair per line.")),
        pcdata(form_sub.extra_headers or ""),
        pcdata(_("Save subscription")),
        pcdata(_("Cancel")),
        pcdata(_("For Happ, you can specify a regular https:// URL or an encrypted happ://crypt* link. Raw, base64 and JSON responses of Happ subscriptions are parsed automatically.")))

      rows[#rows + 1] = "</div>"
      return table.concat(rows, "\n")
    end
  end

  do
    local sec = m:section(SimpleSection, _("Proxy link list"))
    local dv = sec:option(DummyValue, "_watchdog_links")
    dv.rawhtml = true
    function dv.cfgvalue()
      local rows = {}
      local share_mode = share_cfg.selection_mode or "all"
      local share_selected = share_cfg.selected or {}
      local function share_checkbox(entry)
        local hash = tostring(entry.hash or "")
        local blocked = entry.excluded or hash == ""
        local selected = share_selected[hash] == true
        local checked = ((share_mode == "all" and not blocked) or (share_mode == "selected" and selected)) and " checked" or ""
        local disabled = (share_mode ~= "selected" or blocked) and " disabled" or ""
        return string.format(
          "<input class='wd-share-checkbox' type='checkbox' name='share_selected_hash' value='%s' data-share-selected='%s' data-share-blocked='%s'%s%s>",
          pcdata(hash),
          selected and "1" or "0",
          blocked and "1" or "0",
          checked,
          disabled)
      end
      rows[#rows + 1] = "<div class='box'>"
      rows[#rows + 1] = "<table class='wd-table'><thead><tr><th style='width:9%'>" .. _("Source") .. "</th><th style='width:7%'>" .. _("Protocol") .. "</th><th style='width:8%'>" .. _("Shared") .. "</th><th style='width:13%'>" .. _("Comment") .. "</th><th style='width:31%'>" .. _("Proxy link") .. "</th><th style='width:9%'>" .. _("Status") .. "</th><th style='width:10%'>" .. _("Last check") .. "</th><th style='width:13%'>" .. _("Action") .. "</th></tr></thead><tbody>"
      if #links == 0 then
        rows[#rows + 1] = "<tr><td colspan='8' style='color:#6b7280'>" .. _("Link list is empty") .. "</td></tr>"
      end
      for i, entry in ipairs(links) do
        local label, checked = helpers.status_label(entry, pcdata)
        local source_html, has_subscription_source = source_badges(sub_db, entry.hash)
        local is_excluded_link = is_subscription_link_excluded(sub_db, entry.hash)
        local is_active_link = active_hash ~= "" and entry.hash == active_hash
        local row_class = ""
        if is_excluded_link then
          row_class = " class='wd-excluded-row'"
        elseif is_active_link then
          row_class = " class='wd-active-row'"
        end
        if is_excluded_link then
          label = label .. " <span class='svc-badge'>" .. _("EXCLUDED") .. "</span>"
        elseif is_active_link then
          label = label .. " <span class='wd-active-badge'>ACTIVE</span>"
        end
        if edit_hash ~= "" and edit_hash == entry.hash and not has_subscription_source then
          rows[#rows + 1] = string.format([[
<tr%s>
  <td>%s</td>
  <td><span class="svc-badge">%s</span></td>
  <td style="text-align:center">%s</td>
  <td><input type="hidden" name="wd_edit_hash" value="%s"><div style="color:#6b7280">%s</div></td>
  <td><input type="text" name="wd_edit_link" value="%s" style="width:100%%"></td>
  <td>%s</td>
  <td>%s</td>
  <td class="actions">
    <button class="cbi-button cbi-button-apply" name="_wd_edit_save" value="1">%s</button>
    <button class="cbi-button cbi-button-reset" name="_wd_edit_cancel" value="1">%s</button>
  </td>
</tr>]],
            row_class, source_html, pcdata(entry.protocol_label or "-"), share_checkbox(entry), pcdata(entry.hash), pcdata(entry.comment or "—"), pcdata(entry.raw_link or ""), label, pcdata(checked),
            pcdata(_("Save")), pcdata(_("Cancel")))
        else
          local action_buttons
          if is_excluded_link then
            action_buttons = string.format([[
    <button class="cbi-button cbi-button-apply" disabled>%s</button>
    <button class="cbi-button cbi-button-action" disabled>%s</button>
    <button class="cbi-button cbi-button-apply" name="_wd_include" value="%s" onclick="return confirm('%s')">%s</button>
    <button class="cbi-button cbi-button-action" disabled>&uarr;</button>
    <button class="cbi-button cbi-button-action" disabled>&darr;</button>]],
              pcdata(_("Apply")),
              pcdata(_("Check")),
              pcdata(entry.hash), pcdata(_("Return link to rotation?")), pcdata(_("Enable")))
          elseif has_subscription_source then
            action_buttons = string.format([[
    <button class="cbi-button cbi-button-apply" name="_wd_apply" value="%s">%s</button>
    <button class="cbi-button cbi-button-action" name="_wd_test" value="%s">%s</button>
    <button class="cbi-button cbi-button-remove" name="_wd_exclude" value="%s" onclick="return confirm('%s')">%s</button>
    <button class="cbi-button cbi-button-action" name="_wd_move_up" value="%s"%s>&uarr;</button>
    <button class="cbi-button cbi-button-action" name="_wd_move_down" value="%s"%s>&darr;</button>]],
              pcdata(entry.hash), pcdata(_("Apply")),
              pcdata(entry.hash), pcdata(_("Check")),
              pcdata(entry.hash), pcdata(_("Exclude link from rotation?")), pcdata(_("Exclude")),
              pcdata(entry.hash), i == 1 and " disabled" or "",
              pcdata(entry.hash), i == #links and " disabled" or "")
          else
            action_buttons = string.format([[
    <button class="cbi-button cbi-button-apply" name="_wd_apply" value="%s">%s</button>
    <button class="cbi-button cbi-button-action" name="_wd_test" value="%s">%s</button>
    <button class="cbi-button cbi-button-action" name="_wd_edit_start" value="%s">%s</button>
    <button class="cbi-button cbi-button-remove" name="_wd_delete" value="%s" onclick="return confirm('%s')">%s</button>
    <button class="cbi-button cbi-button-action" name="_wd_move_up" value="%s"%s>&uarr;</button>
    <button class="cbi-button cbi-button-action" name="_wd_move_down" value="%s"%s>&darr;</button>]],
              pcdata(entry.hash), pcdata(_("Apply")),
              pcdata(entry.hash), pcdata(_("Check")),
              pcdata(entry.hash), pcdata(_("Edit")),
              pcdata(entry.hash), pcdata(_("Delete selected link?")), pcdata(_("Delete")),
              pcdata(entry.hash), i == 1 and " disabled" or "",
              pcdata(entry.hash), i == #links and " disabled" or "")
          end
          rows[#rows + 1] = string.format([[
<tr%s>
  <td>%s</td>
  <td><span class="svc-badge">%s</span></td>
  <td style="text-align:center">%s</td>
  <td>%s</td>
  <td class="wd-code" title="%s">%s</td>
  <td>%s</td>
  <td>%s</td>
  <td class="actions">
%s
  </td>
</tr>]],
            row_class,
            source_html,
            pcdata(entry.protocol_label or "-"),
            share_checkbox(entry),
            pcdata(entry.comment or "—"),
            pcdata(entry.raw_link or ""),
            pcdata(entry.link or ""),
            label,
            pcdata(checked),
            action_buttons)
        end
      end
      rows[#rows + 1] = [[
<tr>
  <td><span class="svc-badge">local</span></td>
  <td><span class="svc-badge">-</span></td>
  <td style="color:#6b7280;text-align:center">—</td>
  <td style="color:#6b7280">]] .. pcdata(_("New link file line")) .. [[</td>
  <td><input type="text" name="wd_add_link" placeholder="vless:// or hysteria2://..." style="width:100%"></td>
  <td colspan="2" style="color:#6b7280">]] .. pcdata(_("Comment will be taken from the part after # inside the link")) .. [[</td>
  <td class="actions"><button class="cbi-button cbi-button-apply" name="_wd_add" value="1">]] .. pcdata(_("Add")) .. [[</button></td>
</tr>]]
      rows[#rows + 1] = "</tbody></table>"
      rows[#rows + 1] = "<details class='wd-details'><summary>" .. _("LINKS_FILE editor") .. "</summary><div class='box editor-wrap editor-wide' style='margin-top:.5rem'>"
      rows[#rows + 1] = string.format("<div class='wd-grid'><label>LINKS_FILE</label><input type='text' name='watchdog_links_file' value='%s'></div>", pcdata(links_path))
      rows[#rows + 1] = "<div style='margin:.5rem 0;color:#6b7280'>" .. _("For bulk paste: one proxy link per line. Empty lines and lines starting with # are allowed.") .. "</div>"
      rows[#rows + 1] = string.format("<textarea class='wd-textarea' name='watchdog_links_text' rows='12' spellcheck='false'>%s</textarea>", pcdata(read_file(links_path)))
      rows[#rows + 1] = "<div style='margin-top:.5rem'><button class='cbi-button cbi-button-apply' name='_watchdog_save_links_text' value='1'>" .. _("Save LINKS_FILE") .. "</button></div>"
      rows[#rows + 1] = "</div></details></div>"
      return table.concat(rows, "\n")
    end
  end

  do
    local sec = m:section(SimpleSection)
    local dv = sec:option(DummyValue, "_watchdog_share")
    dv.rawhtml = true
    function dv.cfgvalue()
      local rows = {}
      local mode = share_cfg.selection_mode or "all"
      local current_entries = share.parse_links_file(links_path)
      local plain_url, base64_url
      if share_auth_mode == "token" and share_token ~= "" then
        plain_url = public_luci_url("tproxy-manager", "subscription", "plain", share_token)
        base64_url = public_luci_url("tproxy-manager", "subscription", "base64", share_token)
      else
        plain_url = public_luci_url("tproxy-manager", "subscription", "plain")
        base64_url = public_luci_url("tproxy-manager", "subscription", "base64")
      end
      rows[#rows + 1] = "<details class='wd-details'><summary>" .. _("Shared router subscription") .. "</summary><div class='box' style='margin-top:.5rem'>"
      if share_auth_mode == "token" then
        if share_token == "" then
          rows[#rows + 1] = "<div style='color:#b45309;margin-bottom:.6rem'>" ..
            _("Token mode is selected but no token has been generated yet - the URLs below will not work until you generate one.") .. "</div>"
        else
          rows[#rows + 1] = "<div style='color:#166534;margin-bottom:.6rem'>" ..
            _("These URLs only work with the current token. Rotating the token immediately invalidates any link shared before.") .. "</div>"
        end
      else
        rows[#rows + 1] = "<div style='color:#b45309;margin-bottom:.6rem'>" ..
          _("These subscription URLs are public. Anyone who knows the URL can download the exported proxy list.") .. "</div>"
      end
      rows[#rows + 1] = string.format([[
<div class="wd-grid">
  <label>%s</label><input type="checkbox" name="watchdog_share_enabled" value="1" %s>
  <label>%s</label>
  <select name="watchdog_share_auth_mode">
    <option value="public"%s>%s</option>
    <option value="token"%s>%s</option>
  </select>
  <label>%s</label>
  <select id="share_selection_mode" name="share_selection_mode">
    <option value="all"%s>%s</option>
    <option value="selected"%s>%s</option>
  </select>
  <label>%s</label><input type="text" name="watchdog_share_file" value="%s">
  <label>%s</label><div>%s</div>
  <label>%s</label><div>%s</div>
</div>]],
        pcdata(_("Enable sharing")),
        share_enabled and "checked" or "",
        pcdata(_("Access")),
        share_auth_mode == "public" and " selected" or "",
        pcdata(_("Public (no token)")),
        share_auth_mode == "token" and " selected" or "",
        pcdata(_("Token required")),
        pcdata(_("Link selection")),
        mode == "all" and " selected" or "",
        pcdata(_("All links")),
        mode == "selected" and " selected" or "",
        pcdata(_("Selected links")),
        pcdata(_("Shared subscription file")),
        pcdata(share_file),
        pcdata(_("Available links")),
        pcdata(tostring(#current_entries)),
        pcdata(_("Exported links")),
        pcdata(tostring(#share_export_entries)))

      if share_auth_mode == "token" then
        rows[#rows + 1] = string.format([[
<div class="wd-grid" style="margin-top:.4rem">
  <label>%s</label><div class="wd-share-url"><input type="text" readonly value="%s" onclick="this.select()">
  <button type="submit" class="cbi-button cbi-button-action" name="_share_rotate_token" value="1" onclick="return confirm('%s')">%s</button></div>
</div>]],
          pcdata(_("Current token")),
          pcdata(share_token ~= "" and share_token or _("(not generated yet)")),
          pcdata(_("Rotate the token? Any link shared before this stops working immediately.")),
          pcdata(_("Generate / rotate token")))
      end

      rows[#rows + 1] = string.format([[
<table class="wd-table" style="margin-top:.7rem">
  <thead><tr><th style="width:16%%">%s</th><th style="width:84%%">URL</th></tr></thead>
  <tbody>
    <tr>
      <td>plain</td>
      <td><div class="wd-share-url"><input id="share_url_plain" type="text" readonly value="%s" onclick="this.select()"><button type="button" class="cbi-button cbi-button-action" title="%s" onclick="var e=document.getElementById('share_url_plain');e.select();if(navigator.clipboard){navigator.clipboard.writeText(e.value);}else{document.execCommand('copy');}">📋</button></div></td>
    </tr>
    <tr>
      <td>base64</td>
      <td><div class="wd-share-url"><input id="share_url_base64" type="text" readonly value="%s" onclick="this.select()"><button type="button" class="cbi-button cbi-button-action" title="%s" onclick="var e=document.getElementById('share_url_base64');e.select();if(navigator.clipboard){navigator.clipboard.writeText(e.value);}else{document.execCommand('copy');}">📋</button></div></td>
    </tr>
  </tbody>
</table>
<div style="margin-top:.5rem;color:#6b7280">%s</div>]],
        pcdata(_("Format")),
        pcdata(plain_url),
        pcdata(_("Copy")),
        pcdata(base64_url),
        pcdata(_("Copy")),
        pcdata(_("Recommended format: base64 for v2RayTun, Shadowrocket, v2Box and V2rayNG; plain for Happ and clients that accept raw proxy lists.")))

      rows[#rows + 1] = "<div style='margin-top:.6rem'><button class='cbi-button cbi-button-apply' name='_share_save' value='1'>" .. _("Save sharing settings") .. "</button></div>"
      rows[#rows + 1] = [[
<script>
(function(){
  function initShareSelection(){
    var mode = document.getElementById('share_selection_mode');
    var boxes = document.querySelectorAll('.wd-share-checkbox');
    if (!mode || !boxes.length) return;
    function syncShareBoxes(){
      var selectedMode = mode.value === 'selected';
      for (var i = 0; i < boxes.length; i++) {
        var box = boxes[i];
        var blocked = box.getAttribute('data-share-blocked') === '1';
        box.disabled = !selectedMode || blocked;
        if (selectedMode) {
          box.checked = box.getAttribute('data-share-selected') === '1';
        } else {
          box.checked = !blocked;
        }
      }
    }
    mode.addEventListener('change', syncShareBoxes);
    syncShareBoxes();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initShareSelection);
  } else {
    initShareSelection();
  }
})();
</script>]]
      rows[#rows + 1] = "</div></details>"
      return table.concat(rows, "\n")
    end
  end

  do
    local sec = m:section(SimpleSection)
    local dv = sec:option(DummyValue, "_watchdog_settings")
    dv.rawhtml = true
    function dv.cfgvalue()
      return string.format([[
<details class="wd-details">
  <summary>%s</summary>
  <div class="box" style="margin-top:.5rem">
    <div class="wd-grid">
      <label>%s</label><input type="text" name="watchdog_check_url" value="%s">
      <label>%s</label><input type="text" name="watchdog_proxy_url" value="%s">
      <label>%s</label><input type="number" min="1" name="watchdog_interval" value="%s">
      <label>%s</label><input type="number" min="1" name="watchdog_fail_threshold" value="%s">
      <label>%s</label><input type="number" min="1" name="watchdog_connect_timeout" value="%s">
      <label>%s</label><input type="number" min="1" name="watchdog_max_time" value="%s">
      <label>%s</label><input type="text" name="watchdog_outbound_file" value="%s">
      <label>%s</label><input type="text" name="watchdog_vless2json" value="%s">
      <label>%s</label><input type="text" name="watchdog_proxy2mihomo" value="%s">
      <label>%s</label><input type="text" name="watchdog_proxy2singbox" value="%s">
      <label>%s</label><input type="text" name="watchdog_service_path" value="%s">
      <label>%s</label><input type="text" value="restart" readonly>
      <label>%s</label><input type="text" name="watchdog_test_command" value="%s">
      <label>%s</label><input type="text" name="watchdog_hysteria_template_file" value="%s">
      <label>%s</label><input type="text" name="watchdog_hysteria_test_template_file" value="%s">
      <label>%s</label><input type="text" name="watchdog_mihomo_test_template_file" value="%s">
      <label>%s</label><input type="text" name="watchdog_singbox_test_template_file" value="%s">
      <label>%s</label>
      <select name="watchdog_selection_mode">
        <option value="ordered"%s>%s</option>
        <option value="random"%s>%s</option>
        <option value="fastest"%s>%s</option>
      </select>
      <label>%s</label><input type="checkbox" name="watchdog_exclude_dead" value="1" %s>
      <label>%s</label><input type="number" min="0" name="watchdog_dead_cooldown_hours" value="%s">
      <label>%s</label><input type="number" min="0" max="59" name="watchdog_dead_cooldown_minutes" value="%s">
      <label>%s</label><input type="number" min="1" max="65535" name="watchdog_test_port" value="%s">
      <label>%s</label><input type="checkbox" name="watchdog_background_check_enabled" value="1" %s>
      <label>%s</label><input type="number" min="1" name="watchdog_background_check_interval" value="%s">
      <label>%s</label><input type="checkbox" name="watchdog_batch_check_enabled" value="1" %s>
      <label>%s</label><input type="text" name="watchdog_batch_test_template_file" value="%s">
      <label>%s</label><input type="text" name="watchdog_hysteria_batch_test_template_file" value="%s">
      <label>%s</label><input type="text" name="watchdog_mihomo_batch_test_template_file" value="%s">
      <label>%s</label><input type="text" name="watchdog_singbox_batch_test_template_file" value="%s">
      <label>%s</label><input type="number" min="1" max="65535" name="watchdog_batch_check_port_start" value="%s">
      <label>%s</label><input type="number" min="1" name="watchdog_batch_check_batch_size" value="%s">
      <label>%s</label><input type="number" min="1" name="watchdog_batch_check_concurrency" value="%s">
      <label>%s</label><input type="checkbox" name="watchdog_batch_check_fallback" value="1" %s>
      <label>%s</label><input type="text" name="watchdog_subscriptions_file" value="%s">
      <label>%s</label><input type="number" min="1" name="watchdog_happ_capture_ttl" value="%s">
      <label>%s</label><input type="number" min="1" max="65535" name="watchdog_happ_capture_port" value="%s">
      <label>%s</label><input type="text" name="watchdog_happ_capture_log" value="%s">
    </div>
    <div style="margin-top:.6rem">
      <button class="cbi-button cbi-button-apply" name="_watchdog_save_settings" value="1">%s</button>
    </div>
  </div>
</details>]],
        pcdata(_("Watchdog settings")),
        pcdata(_("Check URL")),
        pcdata(getu("watchdog_check_url", "https://ifconfig.me/ip")),
        pcdata(_("Proxy URL")),
        pcdata(getu("watchdog_proxy_url", "socks5h://127.0.0.1:10808")),
        pcdata(_("Check interval, sec")),
        pcdata(getu("watchdog_interval", "60")),
        pcdata(_("Failure threshold")),
        pcdata(getu("watchdog_fail_threshold", "3")),
        pcdata(_("Connect timeout, sec")),
        pcdata(getu("watchdog_connect_timeout", "15")),
        pcdata(_("Max request time, sec")),
        pcdata(getu("watchdog_max_time", "20")),
        pcdata(_("Outbound file")),
        pcdata(getu("watchdog_outbound_file", "/etc/xray/04_outbounds.json")),
        pcdata(_("Link converter")),
        pcdata(getu("watchdog_vless2json", "/usr/bin/vless2json.sh")),
        pcdata(_("Mihomo converter")),
        pcdata(getu("watchdog_proxy2mihomo", "/usr/bin/proxy2mihomo.lua")),
        pcdata(_("sing-box converter")),
        pcdata(getu("watchdog_proxy2singbox", "/usr/bin/proxy2singbox.lua")),
        pcdata(_("Managed service")),
        pcdata(getu("watchdog_service_path", "/etc/init.d/xray")),
        pcdata(_("Restart command")),
        pcdata(_("Test command")),
        pcdata(getu("watchdog_test_command", "/usr/bin/xray -c {config}")),
        pcdata(_("Hysteria outbound template")),
        pcdata(getu("watchdog_hysteria_template_file", "/etc/tproxy-manager/watchdog-hysteria-outbound.template.jsonc")),
        pcdata(_("Hysteria test template")),
        pcdata(getu("watchdog_hysteria_test_template_file", "/etc/tproxy-manager/watchdog-hysteria-test-config.template.jsonc")),
        pcdata(_("Mihomo test template")),
        pcdata(getu("watchdog_mihomo_test_template_file", "/etc/tproxy-manager/watchdog-mihomo-test-config.template.yaml")),
        pcdata(_("sing-box test template")),
        pcdata(getu("watchdog_singbox_test_template_file", "/etc/tproxy-manager/watchdog-singbox-test-config.template.jsonc")),
        pcdata(_("Selection mode")),
        getu("watchdog_selection_mode", "random") == "ordered" and " selected" or "",
        pcdata(_("ordered")),
        getu("watchdog_selection_mode", "random") == "random" and " selected" or "",
        pcdata(_("random")),
        getu("watchdog_selection_mode", "random") == "fastest" and " selected" or "",
        pcdata(_("fastest")),
        pcdata(_("Exclude dead links")),
        getu("watchdog_exclude_dead", "0") == "1" and "checked" or "",
        pcdata(_("Exclusion period: hours")),
        pcdata(getu("watchdog_dead_cooldown_hours", "0")),
        pcdata(_("Exclusion period: minutes")),
        pcdata(getu("watchdog_dead_cooldown_minutes", "0")),
        pcdata(_("Test port")),
        pcdata(getu("watchdog_test_port", "10881")),
        pcdata(_("Background link check")),
        getu("watchdog_background_check_enabled", "0") == "1" and "checked" or "",
        pcdata(_("Background check timer, sec")),
        pcdata(getu("watchdog_background_check_interval", "1800")),
        pcdata(_("Batch link check")),
        getu("watchdog_batch_check_enabled", "1") == "1" and "checked" or "",
        pcdata(_("Batch test template")),
        pcdata(getu("watchdog_batch_test_template_file", "/etc/tproxy-manager/watchdog-batch-test-config.template.jsonc")),
        pcdata(_("Hysteria batch test template")),
        pcdata(getu("watchdog_hysteria_batch_test_template_file", "/etc/tproxy-manager/watchdog-hysteria-batch-test-config.template.jsonc")),
        pcdata(_("Mihomo batch test template")),
        pcdata(getu("watchdog_mihomo_batch_test_template_file", "/etc/tproxy-manager/watchdog-mihomo-batch-test-config.template.yaml")),
        pcdata(_("sing-box batch test template")),
        pcdata(getu("watchdog_singbox_batch_test_template_file", "/etc/tproxy-manager/watchdog-singbox-batch-test-config.template.jsonc")),
        pcdata(_("Batch start port")),
        pcdata(getu("watchdog_batch_check_port_start", "10882")),
        pcdata(_("Batch size")),
        pcdata(getu("watchdog_batch_check_batch_size", "64")),
        pcdata(_("Batch concurrency")),
        pcdata(getu("watchdog_batch_check_concurrency", "8")),
        pcdata(_("Fallback to old check")),
        getu("watchdog_batch_check_fallback", "1") == "1" and "checked" or "",
        pcdata(_("Subscriptions file")),
        pcdata(getu("watchdog_subscriptions_file", DEFAULT_SUBSCRIPTIONS_FILE)),
        pcdata(_("Happ capture TTL, sec")),
        pcdata(getu("watchdog_happ_capture_ttl", "600")),
        pcdata(_("Happ capture port")),
        pcdata(getu("watchdog_happ_capture_port", "18088")),
        pcdata(_("Happ capture log")),
        pcdata(getu("watchdog_happ_capture_log", DEFAULT_CAPTURE_LOG)),
        pcdata(_("Save Watchdog settings")))
    end
  end

  do
    local sec = m:section(SimpleSection)
    local dv = sec:option(DummyValue, "_watchdog_template")
    dv.rawhtml = true
    function dv.cfgvalue()
      local selected = template_choice_by_id(http.formvalue("watchdog_template_kind"))
      local current_path = getu(selected.key, selected.fallback)
      local options = {}
      local template_data = {}
      for __, choice in ipairs(TEMPLATE_CHOICES) do
        local path = getu(choice.key, choice.fallback)
        template_data[choice.id] = {
          path = path,
          text = read_file(path)
        }
        options[#options + 1] = string.format(
          "<option value='%s'%s>%s</option>",
          pcdata(choice.id),
          choice.id == selected.id and " selected" or "",
          pcdata(_(choice.label)))
      end
      local template_json = (jsonc.stringify(template_data, true) or "{}"):gsub("</script", "<\\/script")
      return [[
<details class="wd-details">
  <summary>]] .. pcdata(_("Templates editor")) .. [[</summary>
  <div class="box editor-wrap editor-wide" style="margin-top:.5rem">
    <div class="wd-grid" style="margin-bottom:.5rem">
      <label>]] .. pcdata(_("Template type")) .. [[</label>
      <select name="watchdog_template_kind" id="watchdog_template_kind">
        ]] .. table.concat(options, "\n        ") .. [[
      </select>
      <label>]] .. pcdata(_("Template file")) .. [[</label><input type="text" name="watchdog_template_path" value="]] .. pcdata(current_path) .. [[">
    </div>
    <div style="margin-bottom:.4rem;color:#6b7280">]] .. pcdata(_("Choose a VLESS or Hysteria 2 template, edit it and save it back to its own file. The active path is also stored in UCI settings.")) .. [[</div>
    <textarea class="wd-textarea" name="watchdog_template_text" rows="18" spellcheck="false">]] .. pcdata(template_data[selected.id] and template_data[selected.id].text or "") .. [[</textarea>
    <div style="height:5px"></div>
    <div class="box editor-wrap editor-680" id="watchdog-template-status-box">
      <div id="watchdog_template_status" style="margin:.08rem 0 .14rem 0; font-weight:600"></div>
    </div>
    <div style="margin-top:.5rem">
      <button class="cbi-button cbi-button-apply" name="_watchdog_save_template" value="1">]] .. pcdata(_("Save template")) .. [[</button>
    </div>
  </div>
</details>
<script>
(function(){
  var templateStore = ]] .. template_json .. [[;
  function stripJsonComments(str){
    var out = '', i = 0, n = str.length, inStr = false, esc = false;
    while (i < n) {
      var c = str[i], d = str[i + 1];
      if (inStr) { out += c; if (esc) { esc = false; } else if (c === '\\') { esc = true; } else if (c === '"') { inStr = false; } i++; continue; }
      if (c === '"') { inStr = true; out += c; i++; continue; }
      if (c === '/' && d === '/') { i += 2; while (i < n && str[i] !== '\n') i++; continue; }
      if (c === '/' && d === '*') { i += 2; while (i < n - 1 && !(str[i] === '*' && str[i + 1] === '/')) i++; i += 2; continue; }
      out += c; i++;
    }
    return out;
  }
  function normalizeTemplateJsonc(str){
    var replacements = {
      __ADDRESS__: '127.0.0.1',
      __PORT__: '443',
      __UUID__: '00000000-0000-0000-0000-000000000000',
      __FLOW__: '',
      __NETWORK__: 'tcp',
      __SECURITY__: 'none',
      __SERVER_NAME__: 'example.com',
      __FINGERPRINT__: 'chrome',
      __PUBLIC_KEY__: '',
      __SHORT_ID__: '',
      __SPIDER_X__: '/',
      __HEADER_TYPE__: 'none',
      __REMARKS__: 'template',
      __TEST_PORT__: '10881',
      __OUTBOUND_TAG__: 'proxy',
      __OUTBOUNDS__: '[]',
      __BATCH_INBOUNDS__: '[]',
      __BATCH_OUTBOUNDS__: '[]',
      __BATCH_RULES__: '[]',
      __HY2_AUTH__: 'password',
      __HY2_STREAM_SETTINGS__: '{}',
      __HY2_HYSTERIA_SETTINGS__: '{}',
      __HY2_TLS_SETTINGS__: '{}',
      __HY2_UDPMASKS__: '[]',
      __ALLOW_INSECURE__: 'false',
      __ALLOW_INSECURE_BOOL__: 'false',
      __ALPN__: 'h3',
      __ALPN_ARRAY__: '[]',
      __HY2_ALPN_ARRAY__: '[]'
    };
    return str.replace(/\b__[A-Z0-9_]+__\b/g, function(token){
      return Object.prototype.hasOwnProperty.call(replacements, token) ? replacements[token] : token;
    });
  }
  var sel = document.getElementById('watchdog_template_kind');
  var pathInput = document.querySelector('input[name="watchdog_template_path"]');
  var ta = document.querySelector('textarea[name="watchdog_template_text"]');
  var badge = document.getElementById('watchdog_template_status');
  if (!sel || !pathInput || !ta || !badge) return;
  var current = sel.value || 'vless_outbound';
  function debounce(fn, ms){ var t; return function(){ clearTimeout(t); t = setTimeout(fn, ms); }; }
  function ensureEntry(id){
    if (!templateStore[id]) templateStore[id] = { path: '', text: '' };
    return templateStore[id];
  }
  function rememberCurrent(){
    var item = ensureEntry(current);
    item.path = pathInput.value || '';
    item.text = ta.value || '';
  }
  function loadTemplate(id){
    rememberCurrent();
    current = id || current;
    var item = ensureEntry(current);
    pathInput.value = item.path || '';
    ta.value = item.text || '';
    validate();
  }
  function saveEditorPosition(){
    try {
      sessionStorage.setItem('tpm.watchdog.template.editor', JSON.stringify({
        kind: current,
        pageY: window.scrollY || document.documentElement.scrollTop || 0,
        textY: ta.scrollTop || 0,
        selStart: ta.selectionStart || 0,
        selEnd: ta.selectionEnd || 0,
        focused: document.activeElement === ta ? 'textarea' : (document.activeElement === pathInput ? 'path' : (document.activeElement === sel ? 'select' : ''))
      }));
    } catch(e) {}
  }
  function restoreEditorPosition(){
    try {
      var raw = sessionStorage.getItem('tpm.watchdog.template.editor');
      if (!raw) return;
      sessionStorage.removeItem('tpm.watchdog.template.editor');
      var st = JSON.parse(raw);
      if (st.kind && st.kind !== current && templateStore[st.kind]) {
        sel.value = st.kind;
        loadTemplate(st.kind);
      }
      if (typeof st.textY === 'number') ta.scrollTop = st.textY;
      if (typeof st.selStart === 'number' && typeof st.selEnd === 'number') ta.setSelectionRange(st.selStart, st.selEnd);
      if (st.focused === 'textarea') ta.focus();
      else if (st.focused === 'path') pathInput.focus();
      else if (st.focused === 'select') sel.focus();
      if (typeof st.pageY === 'number') setTimeout(function(){ window.scrollTo(0, st.pageY); }, 0);
    } catch(e) {}
  }
  function validate(){
    try {
      JSON.parse(normalizeTemplateJsonc(stripJsonComments(ta.value)));
      badge.textContent = ']] .. pcdata(_("Template JSONC is valid")) .. [[';
      badge.style.color = '#16a34a';
    } catch(e) {
      badge.textContent = '';
      badge.style.color = '#dc2626';
      badge.appendChild(document.createTextNode(']] .. pcdata(_("JSONC error:").." ") .. [[' + e.message + ' '));
      var m = String(e.message || '').match(/position (\d+)/);
      if (m) {
        var pos = parseInt(m[1], 10);
        var jump = document.createElement('a');
        jump.href = '#';
        jump.textContent = ']] .. pcdata(_("jump to error")) .. [[';
        jump.onclick = function(ev){
          ev.preventDefault();
          var p = Math.min(pos, ta.value.length);
          ta.focus();
          ta.setSelectionRange(p, Math.min(p + 1, ta.value.length));
          var before = ta.value.slice(0, p), line = before.split('\n').length;
          var lh = parseFloat(getComputedStyle(ta).lineHeight) || 18;
          ta.scrollTop = Math.max(0, (line - 3) * lh);
        };
        badge.appendChild(jump);
      }
    }
  }
  ta.addEventListener('input', debounce(validate, 200));
  ta.addEventListener('input', rememberCurrent);
  pathInput.addEventListener('input', rememberCurrent);
  sel.addEventListener('change', function(){ loadTemplate(sel.value); });
  var form = sel.closest && sel.closest('form');
  if (form) form.addEventListener('submit', function(e){
    var submitter = e.submitter || document.activeElement;
    var isTemplateSave = submitter && submitter.name === '_watchdog_save_template';
    rememberCurrent();
    if (isTemplateSave) saveEditorPosition();
  }, true);
  validate();
  restoreEditorPosition();
})();
</script>]]
    end
  end

  do
    local sec = m:section(SimpleSection)
    local dv = sec:option(DummyValue, "_watchdog_log")
    dv.rawhtml = true
    -- The "check start: proxy=... url=..." line is written on EVERY tick of
    -- the background check (every watchdog_interval, usually 60s) and makes
    -- up 90%+ of the log, drowning out the events that actually matter
    -- (batch-check results, subscription errors, etc.) in repeated noise.
    -- Visually de-emphasize these heartbeat lines instead of hiding them
    -- outright — the history stays available, but the eye can pick out what
    -- actually matters more easily.
    local function render_log_lines(text)
      local out = {}
      for line in (text .. "\n"):gmatch("([^\n]*)\n") do
        if line:find("check start: proxy=", 1, true) then
          out[#out + 1] = "<span class='wd-log-heartbeat'>" .. pcdata(line) .. "</span>"
        elseif line ~= "" then
          out[#out + 1] = pcdata(line)
        else
          out[#out + 1] = ""
        end
      end
      return table.concat(out, "\n")
    end
    function dv.cfgvalue()
      return [[<details class="wd-details"><summary><strong>]] .. pcdata(_("Watchdog log")) .. [[</strong></summary><div class="box editor-wrap" style="margin-top:.5rem"><div style="margin-bottom:.5rem"><button class="cbi-button cbi-button-remove" name="_watchdog_clear_log" value="1">]] .. pcdata(_("Clear log")) .. [[</button></div><style>.wd-log-heartbeat{color:#9ca3af}</style><pre style="white-space:pre-wrap;max-height:30rem;overflow:auto">]] ..
             render_log_lines(helpers.watchdog_log()) .. [[</pre></div></details>]]
    end
  end
end

return { render = render }
