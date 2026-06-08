local cbi = require "luci.cbi"
local SimpleSection, DummyValue = cbi.SimpleSection, cbi.DummyValue

local sys = require "luci.sys"
local http = require "luci.http"
local xml = require "luci.xml"
local jsonc = require "luci.jsonc"
local helpers = require "luci.model.cbi.tproxy_manager.modules.watchdog_helpers"
local utils = require "luci.model.cbi.tproxy_manager.utils"
local happ_decrypt = require "tproxy_manager.happ_decrypt"
local _ = require "luci.model.cbi.tproxy_manager.i18n"

local pcdata = xml.pcdata

local SUBSCRIPTIONS_SCRIPT = "/usr/bin/tproxy-manager-subscriptions.lua"
local WATCHDOG_LINK_STATE_DIR = "/tmp/tproxy-manager-watchdog-links"
local DEFAULT_SUBSCRIPTIONS_FILE = "/etc/tproxy-manager/watchdog-subscriptions.json"
local DEFAULT_CAPTURE_LOG = "/tmp/tproxy-manager-happ-capture.log"

local function read_file(path)
  return utils.read_file(path)
end

local function write_file(path, data)
  utils.write_file(path, data or "")
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

local function run_subscription_command(args)
  local parts = { shellescape(SUBSCRIPTIONS_SCRIPT) }
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

local function write_subscription_db(path, db)
  write_file(path, jsonc.stringify(normalize_subscription_db(db), true) .. "\n")
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
      for _ in pairs(item.sources) do has_source = true; break end
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
  if sig.uuid == "" or sig.address == "" or sig.port == "" then return false end
  if not config_text:find(sig.uuid, 1, true) then return false end
  if not config_text:find(sig.address, 1, true) then return false end
  if not config_text:find(sig.port, 1, true) then return false end
  local strong = 0
  if sig.public_key ~= "" and config_text:find(sig.public_key, 1, true) then strong = strong + 1 end
  if sig.short_id ~= "" and config_text:find(sig.short_id, 1, true) then strong = strong + 1 end
  if sig.server_name ~= "" and config_text:find(sig.server_name, 1, true) then strong = strong + 1 end
  return strong > 0 or (sig.public_key == "" and sig.short_id == "" and sig.server_name == "")
end

local function find_active_entry(links, status)
  local outbound_file = trim(status.OUTBOUND_FILE or "")
  if outbound_file ~= "" then
    local config_text = read_file(outbound_file)
    if config_text ~= "" then
      for __, entry in ipairs(links or {}) do
        if config_contains_signature(config_text, vless_signature(entry.raw_link or entry.link or "")) then
          return entry, "config"
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
    if form_capture_log ~= "" then capture_log = form_capture_log end
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

  if http.formvalue("_sub_save") == "1" then
    local db = read_subscription_db(subscriptions_path)
    local id = tonumber(http.formvalue("sub_id"))
    local existing = id and find_subscription(db, id) or nil
    local sub = collect_subscription_form(existing)
    if sub.url == "" then
      set_err(_("Subscription URL is required."))
    elseif sub.timeout < 1 then
      set_err(_("Subscription timeout must be at least 1 second."))
    elseif sub.refresh_interval < 1 then
      set_err(_("Subscription refresh timer must be at least 1 second."))
    else
      if existing then
        sub.id = existing.id
        local _unused, idx = find_subscription(db, existing.id)
        db.subscriptions[idx] = sub
      else
        sub.id = next_subscription_id(db)
        db.subscriptions[#db.subscriptions + 1] = sub
      end
      write_subscription_db(subscriptions_path, db)
      set_err(nil)
      set_info(_("Subscription saved."))
      helpers.redirect_watchdog()
      return m
    end
  end

  if http.formvalue("_sub_delete") then
    local db = read_subscription_db(subscriptions_path)
    local sub, idx = find_subscription(db, http.formvalue("_sub_delete"))
    if sub and idx then
      remove_subscription_sources(db, sub)
      table.remove(db.subscriptions, idx)
      write_subscription_db(subscriptions_path, db)
      run_subscription_command({ "sync-links" })
      set_err(nil)
      set_info(_("Subscription deleted."))
      helpers.redirect_watchdog()
      return m
    end
    set_err(_("Subscription not found."))
  end

  if http.formvalue("_sub_fetch") then
    local id = trim(http.formvalue("_sub_fetch"))
    local rc, out = run_subscription_command({ "fetch", id })
    if rc == 0 then set_info(out ~= "" and out or (_("Subscription updated: ") .. id)) else set_err(out ~= "" and out or (_("Failed to update subscription: ") .. id)) end
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
    local path = trim(http.formvalue("watchdog_template_file"))
    local text = http.formvalue("watchdog_template_text") or ""
    if path == "" then
      set_err(_("Template file path is required."))
    elseif not helpers.validate_jsonc_text(text) then
      set_err(_("Invalid template JSON/JSONC."))
    else
      uci:set(PKG, "main", "watchdog_template_file", path)
      uci:commit(PKG)
      write_file(path, text)
      set_err(nil)
      set_info(_("Watchdog template saved: ") .. path)
      helpers.redirect_watchdog()
      return m
    end
  end

  if http.formvalue("_watchdog_save_test_template") == "1" then
    local path = trim(http.formvalue("watchdog_test_template_file"))
    local text = http.formvalue("watchdog_test_template_text") or ""
    if path == "" then
      set_err(_("Test template file path is required."))
    else
      uci:set(PKG, "main", "watchdog_test_template_file", path)
      uci:commit(PKG)
      write_file(path, text)
      set_err(nil)
      set_info(_("Test template saved: ") .. path)
      helpers.redirect_watchdog()
      return m
    end
  end

  if http.formvalue("_watchdog_save_links_text") == "1" then
    local path = trim(http.formvalue("watchdog_links_file"))
    local text = (http.formvalue("watchdog_links_text") or ""):gsub("\r\n", "\n")
    local ok, bad_line = helpers.validate_links_text(text)
    if path == "" then
      set_err(_("LINKS_FILE path is required."))
    elseif not ok then
      set_err(_("Invalid line in LINKS_FILE: ") .. tostring(bad_line))
    else
      uci:set(PKG, "main", "watchdog_links_file", path)
      uci:commit(PKG)
      write_file(path, text ~= "" and (text:gsub("\n*$", "") .. "\n") or "")
      set_err(nil)
      set_info(_("LINKS_FILE saved: ") .. path)
      helpers.redirect_watchdog()
      return m
    end
  end

  if http.formvalue("_watchdog_clear_log") == "1" then
    helpers.clear_watchdog_log()
    set_err(nil)
    set_info(_("Watchdog log cleared."))
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
    local rc, out = helpers.run_watchdog_command({ "check-all" })
    if rc == 0 then set_info(out ~= "" and out or _("All links check completed.")) else set_err(out ~= "" and out or _("Links check failed.")) end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_wd_apply") then
    local hash = trim(http.formvalue("_wd_apply"))
    local rc, out = helpers.run_watchdog_command({ "apply-link", hash })
    if rc == 0 then set_info(out ~= "" and out or (_("Link applied: ") .. hash)) else set_err(out ~= "" and out or (_("Failed to apply link: ") .. hash)) end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_wd_test") then
    local hash = trim(http.formvalue("_wd_test"))
    local rc, out = helpers.run_watchdog_command({ "test-link", hash })
    if rc == 0 then set_info(out ~= "" and out or (_("Link checked: ") .. hash)) else set_err(out ~= "" and out or (_("Link check failed: ") .. hash)) end
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
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_wd_add") == "1" then
    local entries = helpers.parse_links_file(links_path)
    local raw_link = trim(http.formvalue("wd_add_link"))
    local parsed = helpers.parse_link_line(raw_link)
    if not parsed then
      set_err(_("Added line must start with vless://"))
    else
      entries[#entries + 1] = { raw_link = parsed.raw_link }
      helpers.write_links_file(links_path, entries)
      set_err(nil)
      set_info(_("Link added."))
      helpers.redirect_watchdog()
      return m
    end
  end

  if http.formvalue("_wd_edit_save") == "1" then
    local entries = helpers.parse_links_file(links_path)
    local hash = trim(http.formvalue("wd_edit_hash"))
    local idx = helpers.find_entry_index(entries, hash)
    local raw_link = trim(http.formvalue("wd_edit_link"))
    local parsed = helpers.parse_link_line(raw_link)
    local db = read_subscription_db(subscriptions_path)
    if not idx then
      set_err(_("Editable link not found."))
    elseif is_subscription_link(db, hash) then
      set_err(_("Subscription links cannot be edited directly. Exclude the link or edit the subscription."))
    elseif not parsed then
      set_err(_("Link must start with vless://"))
    else
      entries[idx].raw_link = parsed.raw_link
      helpers.write_links_file(links_path, entries)
      set_err(nil)
      set_info(_("Link updated."))
      helpers.redirect_watchdog()
      return m
    end
  end

  if http.formvalue("_wd_delete") then
    local entries = helpers.parse_links_file(links_path)
    local hash = trim(http.formvalue("_wd_delete"))
    local idx = helpers.find_entry_index(entries, hash)
    if idx then
      table.remove(entries, idx)
      helpers.write_links_file(links_path, entries)
      set_err(nil)
      set_info(_("Link deleted."))
      helpers.redirect_watchdog()
      return m
    end
    set_err(_("Link to delete was not found."))
  end

  if http.formvalue("_wd_move_up") or http.formvalue("_wd_move_down") then
    local entries = helpers.parse_links_file(links_path)
    local hash = trim(http.formvalue("_wd_move_up") or http.formvalue("_wd_move_down"))
    local idx = helpers.find_entry_index(entries, hash)
    if idx then
      local swap_idx = http.formvalue("_wd_move_up") and (idx - 1) or (idx + 1)
      if swap_idx >= 1 and swap_idx <= #entries then
        entries[idx], entries[swap_idx] = entries[swap_idx], entries[idx]
        helpers.write_links_file(links_path, entries)
        set_err(nil)
        set_info(_("Link order updated."))
      end
      helpers.redirect_watchdog()
      return m
    end
    set_err(_("Link to reorder was not found."))
  end

  local status_rc, status_out = helpers.run_watchdog_command({ "status" })
  local status = status_rc == 0 and helpers.parse_kv_text(status_out) or {}
  local edit_hash = trim(http.formvalue("wd_edit_hash"))
  local edit_sub_id = trim(http.formvalue("sub_edit_id"))
  local sub_db = read_subscription_db(subscriptions_path)
  local edit_sub = edit_sub_id ~= "" and find_subscription(sub_db, edit_sub_id) or nil
  local links = helpers.parse_links_file(links_path)
  links = merge_excluded_subscription_links(links, sub_db)
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
    <button type="button" class="cbi-button cbi-button-action" title="%s" style="min-width:2.4rem;padding-left:.45rem;padding-right:.45rem" onclick="var e=document.getElementById('happ_capture_url');e.select();if(navigator.clipboard){navigator.clipboard.writeText(e.value);}else{document.execCommand('copy');}">💾</button>
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
    local sec = m:section(SimpleSection, _("VLESS link list"))
    local dv = sec:option(DummyValue, "_watchdog_links")
    dv.rawhtml = true
    function dv.cfgvalue()
      local rows = {}
      rows[#rows + 1] = "<div class='box'>"
      rows[#rows + 1] = "<table class='wd-table'><thead><tr><th style='width:10%'>" .. _("Source") .. "</th><th style='width:16%'>" .. _("Comment") .. "</th><th style='width:36%'>" .. _("VLESS link") .. "</th><th style='width:10%'>" .. _("Status") .. "</th><th style='width:12%'>" .. _("Last check") .. "</th><th style='width:16%'>" .. _("Action") .. "</th></tr></thead><tbody>"
      if #links == 0 then
        rows[#rows + 1] = "<tr><td colspan='6' style='color:#6b7280'>" .. _("Link list is empty") .. "</td></tr>"
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
  <td><input type="hidden" name="wd_edit_hash" value="%s"><div style="color:#6b7280">%s</div></td>
  <td><input type="text" name="wd_edit_link" value="%s" style="width:100%%"></td>
  <td>%s</td>
  <td>%s</td>
  <td class="actions">
    <button class="cbi-button cbi-button-apply" name="_wd_edit_save" value="1">%s</button>
    <button class="cbi-button cbi-button-reset" name="_wd_edit_cancel" value="1">%s</button>
  </td>
</tr>]],
            row_class, source_html, pcdata(entry.hash), pcdata(entry.comment or "—"), pcdata(entry.raw_link or ""), label, pcdata(checked),
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
  <td style="color:#6b7280">]] .. pcdata(_("New link file line")) .. [[</td>
  <td><input type="text" name="wd_add_link" placeholder="vless://..." style="width:100%"></td>
  <td colspan="2" style="color:#6b7280">]] .. pcdata(_("Comment will be taken from the part after # inside the link")) .. [[</td>
  <td class="actions"><button class="cbi-button cbi-button-apply" name="_wd_add" value="1">]] .. pcdata(_("Add")) .. [[</button></td>
</tr>]]
      rows[#rows + 1] = "</tbody></table>"
      rows[#rows + 1] = "<details class='wd-details'><summary>" .. _("LINKS_FILE editor") .. "</summary><div class='box editor-wrap editor-wide' style='margin-top:.5rem'>"
      rows[#rows + 1] = string.format("<div class='wd-grid'><label>LINKS_FILE</label><input type='text' name='watchdog_links_file' value='%s'></div>", pcdata(links_path))
      rows[#rows + 1] = "<div style='margin:.5rem 0;color:#6b7280'>" .. _("For bulk paste: one VLESS link per line. Empty lines and lines starting with # are allowed.") .. "</div>"
      rows[#rows + 1] = string.format("<textarea class='wd-textarea' name='watchdog_links_text' rows='12' spellcheck='false'>%s</textarea>", pcdata(read_file(links_path)))
      rows[#rows + 1] = "<div style='margin-top:.5rem'><button class='cbi-button cbi-button-apply' name='_watchdog_save_links_text' value='1'>" .. _("Save LINKS_FILE") .. "</button></div>"
      rows[#rows + 1] = "</div></details></div>"
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
      <label>%s</label><input type="text" name="watchdog_service_path" value="%s">
      <label>%s</label><input type="text" value="restart" readonly>
      <label>%s</label><input type="text" name="watchdog_test_command" value="%s">
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
        pcdata(_("VLESS converter")),
        pcdata(getu("watchdog_vless2json", "/usr/bin/vless2json.sh")),
        pcdata(_("Managed service")),
        pcdata(getu("watchdog_service_path", "/etc/init.d/xray")),
        pcdata(_("Restart command")),
        pcdata(_("Test command")),
        pcdata(getu("watchdog_test_command", "/usr/bin/xray -c {config}")),
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
      local current_path = getu("watchdog_template_file", "/etc/tproxy-manager/watchdog-outbound.template.jsonc")
      local content = read_file(current_path)
      return [[
<details class="wd-details">
  <summary>]] .. pcdata(_("Outbounds template")) .. [[</summary>
  <div class="box editor-wrap editor-wide" style="margin-top:.5rem">
    <div class="wd-grid" style="margin-bottom:.5rem">
      <label>TEMPLATE_FILE</label><input type="text" name="watchdog_template_file" value="]] .. pcdata(current_path) .. [[">
    </div>
    <div style="margin-bottom:.4rem;color:#6b7280">]] .. pcdata(_("The template is stored in a separate file and is processed by the built-in /usr/bin/vless2json.sh converter by default. The path can be overridden in settings.")) .. [[</div>
    <textarea class="wd-textarea" name="watchdog_template_text" rows="18" spellcheck="false">]] .. pcdata(content) .. [[</textarea>
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
  var ta = document.querySelector('textarea[name="watchdog_template_text"]');
  var badge = document.getElementById('watchdog_template_status');
  if (!ta || !badge) return;
  function debounce(fn, ms){ var t; return function(){ clearTimeout(t); t = setTimeout(fn, ms); }; }
  function validate(){
    try {
      JSON.parse(stripJsonComments(ta.value));
      badge.textContent = ']] .. pcdata(_("Template JSONC is valid")) .. [[';
      badge.style.color = '#16a34a';
    } catch(e) {
      badge.textContent = ']] .. pcdata(_("JSONC error: ")) .. [[' + e.message;
      badge.style.color = '#dc2626';
    }
  }
  ta.addEventListener('input', debounce(validate, 200));
  validate();
})();
</script>]]
    end
  end

  do
    local sec = m:section(SimpleSection)
    local dv = sec:option(DummyValue, "_watchdog_test_template")
    dv.rawhtml = true
    function dv.cfgvalue()
      local current_path = getu("watchdog_test_template_file", "/etc/tproxy-manager/watchdog-test-config.template.jsonc")
      local content = read_file(current_path)
      return [[
<details class="wd-details">
  <summary>]] .. pcdata(_("Test template")) .. [[</summary>
  <div class="box editor-wrap editor-wide" style="margin-top:.5rem">
    <div class="wd-grid" style="margin-bottom:.5rem">
      <label>TEST_TEMPLATE_FILE</label><input type="text" name="watchdog_test_template_file" value="]] .. pcdata(current_path) .. [[">
    </div>
    <div style="margin-bottom:.4rem;color:#6b7280">]] .. pcdata(_("This template is used for the temporary test-instance. The default variant supports placeholders __TEST_PORT__, __OUTBOUNDS__ and __OUTBOUND_TAG__.")) .. [[</div>
    <textarea class="wd-textarea" name="watchdog_test_template_text" rows="18" spellcheck="false">]] .. pcdata(content) .. [[</textarea>
    <div style="margin-top:.5rem">
      <button class="cbi-button cbi-button-apply" name="_watchdog_save_test_template" value="1">]] .. pcdata(_("Save test template")) .. [[</button>
    </div>
  </div>
</details>]]
    end
  end

  do
    local sec = m:section(SimpleSection)
    local dv = sec:option(DummyValue, "_watchdog_log")
    dv.rawhtml = true
    function dv.cfgvalue()
      return [[<details class="wd-details"><summary><strong>]] .. pcdata(_("Watchdog log")) .. [[</strong></summary><div class="box editor-wrap" style="margin-top:.5rem"><div style="margin-bottom:.5rem"><button class="cbi-button cbi-button-remove" name="_watchdog_clear_log" value="1">]] .. pcdata(_("Clear log")) .. [[</button></div><pre style="white-space:pre-wrap;max-height:30rem;overflow:auto">]] ..
             pcdata(helpers.watchdog_log()) .. [[</pre></div></details>]]
    end
  end
end

return { render = render }
