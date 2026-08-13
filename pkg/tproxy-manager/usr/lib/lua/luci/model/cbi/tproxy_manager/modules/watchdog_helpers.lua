local fs = require "nixio.fs"
local sys = require "luci.sys"
local http = require "luci.http"
local disp = require "luci.dispatcher"
local utils = require "luci.model.cbi.tproxy_manager.utils"
local _ = require "luci.model.cbi.tproxy_manager.i18n"
local proxy_links = require "tproxy_manager.proxy_links"

local M = {}

local WATCHDOG_SCRIPT = "/usr/bin/tproxy-manager-watchdog.sh"
local WATCHDOG_LINK_STATE_DIR = "/tmp/tproxy-manager-watchdog-links"
local WATCHDOG_LOG_FILE = "/tmp/tproxy-manager-watchdog.log"

local md5_cache = {}
local state_cache = {}

local function trim(value)
  return utils.trim(value)
end

local function parse_int(value, fallback)
  if not tostring(value or ""):match("^%d+$") then return fallback end
  return tonumber(value)
end

local function parse_link_line(line)
  return proxy_links.parse_link_line(line)
end

local function run_cmd_capture(cmd)
  local marker = "__TPM_WD_RC__:"
  local wrapped = string.format("(%s) 2>&1; printf '\\n%s%%s' \"$?\"", cmd, marker)
  local out = sys.exec(wrapped) or ""
  local rc = tonumber(out:match(marker .. "([%-%d]+)%s*$")) or 1
  out = out:gsub("\n?" .. marker .. "[%-%d]+%s*$", "")
  return rc, trim(out)
end

function M.run_watchdog_command(args, env)
  local parts = {}
  for key, value in pairs(env or {}) do
    key = tostring(key or "")
    if key:match("^[A-Z0-9_]+$") then
      parts[#parts + 1] = key .. "=" .. utils.shellescape(value)
    end
  end
  parts[#parts + 1] = utils.shellescape(WATCHDOG_SCRIPT)
  for __, arg in ipairs(args or {}) do
    parts[#parts + 1] = utils.shellescape(arg)
  end
  return run_cmd_capture(table.concat(parts, " "))
end

-- Starts the watchdog script without waiting for it. uhttpd kills a CGI process
-- at script_timeout (60 s by default), so anything that scales with the number
-- of links cannot run inside the request: a full check of 55 links takes about
-- two minutes, and the user got "Bad Gateway - The process did not produce any
-- response" even though the scan itself completed and wrote every result. The
-- output goes to the watchdog log the page already displays, and each link's
-- state file is written as it finishes, so the table fills in on any later load.
function M.run_watchdog_command_detached(args, env)
  local parts = {}
  for key, value in pairs(env or {}) do
    key = tostring(key or "")
    if key:match("^[A-Z0-9_]+$") then
      parts[#parts + 1] = key .. "=" .. utils.shellescape(value)
    end
  end
  parts[#parts + 1] = utils.shellescape(WATCHDOG_SCRIPT)
  for __, arg in ipairs(args or {}) do
    parts[#parts + 1] = utils.shellescape(arg)
  end
  -- setsid detaches from the CGI process group, so uhttpd reaping the request
  -- does not take the scan down with it. Output goes to syslog rather than to
  -- WATCHDOG_LOG_FILE: the script already writes its own progress there, so
  -- appending stdout as well printed every line twice in the log box. Anything
  -- the script itself cannot log — a shell-level failure — still ends up in
  -- logread this way instead of being discarded.
  local inner = table.concat(parts, " ") .. " 2>&1 | logger -t tproxy-manager-watchdog"
  return sys.call("setsid sh -c " .. utils.shellescape(inner) .. " >/dev/null 2>&1 &") == 0
end

-- True when a detached run of the same subcommand is still going. Checked before
-- starting another one: two concurrent scans would fight over the test ports.
function M.watchdog_command_running(subcommand)
  local pattern = "[t]proxy-manager-watchdog.sh " .. tostring(subcommand or "")
  local out = sys.exec("ps w 2>/dev/null | grep -c " .. utils.shellescape(pattern)) or "0"
  return (tonumber(out:match("(%d+)") or "0") or 0) > 0
end

local function read_state_file(path)
  if state_cache[path] ~= nil then
    return state_cache[path]
  end
  local parsed = utils.parse_kv_text(utils.read_file(path))
  state_cache[path] = parsed
  return parsed
end

local function md5_hash(link)
  if md5_cache[link] ~= nil then
    return md5_cache[link]
  end
  local value = proxy_links.hash(link)
  md5_cache[link] = value
  return value
end

function M.parse_links_file(path)
  local entries = {}
  local raw = utils.read_file(path)
  local index = 0
  for line in (raw .. "\n"):gmatch("([^\n]*)\n") do
    local parsed = parse_link_line(line)
    if parsed then
      index = index + 1
      local hash = md5_hash(parsed.raw_link)
      local state = {}
      if hash ~= "" then
        state = read_state_file(WATCHDOG_LINK_STATE_DIR .. "/" .. hash .. ".state")
      end
      entries[#entries + 1] = {
        index = index,
        hash = hash,
        raw_link = parsed.raw_link,
        link = parsed.display_link,
        comment = parsed.comment,
        protocol = parsed.protocol,
        protocol_label = parsed.protocol_label,
        state = state
      }
    end
  end
  return entries
end

function M.write_links_file(path, entries)
  local out = {}
  for __, entry in ipairs(entries or {}) do
    local raw_link = trim(entry.raw_link or entry.link)
    if raw_link ~= "" then
      out[#out + 1] = raw_link
    end
  end
  -- Result is returned to the caller: "permissions" still means the file
  -- was written, only its mode could not be set. The caches are invalidated
  -- first - returning before them would have left stale link state behind.
  local wrote, wwhy = utils.write_file(path, table.concat(out, "\n") .. (#out > 0 and "\n" or ""))
  md5_cache = {}
  state_cache = {}
  return wrote, wwhy
end

function M.validate_links_text(text)
  local line_no = 0
  for line in ((text or "") .. "\n"):gmatch("([^\n]*)\n") do
    line_no = line_no + 1
    local value = trim(line)
    if value ~= "" and not value:match("^#") and not parse_link_line(value) then
      return false, line_no
    end
  end
  return true
end

function M.find_entry_index(entries, hash)
  for i, entry in ipairs(entries or {}) do
    if entry.hash == hash then return i end
  end
  return nil
end

-- "2026-08-12 08:51:19" in a 10%-wide column wrapped at the space, which is
-- readable by luck rather than by design. Date and time become two explicit
-- unbreakable lines instead.
function M.when_html(value, pcdata)
  local text = tostring(value or "-")
  local d, t = text:match("^(%S+)%s+(%S+)$")
  if not d then return "<span class='d'>" .. pcdata(text) .. "</span>" end
  return "<span class='d'>" .. pcdata(d) .. "</span><span class='t'>" .. pcdata(t) .. "</span>"
end

function M.status_label(entry, pcdata)
  local state = entry.state or {}
  local status = state.LAST_STATUS or "unknown"
  local checked = state.LAST_CHECKED_HUMAN or "-"
  local cooldown = state.COOLDOWN_UNTIL_HUMAN or "-"
  local request_text = state.LAST_REQUEST_TIME_TEXT or ""
  if request_text == "" or request_text == "-" then
    local request_ms = tonumber(state.LAST_REQUEST_TIME_MS or "")
    if request_ms and request_ms > 0 then request_text = tostring(request_ms) .. " ms" end
  end
  local speed = ""
  if request_text ~= "" and request_text ~= "-" then
    -- Own line, and never broken inside: inline after the badge the narrow Status
    -- column split the value from its unit ("OK · 700" / "ms").
    speed = "<span class='wd-speed'>" .. pcdata(request_text) .. "</span>"
  end
  if status == "alive" then
    return "<span class='svc-badge ok'>OK</span>" .. speed, checked
  elseif status == "dead" then
    local suffix = ""
    if cooldown ~= "" and cooldown ~= "-" then
      -- "excluded until 2026-08-12 14:52:31" in a narrow column broke wherever the
      -- line happened to end, splitting the date itself. Label, date and time are
      -- separate unbreakable lines instead.
      local cd_date, cd_time = tostring(cooldown):match("^(%S+)%s+(%S+)$")
      if cd_date then
        suffix = "<span class='wd-cooldown'><span>" .. _("excluded until") .. "</span>" ..
                 "<span>" .. pcdata(cd_date) .. "</span><span>" .. pcdata(cd_time) .. "</span></span>"
      else
        suffix = "<span class='wd-cooldown'><span>" .. _("excluded until") .. "</span>" ..
                 "<span>" .. pcdata(cooldown) .. "</span></span>"
      end
    end
    return "<span class='svc-badge err'>Error</span>" .. speed .. suffix, checked
  elseif status == "unsupported" then
    -- Deliberately not an error: nothing was measured and the server was never
    -- contacted. The active engine cannot build this outbound, and switching
    -- engines makes the link usable again with no change to the link itself.
    local reason = state.LAST_REQUEST_TIME_TEXT or ""
    local note = ""
    if reason ~= "" and reason ~= "-" then
      note = "<span class='wd-note'>" .. pcdata(reason) .. "</span>"
    end
    return "<span class='svc-badge warn'>" .. _("Unsupported") .. "</span>" .. note, checked
  end
  return "<span style='color:var(--tpm-muted)'>" .. _("Not checked") .. "</span>", "-"
end

function M.watchdog_log()
  if fs.access(WATCHDOG_LOG_FILE) then
    local rc, out = run_cmd_capture("tail -n 200 " .. utils.shellescape(WATCHDOG_LOG_FILE))
    if rc == 0 and out ~= "" then
      return out
    end
  end
  return _("(log is empty)")
end

function M.clear_watchdog_log()
  return utils.write_file(WATCHDOG_LOG_FILE, "")
end

function M.redirect_watchdog(extra)
  local url = disp.build_url("admin", "network", "tproxy_manager") .. "?tab=watchdog"
  if extra and extra ~= "" then
    url = url .. "&" .. extra
  end
  http.redirect(url)
end

function M.save_watchdog_settings(ctx)
  local uci = ctx.uci
  local PKG = ctx.PKG
  local set_err, set_info = ctx.set_err, ctx.set_info

  local interval = parse_int(http.formvalue("watchdog_interval"), 0)
  local fail_threshold = parse_int(http.formvalue("watchdog_fail_threshold"), 0)
  local connect_timeout = parse_int(http.formvalue("watchdog_connect_timeout"), 0)
  local max_time = parse_int(http.formvalue("watchdog_max_time"), 0)
  local cooldown_hours = parse_int(http.formvalue("watchdog_dead_cooldown_hours"), 0)
  local cooldown_minutes = parse_int(http.formvalue("watchdog_dead_cooldown_minutes"), 0)
  local test_port = parse_int(http.formvalue("watchdog_test_port"), 0)
  local background_check_interval = parse_int(http.formvalue("watchdog_background_check_interval"), 0)
  local batch_check_port_start = parse_int(http.formvalue("watchdog_batch_check_port_start"), 0)
  local batch_check_batch_size = parse_int(http.formvalue("watchdog_batch_check_batch_size"), 0)
  local batch_check_concurrency = parse_int(http.formvalue("watchdog_batch_check_concurrency"), 0)
  local happ_capture_ttl = parse_int(http.formvalue("watchdog_happ_capture_ttl"), 0)
  local happ_capture_port = parse_int(http.formvalue("watchdog_happ_capture_port"), 0)
  local mode = trim(http.formvalue("watchdog_selection_mode"))
  local service_path = trim(http.formvalue("watchdog_service_path"))
  local test_command, test_command_err = M.validate_test_command(http.formvalue("watchdog_test_command"))

  if interval < 1 then set_err(_("Interval must be at least 1 second.")); return false end
  if fail_threshold < 1 then set_err(_("Failure threshold must be at least 1.")); return false end
  if connect_timeout < 1 then set_err(_("Connect timeout must be at least 1.")); return false end
  if max_time < connect_timeout then set_err(_("Max time must be greater than or equal to connect timeout.")); return false end
  if cooldown_hours < 0 or cooldown_minutes < 0 or cooldown_minutes > 59 then
    set_err(_("Exclusion period is invalid.")); return false
  end
  if test_port < 1 or test_port > 65535 then set_err(_("Test-instance port must be in range 1..65535.")); return false end
  if background_check_interval < 1 then set_err(_("Background check timer must be at least 1 second.")); return false end
  if happ_capture_ttl < 1 then set_err(_("Happ capture TTL must be at least 1 second.")); return false end
  if happ_capture_port < 1 or happ_capture_port > 65535 then set_err(_("Happ capture port must be in range 1..65535.")); return false end
  if mode ~= "random" and mode ~= "ordered" and mode ~= "fastest" then set_err(_("Unknown link selection mode.")); return false end
  if service_path == "" or not utils.is_abs_path(service_path) then set_err(_("A valid absolute service path is required.")); return false end
  if not test_command then set_err(test_command_err); return false end
  if batch_check_port_start < 1 or batch_check_port_start > 65535 then set_err(_("Batch check start port must be in range 1..65535.")); return false end
  if batch_check_batch_size < 1 then set_err(_("Batch check size must be at least 1.")); return false end
  if batch_check_concurrency < 1 then set_err(_("Batch check concurrency must be at least 1.")); return false end
  if batch_check_port_start + batch_check_batch_size - 1 > 65535 then set_err(_("Batch check port range exceeds 65535.")); return false end
  if batch_check_port_start <= test_port and (batch_check_port_start + batch_check_batch_size - 1) >= test_port then
    set_err(_("Batch check port range must not include Watchdog TEST_PORT.")); return false
  end
  if batch_check_concurrency > batch_check_batch_size then batch_check_concurrency = batch_check_batch_size end

  -- Not every stored path has an input in this form. Outbound templates are
  -- edited through the dedicated selector; probe-layout templates are internal
  -- service files. This settings transaction must not take ownership of either.
  --
  -- So the distinction that matters is submitted-and-empty (the user cleared a
  -- box: an error) versus not-submitted-at-all (this form does not own the
  -- field: keep what is stored). An absent field falls back to UCI and is only
  -- reported as missing when nothing is stored either.
  local function field(key)
    local submitted = http.formvalue(key)
    if submitted == nil then return trim(uci:get(PKG, "main", key) or "") end
    return trim(submitted)
  end

  local text_fields = {
    watchdog_check_url = field("watchdog_check_url"),
    watchdog_proxy_url = field("watchdog_proxy_url"),
    watchdog_links_file = field("watchdog_links_file"),
    watchdog_outbound_file = field("watchdog_outbound_file"),
    watchdog_vless2json = field("watchdog_vless2json"),
    watchdog_proxy2mihomo = field("watchdog_proxy2mihomo"),
    watchdog_proxy2singbox = field("watchdog_proxy2singbox"),
    watchdog_subscriptions_file = field("watchdog_subscriptions_file"),
    watchdog_share_file = field("watchdog_share_file"),
    watchdog_happ_capture_log = field("watchdog_happ_capture_log"),
  }
  for key, value in pairs(text_fields) do
    if value == "" then
      set_err(_("Required field is empty:").." " .. key .. ".")
      return false
    end
    if key:match("_file$") or key == "watchdog_vless2json" or key == "watchdog_proxy2mihomo" or key == "watchdog_proxy2singbox" or key == "watchdog_happ_capture_log" then
      if not utils.is_abs_path(value) then
        set_err(_("Invalid absolute path for").." " .. key .. ".")
        return false
      end
    end
  end

  -- Every staged change is recorded. Roughly thirty options are written here;
  -- discarding the results meant a failure part-way through was committed as
  -- a half-formed watchdog configuration and still reported as saved.
  -- utils.uci_stage() decides set-vs-delete in one place and judges a delete
  -- by whether the option is gone, not by uci:delete's return code (which is
  -- false whenever the option was not there to begin with).
  local stage_ok = true
  local function S(k, v)
    if not utils.uci_stage(uci, PKG, "main", k, v) then stage_ok = false end
  end

  for key, value in pairs(text_fields) do S(key, value) end
  S("watchdog_interval", tostring(interval))
  S("watchdog_fail_threshold", tostring(fail_threshold))
  S("watchdog_connect_timeout", tostring(connect_timeout))
  S("watchdog_max_time", tostring(max_time))
  S("watchdog_service_path", service_path)
  S("watchdog_restart_cmd", "restart")
  -- Only when the field was actually edited. This form belongs to the watchdog,
  -- not to the engine switch, and saving it used to re-assert whatever the input
  -- happened to be showing -- which is how a command for one engine survived a
  -- switch to another and then failed every probe.
  local test_command_edited = (test_command ~= (uci:get(PKG, "main", "watchdog_test_command") or ""))
  if test_command_edited then
    S("watchdog_test_command", test_command)
  end
  S("watchdog_selection_mode", mode)
  S("watchdog_exclude_dead", http.formvalue("watchdog_exclude_dead") and "1" or "0")
  S("watchdog_dead_cooldown_hours", tostring(cooldown_hours))
  S("watchdog_dead_cooldown_minutes", tostring(cooldown_minutes))
  S("watchdog_test_port", tostring(test_port))
  S("watchdog_background_check_enabled", http.formvalue("watchdog_background_check_enabled") and "1" or "0")
  S("watchdog_background_check_interval", tostring(background_check_interval))
  S("watchdog_batch_check_enabled", http.formvalue("watchdog_batch_check_enabled") and "1" or "0")
  S("watchdog_batch_check_port_start", tostring(batch_check_port_start))
  S("watchdog_batch_check_batch_size", tostring(batch_check_batch_size))
  S("watchdog_batch_check_concurrency", tostring(batch_check_concurrency))
  S("watchdog_batch_check_fallback", http.formvalue("watchdog_batch_check_fallback") and "1" or "0")
  S("watchdog_happ_capture_ttl", tostring(happ_capture_ttl))
  S("watchdog_happ_capture_port", tostring(happ_capture_port))
  if ctx.engines and ctx.proxy_engine then
    -- The active engine's profile is part of this save: the watchdog service
    -- path and test command it mirrors are set right above. Staging it
    -- silently meant a failure here was committed with everything else.
    --
    -- Which fields the user actually edited travels with the call. Skipping the
    -- live write above was not enough on its own: the profile save reads the live
    -- key too, so an untouched form still copied a stale command -- an Xray one
    -- while Mihomo was active -- over the correct mihomo_profile_test_command.
    if not ctx.engines.save_legacy_to_profile(uci, PKG, ctx.proxy_engine,
      { edited = { watchdog_test_command = test_command_edited } }) then
      stage_ok = false
    end
  end

  -- Nothing is committed once any part of the set failed to stage: a partial
  -- watchdog configuration is what makes it probe one engine while restarting
  -- another.
  if not stage_ok then
    uci:revert(PKG)
    set_info(nil)
    set_err(_("Failed to save settings."))
    return false
  end

  -- Not committed means nothing was saved: report failure instead of the
  -- unconditional success message this used to show.
  local ok_c, why_c = utils.commit_uci(uci, PKG)
  if not ok_c and why_c == "commit" then
    -- Drop the staged set as well: left pending, it would be swept into the
    -- next unrelated commit from any other tab.
    uci:revert(PKG)
    set_info(nil)
    set_err(_("Failed to save settings."))
    return false
  end
  set_err(nil)
  if ok_c then
    set_info(_("Watchdog settings saved."))
  else
    set_info(nil)
    set_err(_("Settings saved, but the configuration file permissions could not be secured."))
  end
  return true
end

function M.validate_test_command(value)
  value = trim(value)
  if value == "" then return nil, _("Test start command is required.") end
  return value
end

local template_placeholder_values = {
  __ADDRESS__ = "127.0.0.1",
  __PORT__ = "443",
  __UUID__ = "00000000-0000-0000-0000-000000000000",
  __FLOW__ = "",
  __NETWORK__ = "tcp",
  __SECURITY__ = "none",
  __SERVER_NAME__ = "example.com",
  __FINGERPRINT__ = "chrome",
  __PUBLIC_KEY__ = "",
  __SHORT_ID__ = "",
  __SPIDER_X__ = "/",
  __HEADER_TYPE__ = "none",
  __REMARKS__ = "template",
  __TEST_PORT__ = "10881",
  __OUTBOUND_TAG__ = "proxy",
  __OUTBOUNDS__ = "[]",
  __BATCH_INBOUNDS__ = "[]",
  __BATCH_OUTBOUNDS__ = "[]",
  __BATCH_RULES__ = "[]",
  __HY2_AUTH__ = "password",
  __HY2_STREAM_SETTINGS__ = "{}",
  __HY2_HYSTERIA_SETTINGS__ = "{}",
  __HY2_TLS_SETTINGS__ = "{}",
  __HY2_UDPMASKS__ = "[]",
  __ALLOW_INSECURE__ = "false",
  __ALLOW_INSECURE_BOOL__ = "false",
  __ALPN__ = "h3",
  __ALPN_ARRAY__ = "[]",
  __HY2_ALPN_ARRAY__ = "[]"
}

function M.normalize_template_jsonc_for_validation(text)
  local out = tostring(text or "")
  for placeholder, value in pairs(template_placeholder_values) do
    out = out:gsub(placeholder, value)
  end
  return out
end

function M.validate_template_jsonc_text(text)
  return utils.validate_jsonc_text(M.normalize_template_jsonc_for_validation(text))
end

M.trim = trim
M.parse_link_line = parse_link_line
M.read_file = utils.read_file
M.write_file = utils.write_file
M.validate_jsonc_text = utils.validate_jsonc_text
M.parse_kv_text = utils.parse_kv_text

return M
