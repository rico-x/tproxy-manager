local fs = require "nixio.fs"
local sys = require "luci.sys"
local http = require "luci.http"
local disp = require "luci.dispatcher"
local utils = require "luci.model.cbi.tproxy_manager.utils"

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

local function urldecode_component(s)
  s = tostring(s or ""):gsub("+", " ")
  return (s:gsub("%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end))
end

local function parse_link_line(line)
  local value = trim(line)
  if value == "" or value:match("^#") then return nil end

  local raw_link, external_comment = value, ""
  if value:find(" # ", 1, true) then
    raw_link = value:match("^(.-) # ") or value
    external_comment = trim(value:match(" # (.*)$") or "")
  end

  raw_link = trim(raw_link)
  if not raw_link:match("^vless://") then return nil end

  local fragment = raw_link:match("#(.*)$") or ""
  local display_link = raw_link:gsub("#.*$", "")
  local comment = external_comment ~= "" and external_comment or trim(urldecode_component(fragment))

  return {
    raw_link = raw_link,
    display_link = display_link,
    comment = comment
  }
end

local function run_cmd_capture(cmd)
  local marker = "__TPM_WD_RC__:"
  local wrapped = string.format("(%s) 2>&1; printf '\\n%s%%s' \"$?\"", cmd, marker)
  local out = sys.exec(wrapped) or ""
  local rc = tonumber(out:match(marker .. "([%-%d]+)%s*$")) or 1
  out = out:gsub("\n?" .. marker .. "[%-%d]+%s*$", "")
  return rc, trim(out)
end

function M.run_watchdog_command(args)
  local parts = { utils.shellescape(WATCHDOG_SCRIPT) }
  for _, arg in ipairs(args or {}) do
    parts[#parts + 1] = utils.shellescape(arg)
  end
  return run_cmd_capture(table.concat(parts, " "))
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
  local rc, out = run_cmd_capture("printf %s " .. utils.shellescape(link) .. " | md5sum | awk '{print $1}'")
  local value = rc == 0 and trim(out) or ""
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
        state = state
      }
    end
  end
  return entries
end

function M.write_links_file(path, entries)
  local out = {}
  for _, entry in ipairs(entries or {}) do
    local raw_link = trim(entry.raw_link or entry.link)
    if raw_link ~= "" then
      out[#out + 1] = raw_link
    end
  end
  utils.write_file(path, table.concat(out, "\n") .. (#out > 0 and "\n" or ""))
  md5_cache = {}
  state_cache = {}
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

function M.status_label(entry, pcdata)
  local state = entry.state or {}
  local status = state.LAST_STATUS or "unknown"
  local checked = state.LAST_CHECKED_HUMAN or "-"
  local cooldown = state.COOLDOWN_UNTIL_HUMAN or "-"
  if status == "alive" then
    return "<span class='svc-badge ok'>OK</span>", checked
  elseif status == "dead" then
    local suffix = ""
    if cooldown ~= "" and cooldown ~= "-" then
      suffix = " <span style='color:#9ca3af'>(искл. до " .. pcdata(cooldown) .. ")</span>"
    end
    return "<span class='svc-badge err'>Error</span>" .. suffix, checked
  end
  return "<span style='color:#6b7280'>Не проверялась</span>", "-"
end

function M.watchdog_log()
  if fs.access(WATCHDOG_LOG_FILE) then
    local rc, out = run_cmd_capture("tail -n 200 " .. utils.shellescape(WATCHDOG_LOG_FILE))
    if rc == 0 and out ~= "" then
      return out
    end
  end
  return "(лог пуст)"
end

function M.clear_watchdog_log()
  utils.write_file(WATCHDOG_LOG_FILE, "")
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
  local happ_capture_ttl = parse_int(http.formvalue("watchdog_happ_capture_ttl"), 0)
  local happ_capture_port = parse_int(http.formvalue("watchdog_happ_capture_port"), 0)
  local mode = trim(http.formvalue("watchdog_selection_mode"))
  local service_path = trim(http.formvalue("watchdog_service_path"))
  local test_command, test_command_err = M.validate_test_command(http.formvalue("watchdog_test_command"))

  if interval < 1 then set_err("Интервал должен быть не меньше 1 секунды."); return false end
  if fail_threshold < 1 then set_err("Порог ошибок должен быть не меньше 1."); return false end
  if connect_timeout < 1 then set_err("Connect timeout должен быть не меньше 1."); return false end
  if max_time < connect_timeout then set_err("Max time должен быть не меньше connect timeout."); return false end
  if cooldown_hours < 0 or cooldown_minutes < 0 or cooldown_minutes > 59 then
    set_err("Период исключения задан некорректно."); return false
  end
  if test_port < 1 or test_port > 65535 then set_err("Порт test-instance должен быть в диапазоне 1..65535."); return false end
  if background_check_interval < 1 then set_err("Таймер фоновой проверки должен быть не меньше 1 секунды."); return false end
  if happ_capture_ttl < 1 then set_err("Время действия Happ capture должно быть не меньше 1 секунды."); return false end
  if happ_capture_port < 1 or happ_capture_port > 65535 then set_err("Порт Happ capture должен быть в диапазоне 1..65535."); return false end
  if mode ~= "random" and mode ~= "ordered" then set_err("Неизвестный режим выбора ссылок."); return false end
  if service_path == "" or not utils.is_abs_path(service_path) then set_err("Нужно указать корректный абсолютный путь к сервису."); return false end
  if not test_command then set_err(test_command_err); return false end

  local text_fields = {
    watchdog_check_url = trim(http.formvalue("watchdog_check_url")),
    watchdog_proxy_url = trim(http.formvalue("watchdog_proxy_url")),
    watchdog_links_file = trim(http.formvalue("watchdog_links_file")),
    watchdog_template_file = trim(http.formvalue("watchdog_template_file")),
    watchdog_test_template_file = trim(http.formvalue("watchdog_test_template_file")),
    watchdog_outbound_file = trim(http.formvalue("watchdog_outbound_file")),
    watchdog_vless2json = trim(http.formvalue("watchdog_vless2json")),
    watchdog_subscriptions_file = trim(http.formvalue("watchdog_subscriptions_file")),
    watchdog_happ_capture_log = trim(http.formvalue("watchdog_happ_capture_log")),
  }
  for key, value in pairs(text_fields) do
    if value == "" then
      set_err("Нужно заполнить поле " .. key .. ".")
      return false
    end
    if key:match("_file$") or key == "watchdog_vless2json" or key == "watchdog_happ_capture_log" then
      if not utils.is_abs_path(value) then
        set_err("Некорректный абсолютный путь для " .. key .. ".")
        return false
      end
    end
  end

  local function S(k, v)
    if v ~= nil and v ~= "" then uci:set(PKG, "main", k, v) else uci:delete(PKG, "main", k) end
  end

  for key, value in pairs(text_fields) do S(key, value) end
  S("watchdog_interval", tostring(interval))
  S("watchdog_fail_threshold", tostring(fail_threshold))
  S("watchdog_connect_timeout", tostring(connect_timeout))
  S("watchdog_max_time", tostring(max_time))
  S("watchdog_service_path", service_path)
  S("watchdog_restart_cmd", "restart")
  S("watchdog_test_command", test_command)
  S("watchdog_selection_mode", mode)
  S("watchdog_exclude_dead", http.formvalue("watchdog_exclude_dead") and "1" or "0")
  S("watchdog_dead_cooldown_hours", tostring(cooldown_hours))
  S("watchdog_dead_cooldown_minutes", tostring(cooldown_minutes))
  S("watchdog_test_port", tostring(test_port))
  S("watchdog_background_check_enabled", http.formvalue("watchdog_background_check_enabled") and "1" or "0")
  S("watchdog_background_check_interval", tostring(background_check_interval))
  S("watchdog_happ_capture_ttl", tostring(happ_capture_ttl))
  S("watchdog_happ_capture_port", tostring(happ_capture_port))
  uci:commit(PKG)

  set_err(nil)
  set_info("Настройки watchdog сохранены.")
  return true
end

function M.validate_test_command(value)
  value = trim(value)
  if value == "" then return nil, "Нужно указать команду тестового запуска." end
  return value
end

M.trim = trim
M.read_file = utils.read_file
M.write_file = utils.write_file
M.validate_jsonc_text = utils.validate_jsonc_text
M.parse_kv_text = utils.parse_kv_text

return M
