local cbi = require "luci.cbi"
local SimpleSection, DummyValue = cbi.SimpleSection, cbi.DummyValue

local fs = require "nixio.fs"
local sys = require "luci.sys"
local http = require "luci.http"
local disp = require "luci.dispatcher"
local xml = require "luci.xml"
local jsonc = require "luci.jsonc"
local helpers = require "luci.model.cbi.tproxy_manager.modules.watchdog_helpers"

local pcdata = xml.pcdata

local WATCHDOG_SCRIPT = "/usr/bin/tproxy-manager-watchdog.sh"
local WATCHDOG_LINK_STATE_DIR = "/tmp/tproxy-manager-watchdog-links"
local WATCHDOG_LOG_FILE = "/tmp/tproxy-manager-watchdog.log"
local MD5_CACHE = {}
local STATE_CACHE = {}

local function atomic_write(path, data)
  data = (data or ""):gsub("\r\n", "\n")
  local dir, base = path:match("^(.*)/([^/]+)$")
  local tmpdir = dir and dir or "/tmp"
  if dir and not fs.access(dir) then
    sys.call("mkdir -p '" .. dir:gsub("'", "'\\''") .. "'")
  end
  local tmp = string.format("%s/.%s.%d.tmp", tmpdir, base or "tmp", math.random(1, 10^9))
  fs.writefile(tmp, data or "")
  fs.rename(tmp, path)
end

local function read_file(path)
  return fs.readfile(path) or ""
end

local function write_file(path, data)
  atomic_write(path, data or "")
end

local function shellescape(s)
  s = tostring(s or "")
  if s == "" then return "''" end
  return "'" .. s:gsub("'", "'\\''") .. "'"
end

local function trim(s)
  return tostring(s or ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
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

local function strip_json_comments(s)
  local out, i, n = {}, 1, #s
  local in_str, esc = false, false
  while i <= n do
    local c = s:sub(i, i)
    local d = s:sub(i + 1, i + 1)
    if in_str then
      out[#out + 1] = c
      if esc then esc = false
      elseif c == "\\" then esc = true
      elseif c == '"' then in_str = false end
      i = i + 1
    else
      if c == '"' then
        in_str = true
        out[#out + 1] = c
        i = i + 1
      elseif c == "/" and d == "/" then
        i = i + 2
        while i <= n and s:sub(i, i) ~= "\n" do i = i + 1 end
      elseif c == "/" and d == "*" then
        i = i + 2
        while i <= n - 1 and not (s:sub(i, i) == "*" and s:sub(i + 1, i + 1) == "/") do i = i + 1 end
        i = i + 2
      else
        out[#out + 1] = c
        i = i + 1
      end
    end
  end
  return table.concat(out)
end

local function validate_jsonc_text(text)
  local cleaned = strip_json_comments(text or "")
  local ok, parsed = pcall(jsonc.parse, cleaned)
  return ok and parsed ~= nil
end

local function run_cmd_capture(cmd)
  local marker = "__TPM_WD_RC__:"
  local wrapped = string.format("(%s) 2>&1; printf '\\n%s%%s' \"$?\"", cmd, marker)
  local out = sys.exec(wrapped) or ""
  local rc = tonumber(out:match(marker .. "([%-%d]+)%s*$")) or 1
  out = out:gsub("\n?" .. marker .. "[%-%d]+%s*$", "")
  return rc, trim(out)
end

local function run_watchdog_command(args)
  local parts = { shellescape(WATCHDOG_SCRIPT) }
  for _, arg in ipairs(args or {}) do
    parts[#parts + 1] = shellescape(arg)
  end
  return run_cmd_capture(table.concat(parts, " "))
end

local function parse_kv_text(text)
  local data = {}
  for line in (text .. "\n"):gmatch("([^\n]*)\n") do
    local k, v = line:match("^([A-Z0-9_]+)=(.*)$")
    if k then data[k] = v end
  end
  return data
end

local function read_state_file(path)
  if STATE_CACHE[path] ~= nil then return STATE_CACHE[path] end
  local parsed = parse_kv_text(read_file(path))
  STATE_CACHE[path] = parsed
  return parsed
end

local function md5_hash(link)
  if MD5_CACHE[link] ~= nil then return MD5_CACHE[link] end
  local rc, out = run_cmd_capture("printf %s " .. shellescape(link) .. " | md5sum | awk '{print $1}'")
  local value = rc == 0 and trim(out) or ""
  MD5_CACHE[link] = value
  return value
end

local function parse_links_file(path)
  local entries = {}
  local raw = read_file(path)
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

local function write_links_file(path, entries)
  local out = {}
  for _, entry in ipairs(entries or {}) do
    local raw_link = trim(entry.raw_link or entry.link)
    if raw_link ~= "" then
      out[#out + 1] = raw_link
    end
  end
  write_file(path, table.concat(out, "\n") .. (#out > 0 and "\n" or ""))
  MD5_CACHE = {}
  STATE_CACHE = {}
end

local function validate_links_text(text)
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

local function find_entry_index(entries, hash)
  for i, entry in ipairs(entries or {}) do
    if entry.hash == hash then return i end
  end
  return nil
end

local function status_label(entry)
  local state = entry.state or {}
  local status = state.LAST_STATUS or "unknown"
  local checked = state.LAST_CHECKED_HUMAN or "-"
  local cooldown = state.COOLDOWN_UNTIL_HUMAN or "-"
  if status == "alive" then
    return "<span class='svc-badge ok'>Живая</span>", checked
  elseif status == "dead" then
    local suffix = ""
    if cooldown ~= "" and cooldown ~= "-" then
      suffix = " <span style='color:#9ca3af'>(искл. до " .. pcdata(cooldown) .. ")</span>"
    end
    return "<span class='svc-badge err'>Не живая</span>" .. suffix, checked
  end
  return "<span style='color:#6b7280'>Не проверялась</span>", "-"
end

local function watchdog_log()
  if fs.access(WATCHDOG_LOG_FILE) then
    local rc, out = run_cmd_capture("tail -n 200 " .. shellescape(WATCHDOG_LOG_FILE))
    if rc == 0 and out ~= "" then
      return out
    end
  end
  return "(лог пуст)"
end

local function clear_watchdog_log()
  write_file(WATCHDOG_LOG_FILE, "")
end

local function redirect_watchdog(extra)
  local url = disp.build_url("admin", "network", "tproxy_manager") .. "?tab=watchdog"
  if extra and extra ~= "" then
    url = url .. "&" .. extra
  end
  http.redirect(url)
end

local function save_watchdog_settings(ctx)
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
  local mode = trim(http.formvalue("watchdog_selection_mode"))
  local service_path = trim(http.formvalue("watchdog_service_path"))
  local test_command = trim(http.formvalue("watchdog_test_command"))

  if interval < 1 then set_err("Интервал должен быть не меньше 1 секунды."); return false end
  if fail_threshold < 1 then set_err("Порог ошибок должен быть не меньше 1."); return false end
  if connect_timeout < 1 then set_err("Connect timeout должен быть не меньше 1."); return false end
  if max_time < connect_timeout then set_err("Max time должен быть не меньше connect timeout."); return false end
  if cooldown_hours < 0 or cooldown_minutes < 0 or cooldown_minutes > 59 then
    set_err("Период исключения задан некорректно."); return false
  end
  if test_port < 1 or test_port > 65535 then set_err("Порт test-instance должен быть в диапазоне 1..65535."); return false end
  if background_check_interval < 1 then set_err("Таймер фоновой проверки должен быть не меньше 1 секунды."); return false end
  if mode ~= "random" and mode ~= "ordered" then set_err("Неизвестный режим выбора ссылок."); return false end
  if service_path == "" then set_err("Нужно указать путь к сервису."); return false end
  if test_command == "" then set_err("Нужно указать команду тестового запуска."); return false end

  local function S(k, v)
    if v ~= nil and v ~= "" then uci:set(PKG, "main", k, v) else uci:delete(PKG, "main", k) end
  end

  S("watchdog_check_url", trim(http.formvalue("watchdog_check_url")))
  S("watchdog_proxy_url", trim(http.formvalue("watchdog_proxy_url")))
  S("watchdog_interval", tostring(interval))
  S("watchdog_fail_threshold", tostring(fail_threshold))
  S("watchdog_connect_timeout", tostring(connect_timeout))
  S("watchdog_max_time", tostring(max_time))
  S("watchdog_links_file", trim(http.formvalue("watchdog_links_file")))
  S("watchdog_template_file", trim(http.formvalue("watchdog_template_file")))
  S("watchdog_test_template_file", trim(http.formvalue("watchdog_test_template_file")))
  S("watchdog_outbound_file", trim(http.formvalue("watchdog_outbound_file")))
  S("watchdog_vless2json", trim(http.formvalue("watchdog_vless2json")))
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
  uci:commit(PKG)

  set_err(nil)
  set_info("Настройки watchdog сохранены.")
  return true
end

local function render(ctx)
  local m = ctx.m
  local uci = ctx.uci
  local PKG = ctx.PKG
  local service_block = ctx.service_block
  local set_err, set_info = ctx.set_err, ctx.set_info

  local function getu(k, def)
    local v = uci:get(PKG, "main", k)
    if v == nil or v == "" then return def or "" end
    return v
  end

  local links_path = getu("watchdog_links_file", "/etc/tproxy-manager/watchdog.links")

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
      set_err("Нужно указать путь к файлу шаблона.")
    elseif not helpers.validate_jsonc_text(text) then
      set_err("Некорректный JSON/JSONC шаблона.")
    else
      uci:set(PKG, "main", "watchdog_template_file", path)
      uci:commit(PKG)
      write_file(path, text)
      set_err(nil)
      set_info("Шаблон watchdog сохранён: " .. path)
      helpers.redirect_watchdog()
      return m
    end
  end

  if http.formvalue("_watchdog_save_test_template") == "1" then
    local path = trim(http.formvalue("watchdog_test_template_file"))
    local text = http.formvalue("watchdog_test_template_text") or ""
    if path == "" then
      set_err("Нужно указать путь к файлу тестового шаблона.")
    else
      uci:set(PKG, "main", "watchdog_test_template_file", path)
      uci:commit(PKG)
      write_file(path, text)
      set_err(nil)
      set_info("Тестовый шаблон сохранён: " .. path)
      helpers.redirect_watchdog()
      return m
    end
  end

  if http.formvalue("_watchdog_save_links_text") == "1" then
    local path = trim(http.formvalue("watchdog_links_file"))
    local text = (http.formvalue("watchdog_links_text") or ""):gsub("\r\n", "\n")
    local ok, bad_line = validate_links_text(text)
    if path == "" then
      set_err("Нужно указать путь к LINKS_FILE.")
    elseif not ok then
      set_err("Некорректная строка в LINKS_FILE: " .. tostring(bad_line))
    else
      uci:set(PKG, "main", "watchdog_links_file", path)
      uci:commit(PKG)
      write_file(path, text ~= "" and (text:gsub("\n*$", "") .. "\n") or "")
      set_err(nil)
      set_info("LINKS_FILE сохранён: " .. path)
      helpers.redirect_watchdog()
      return m
    end
  end

  if http.formvalue("_watchdog_clear_log") == "1" then
    helpers.clear_watchdog_log()
    set_err(nil)
    set_info("Лог watchdog очищен.")
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_watchdog_once") == "1" then
    local rc, out = helpers.run_watchdog_command({ "once" })
    if rc == 0 then set_info(out ~= "" and out or "Проверка watchdog выполнена.") else set_err(out ~= "" and out or "Проверка watchdog завершилась ошибкой.") end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_watchdog_reset") == "1" then
    local rc, out = helpers.run_watchdog_command({ "reset" })
    if rc == 0 then set_info(out ~= "" and out or "Счётчик ошибок сброшен.") else set_err(out ~= "" and out or "Не удалось сбросить счётчик ошибок.") end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_watchdog_test_rotate") == "1" then
    local rc, out = helpers.run_watchdog_command({ "test-rotate" })
    if rc == 0 then set_info(out ~= "" and out or "Ротация выполнена.") else set_err(out ~= "" and out or "Ротация завершилась ошибкой.") end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_watchdog_check_all") == "1" then
    local rc, out = helpers.run_watchdog_command({ "check-all" })
    if rc == 0 then set_info(out ~= "" and out or "Проверка всех ссылок выполнена.") else set_err(out ~= "" and out or "Проверка ссылок завершилась ошибкой.") end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_wd_apply") then
    local hash = trim(http.formvalue("_wd_apply"))
    local rc, out = helpers.run_watchdog_command({ "apply-link", hash })
    if rc == 0 then set_info(out ~= "" and out or ("Ссылка применена: " .. hash)) else set_err(out ~= "" and out or ("Не удалось применить ссылку: " .. hash)) end
    helpers.redirect_watchdog()
    return m
  end

  if http.formvalue("_wd_test") then
    local hash = trim(http.formvalue("_wd_test"))
    local rc, out = helpers.run_watchdog_command({ "test-link", hash })
    if rc == 0 then set_info(out ~= "" and out or ("Ссылка проверена: " .. hash)) else set_err(out ~= "" and out or ("Ссылка не прошла проверку: " .. hash)) end
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
    local entries = parse_links_file(links_path)
    local raw_link = trim(http.formvalue("wd_add_link"))
    if not raw_link:match("^vless://") then
      set_err("Добавляемая строка должна начинаться с vless://")
    else
      entries[#entries + 1] = { raw_link = raw_link }
      write_links_file(links_path, entries)
      set_err(nil)
      set_info("Ссылка добавлена.")
      helpers.redirect_watchdog()
      return m
    end
  end

  if http.formvalue("_wd_edit_save") == "1" then
    local entries = parse_links_file(links_path)
    local hash = trim(http.formvalue("wd_edit_hash"))
    local idx = find_entry_index(entries, hash)
    local raw_link = trim(http.formvalue("wd_edit_link"))
    if not idx then
      set_err("Редактируемая ссылка не найдена.")
    elseif not raw_link:match("^vless://") then
      set_err("Ссылка должна начинаться с vless://")
    else
      entries[idx].raw_link = raw_link
      write_links_file(links_path, entries)
      set_err(nil)
      set_info("Ссылка обновлена.")
      helpers.redirect_watchdog()
      return m
    end
  end

  if http.formvalue("_wd_delete") then
    local entries = parse_links_file(links_path)
    local hash = trim(http.formvalue("_wd_delete"))
    local idx = find_entry_index(entries, hash)
    if idx then
      table.remove(entries, idx)
      write_links_file(links_path, entries)
      set_err(nil)
      set_info("Ссылка удалена.")
      helpers.redirect_watchdog()
      return m
    end
    set_err("Удаляемая ссылка не найдена.")
  end

  if http.formvalue("_wd_move_up") or http.formvalue("_wd_move_down") then
    local entries = parse_links_file(links_path)
    local hash = trim(http.formvalue("_wd_move_up") or http.formvalue("_wd_move_down"))
    local idx = find_entry_index(entries, hash)
    if idx then
      local swap_idx = http.formvalue("_wd_move_up") and (idx - 1) or (idx + 1)
      if swap_idx >= 1 and swap_idx <= #entries then
        entries[idx], entries[swap_idx] = entries[swap_idx], entries[idx]
        write_links_file(links_path, entries)
        set_err(nil)
        set_info("Порядок ссылок обновлён.")
      end
      helpers.redirect_watchdog()
      return m
    end
    set_err("Ссылка для изменения порядка не найдена.")
  end

  local status_rc, status_out = helpers.run_watchdog_command({ "status" })
  local status = status_rc == 0 and helpers.parse_kv_text(status_out) or {}
  local edit_hash = trim(http.formvalue("wd_edit_hash"))
  local links = parse_links_file(links_path)

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
.wd-table .actions .cbi-button{margin:0 .2rem .2rem 0}
.wd-code{font-family:monospace;font-size:.92em}
.wd-details{margin-top:.6rem}
.wd-details summary{cursor:pointer;font-weight:600}
.wd-textarea{width:100%;font-family:monospace;font-size:.92em}
</style>]]
    end
  end

  do
    local ss = m:section(SimpleSection, "Статус и управление сервисом Watchdog")
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
      local scan_alive = status.LAST_LINK_SCAN_ALIVE or "0"
      local scan_total = status.LAST_LINK_SCAN_TOTAL or "0"
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
  </div>
  <div style="margin-top:.5rem">
    <button class="cbi-button cbi-button-apply" name="_watchdog_once" value="1">Проверить сейчас</button>
    <button class="cbi-button cbi-button-action" name="_watchdog_check_all" value="1">Проверить все ссылки</button>
    <button class="cbi-button cbi-button-action" name="_watchdog_test_rotate" value="1">Принудительная ротация</button>
    <button class="cbi-button cbi-button-remove" name="_watchdog_reset" value="1">Сбросить счётчик</button>
  </div>
</div>]],
        pcdata(running), pcdata(failcount), pcdata(code), pcdata(st), pcdata(ts),
        pcdata(scan), pcdata(scan_status), pcdata(scan_alive), pcdata(scan_total))
    end
  end

  do
    local sec = m:section(SimpleSection, "Список VLESS-ссылок")
    local dv = sec:option(DummyValue, "_watchdog_links")
    dv.rawhtml = true
    function dv.cfgvalue()
      local rows = {}
      rows[#rows + 1] = "<div class='box'>"
      rows[#rows + 1] = "<div style='margin-bottom:.5rem;color:#6b7280'>Комментарий берётся из части после <code>#</code> внутри самой VLESS-ссылки.</div>"
      rows[#rows + 1] = "<table class='wd-table'><thead><tr><th style='width:18%'>Комментарий</th><th style='width:42%'>VLESS ссылка</th><th style='width:12%'>Статус</th><th style='width:12%'>Последняя проверка</th><th style='width:16%'>Действие</th></tr></thead><tbody>"
      if #links == 0 then
        rows[#rows + 1] = "<tr><td colspan='5' style='color:#6b7280'>Список ссылок пуст</td></tr>"
      end
      for i, entry in ipairs(links) do
        local label, checked = helpers.status_label(entry, pcdata)
        if edit_hash ~= "" and edit_hash == entry.hash then
          rows[#rows + 1] = string.format([[
<tr>
  <td><input type="hidden" name="wd_edit_hash" value="%s"><div style="color:#6b7280">%s</div></td>
  <td><input type="text" name="wd_edit_link" value="%s" style="width:100%%"></td>
  <td>%s</td>
  <td>%s</td>
  <td class="actions">
    <button class="cbi-button cbi-button-apply" name="_wd_edit_save" value="1">Сохранить</button>
    <button class="cbi-button cbi-button-reset" name="_wd_edit_cancel" value="1">Отмена</button>
  </td>
</tr>]],
            pcdata(entry.hash), pcdata(entry.comment or "—"), pcdata(entry.raw_link or ""), label, pcdata(checked))
        else
          rows[#rows + 1] = string.format([[
<tr>
  <td>%s</td>
  <td class="wd-code" title="%s">%s</td>
  <td>%s</td>
  <td>%s</td>
  <td class="actions">
    <button class="cbi-button cbi-button-apply" name="_wd_apply" value="%s">Применить</button>
    <button class="cbi-button cbi-button-action" name="_wd_test" value="%s">Проверить</button>
    <button class="cbi-button cbi-button-action" name="_wd_edit_start" value="%s">Ред.</button>
    <button class="cbi-button cbi-button-remove" name="_wd_delete" value="%s" onclick="return confirm('Удалить выбранную ссылку?')">Удалить</button>
    <button class="cbi-button cbi-button-action" name="_wd_move_up" value="%s"%s>&uarr;</button>
    <button class="cbi-button cbi-button-action" name="_wd_move_down" value="%s"%s>&darr;</button>
  </td>
</tr>]],
            pcdata(entry.comment or "—"),
            pcdata(entry.raw_link or ""),
            pcdata(entry.link or ""),
            label,
            pcdata(checked),
            pcdata(entry.hash), pcdata(entry.hash), pcdata(entry.hash), pcdata(entry.hash),
            pcdata(entry.hash), i == 1 and " disabled" or "",
            pcdata(entry.hash), i == #links and " disabled" or "")
        end
      end
      rows[#rows + 1] = [[
<tr>
  <td style="color:#6b7280">Новая строка файла ссылок</td>
  <td><input type="text" name="wd_add_link" placeholder="vless://..." style="width:100%"></td>
  <td colspan="2" style="color:#6b7280">Комментарий будет взят из части после # внутри ссылки</td>
  <td class="actions"><button class="cbi-button cbi-button-apply" name="_wd_add" value="1">Добавить</button></td>
</tr>]]
      rows[#rows + 1] = "</tbody></table>"
      rows[#rows + 1] = "<details class='wd-details'><summary>Редактор LINKS_FILE</summary><div class='box editor-wrap editor-wide' style='margin-top:.5rem'>"
      rows[#rows + 1] = string.format("<div class='wd-grid'><label>LINKS_FILE</label><input type='text' name='watchdog_links_file' value='%s'></div>", pcdata(links_path))
      rows[#rows + 1] = "<div style='margin:.5rem 0;color:#6b7280'>Для массовой вставки: одна VLESS-ссылка на строку. Пустые строки и строки, начинающиеся с <code>#</code>, допускаются.</div>"
      rows[#rows + 1] = string.format("<textarea class='wd-textarea' name='watchdog_links_text' rows='12' spellcheck='false'>%s</textarea>", pcdata(read_file(links_path)))
      rows[#rows + 1] = "<div style='margin-top:.5rem'><button class='cbi-button cbi-button-apply' name='_watchdog_save_links_text' value='1'>Сохранить LINKS_FILE</button></div>"
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
  <summary>Настройки Watchdog</summary>
  <div class="box" style="margin-top:.5rem">
    <div class="wd-grid">
      <label>CHECK_URL</label><input type="text" name="watchdog_check_url" value="%s">
      <label>PROXY_URL</label><input type="text" name="watchdog_proxy_url" value="%s">
      <label>INTERVAL</label><input type="number" min="1" name="watchdog_interval" value="%s">
      <label>FAIL_THRESHOLD</label><input type="number" min="1" name="watchdog_fail_threshold" value="%s">
      <label>CONNECT_TIMEOUT</label><input type="number" min="1" name="watchdog_connect_timeout" value="%s">
      <label>MAX_TIME</label><input type="number" min="1" name="watchdog_max_time" value="%s">
      <label>OUTBOUND_FILE</label><input type="text" name="watchdog_outbound_file" value="%s">
      <label>VLESS2JSON</label><input type="text" name="watchdog_vless2json" value="%s">
      <label>SERVICE_PATH</label><input type="text" name="watchdog_service_path" value="%s">
      <label>RESTART_CMD</label><input type="text" value="restart" readonly>
      <label>TEST_COMMAND</label><input type="text" name="watchdog_test_command" value="%s">
      <label>SELECTION_MODE</label>
      <select name="watchdog_selection_mode">
        <option value="ordered"%s>по порядку</option>
        <option value="random"%s>случайно</option>
      </select>
      <label>Исключать нерабочие ссылки</label><input type="checkbox" name="watchdog_exclude_dead" value="1" %s>
      <label>Период исключения: часы</label><input type="number" min="0" name="watchdog_dead_cooldown_hours" value="%s">
      <label>Период исключения: минуты</label><input type="number" min="0" max="59" name="watchdog_dead_cooldown_minutes" value="%s">
      <label>TEST_PORT</label><input type="number" min="1" max="65535" name="watchdog_test_port" value="%s">
      <label>Фоновая проверка ссылок</label><input type="checkbox" name="watchdog_background_check_enabled" value="1" %s>
      <label>Таймер фоновой проверки, сек</label><input type="number" min="1" name="watchdog_background_check_interval" value="%s">
    </div>
    <div style="margin-top:.6rem">
      <button class="cbi-button cbi-button-apply" name="_watchdog_save_settings" value="1">Сохранить настройки Watchdog</button>
    </div>
  </div>
</details>]],
        pcdata(getu("watchdog_check_url", "https://ifconfig.me/ip")),
        pcdata(getu("watchdog_proxy_url", "socks5h://127.0.0.1:10808")),
        pcdata(getu("watchdog_interval", "60")),
        pcdata(getu("watchdog_fail_threshold", "3")),
        pcdata(getu("watchdog_connect_timeout", "15")),
        pcdata(getu("watchdog_max_time", "20")),
        pcdata(getu("watchdog_outbound_file", "/etc/xray/04_outbounds.json")),
        pcdata(getu("watchdog_vless2json", "/usr/bin/vless2json.sh")),
        pcdata(getu("watchdog_service_path", "/etc/init.d/xray")),
        pcdata(getu("watchdog_test_command", "/usr/bin/xray -c {config}")),
        getu("watchdog_selection_mode", "random") == "ordered" and " selected" or "",
        getu("watchdog_selection_mode", "random") == "random" and " selected" or "",
        getu("watchdog_exclude_dead", "0") == "1" and "checked" or "",
        pcdata(getu("watchdog_dead_cooldown_hours", "0")),
        pcdata(getu("watchdog_dead_cooldown_minutes", "0")),
        pcdata(getu("watchdog_test_port", "10881")),
        getu("watchdog_background_check_enabled", "0") == "1" and "checked" or "",
        pcdata(getu("watchdog_background_check_interval", "1800")))
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
  <summary>Шаблон outbounds</summary>
  <div class="box editor-wrap editor-wide" style="margin-top:.5rem">
    <div class="wd-grid" style="margin-bottom:.5rem">
      <label>TEMPLATE_FILE</label><input type="text" name="watchdog_template_file" value="]] .. pcdata(current_path) .. [[">
    </div>
    <div style="margin-bottom:.4rem;color:#6b7280">Шаблон хранится в отдельном файле и по умолчанию обрабатывается встроенным конвертером <code>/usr/bin/vless2json.sh</code>. Путь можно переопределить в настройках.</div>
    <textarea class="wd-textarea" name="watchdog_template_text" rows="18" spellcheck="false">]] .. pcdata(content) .. [[</textarea>
    <div style="height:5px"></div>
    <div class="box editor-wrap editor-680" id="watchdog-template-status-box">
      <div id="watchdog_template_status" style="margin:.08rem 0 .14rem 0; font-weight:600"></div>
    </div>
    <div style="margin-top:.5rem">
      <button class="cbi-button cbi-button-apply" name="_watchdog_save_template" value="1">Сохранить шаблон</button>
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
      badge.textContent = 'Шаблон JSONC валиден';
      badge.style.color = '#16a34a';
    } catch(e) {
      badge.textContent = 'Ошибка JSONC: ' + e.message;
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
  <summary>Тестовый шаблон</summary>
  <div class="box editor-wrap editor-wide" style="margin-top:.5rem">
    <div class="wd-grid" style="margin-bottom:.5rem">
      <label>TEST_TEMPLATE_FILE</label><input type="text" name="watchdog_test_template_file" value="]] .. pcdata(current_path) .. [[">
    </div>
    <div style="margin-bottom:.4rem;color:#6b7280">Этот шаблон используется для временного test-instance. В базовом варианте доступны плейсхолдеры <code>__TEST_PORT__</code>, <code>__OUTBOUNDS__</code> и <code>__OUTBOUND_TAG__</code>.</div>
    <textarea class="wd-textarea" name="watchdog_test_template_text" rows="18" spellcheck="false">]] .. pcdata(content) .. [[</textarea>
    <div style="margin-top:.5rem">
      <button class="cbi-button cbi-button-apply" name="_watchdog_save_test_template" value="1">Сохранить тестовый шаблон</button>
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
      return [[<details class="wd-details"><summary><strong>Лог Watchdog</strong></summary><div class="box editor-wrap" style="margin-top:.5rem"><div style="margin-bottom:.5rem"><button class="cbi-button cbi-button-remove" name="_watchdog_clear_log" value="1">Очистить лог</button></div><pre style="white-space:pre-wrap;max-height:30rem;overflow:auto">]] ..
             pcdata(helpers.watchdog_log()) .. [[</pre></div></details>]]
    end
  end
end

return { render = render }
