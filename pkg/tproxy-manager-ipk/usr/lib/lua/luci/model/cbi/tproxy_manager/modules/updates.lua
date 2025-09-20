local cbi = require "luci.cbi"
local SimpleSection, DummyValue, Button = cbi.SimpleSection, cbi.DummyValue, cbi.Button

-- ===== Локальная, полностью независимая реализация модуля "updates" (со стилями и разметкой) =====
local fs    = require "nixio.fs"
local sys   = require "luci.sys"
local http  = require "luci.http"
local disp  = require "luci.dispatcher"
local xml   = require "luci.xml"
local jsonc = require "luci.jsonc"

local pcdata = xml.pcdata

-- Внутренние пути/константы этого модуля (не зависят от ctx)
local BASE_DIR     = "/etc/tproxy-manager"
local GEO_CFG      = BASE_DIR .. "/geo-sources.conf"
local GEO_SCRIPT   = "/usr/bin/tproxy-manager-geo-update.sh"
local CRON_FILE    = "/etc/crontabs/root"
local CRON_TAG     = "# tproxy-manager-geo-update"
local SYSLOG_TAG   = "tproxy-manager-geoip-update"

-- ---------- Файловые хелперы ----------
local function atomic_write(path, data)
  data = (data or ""):gsub("\r\n","\n")
  local dir, base = path:match("^(.*)/([^/]+)$")
  local tmpdir = dir and dir or "/tmp"
  if dir and not fs.access(dir) then
    sys.call("mkdir -p '"..dir:gsub("'", "'\\''").."'")
  end
  local tmp = string.format("%s/.%s.%d.tmp", tmpdir, base or "tmp", math.random(1, 10^9))
  fs.writefile(tmp, data or "")
  fs.rename(tmp, path)
end

local function read_file(p)  return fs.readfile(p) or "" end
local function write_file(p, s) atomic_write(p, s or "") end

-- ---------- JSONC хелперы (локальные) ----------
local function strip_json_comments(s)
  local out, i, n = {}, 1, #s
  local in_str, esc = false, false
  while i <= n do
    local c = s:sub(i,i)
    local d = s:sub(i+1,i+1)
    if in_str then
      out[#out+1] = c
      if esc then esc = false
      elseif c == "\\" then esc = true
      elseif c == '"' then in_str = false end
      i = i + 1
    else
      if c == '"' then in_str = true; out[#out+1] = c; i = i + 1
      elseif c == '/' and d == '/' then
        i = i + 2; while i <= n and s:sub(i,i) ~= '\n' do i = i + 1 end
      elseif c == '/' and d == '*' then
        i = i + 2
        while i <= n-1 and not (s:sub(i,i) == '*' and s:sub(i+1,i+1) == '/') do i = i + 1 end
        i = i + 2
      else
        out[#out+1] = c; i = i + 1
      end
    end
  end
  return table.concat(out)
end

local function parse_jsonc_or_empty(raw)
  if (raw or "") == "" then return {} end
  local cleaned = strip_json_comments(raw or "")
  local ok, data = pcall(jsonc.parse, cleaned)
  if not ok or type(data) ~= "table" then return {} end
  return data
end

local function write_json_file(path, tbl)
  local text = jsonc.stringify(tbl or {}, true)
  write_file(path, text)
  return true
end

-- ---------- Утилиты ----------
local function mtime_str(path)
  local st = fs.stat(path)
  if not st or not st.mtime then return "(не найдено)" end
  local size = st.size or 0
  return os.date("%Y-%m-%d %H:%M:%S", st.mtime) .. string.format(" · %d bytes", size)
end

local function shellescape(s)
  if s == nil then return "''" end
  s = tostring(s)
  if s == "" then return "''" end
  return "'" .. s:gsub("'", "'\\''") .. "'"
end

local function log_sys(msg)
  sys.exec(string.format("logger -t %s %s", SYSLOG_TAG, shellescape(msg or "")))
end

local function fetch_to(url, dest)
  local tmp = dest .. ".tmp"
  local cmd = string.format("(command -v curl >/dev/null && curl -L --fail --silent --show-error -o %s %s) " ..
                            "|| (command -v wget >/dev/null && wget -O %s %s)",
                            shellescape(tmp), shellescape(url),
                            shellescape(tmp), shellescape(url))
  local ok = (sys.call(cmd .. " >/dev/null 2>&1") == 0)
  if ok then
    local dir = dest:match("^(.*)/[^/]+$")
    if dir and not fs.access(dir) then sys.call("mkdir -p '"..dir:gsub("'", "'\\''").."'") end
    fs.rename(tmp, dest)
    log_sys(string.format("OK: %s -> %s", url or "", dest or ""))
  else
    fs.remove(tmp)
    log_sys(string.format("FAIL: %s", url or ""))
  end
  return ok
end

-- ---------- CRON ----------
local function cron_body_without_tag()
  local body = read_file(CRON_FILE)
  local new = {}
  for line in (body.."\n"):gmatch("([^\n]*)\n") do
    if not line:find(CRON_TAG, 1, true) and line ~= "" then new[#new+1] = line end
  end
  return table.concat(new, "\n")
end

local function cron_install(spec)
  local new_body = cron_body_without_tag()
  new_body = (new_body ~= "" and (new_body .. "\n") or "") .. string.format("%s %s %s\n", spec, GEO_SCRIPT, CRON_TAG)
  write_file(CRON_FILE, new_body)
  sys.call("/etc/init.d/cron restart >/dev/null 2>&1")
  return true
end

local function cron_remove()
  local body = cron_body_without_tag()
  write_file(CRON_FILE, (body ~= "" and (body .. "\n") or ""))
  sys.call("/etc/init.d/cron restart >/dev/null 2>&1")
  return true
end

local function current_cron_spec()
  local body = read_file(CRON_FILE)
  for line in (body.."\n"):gmatch("([^\n]*)\n") do
    if line:find(CRON_TAG, 1, true) then
      local a,b,c,d,e = line:match("^%s*(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)")
      if a then return table.concat({a,b,c,d,e}, " ") end
    end
  end
  return ""
end

local function cron_spec_human(spec)
  spec = (spec or ""):gsub("^%s+",""):gsub("%s+$","")
  if spec == "" then return "" end
  local parts = {}
  for w in (spec.." "):gmatch("([^%s]+)") do parts[#parts+1] = w end
  if #parts < 5 then return "по расписанию: "..spec end
  local min, hr, dom, mon, dow = parts[1], parts[2], parts[3], parts[4], parts[5]
  local min_num, hr_num = tonumber(min), tonumber(hr)
  local time_str = (min_num and hr_num) and string.format("%d:%02d", hr_num, min_num) or (hr..":"..min)
  local names = { ["0"]="воскресеньям",["7"]="воскресеньям",["1"]="понедельникам",["2"]="вторникам",["3"]="средам",["4"]="четвергам",["5"]="пятницам",["6"]="субботам" }

  if dow ~= "*" and mon == "*" and dom == "*" then
    local days = {}
    for token in (dow..","):gmatch("([^,]+),") do
      if token:match("^%d+%-%d+$") then
        local s,e = token:match("^(%d+)%-(%d+)$"); s=tonumber(s); e=tonumber(e)
        if s and e and s <= e then for d=s,e do days[#days+1]=d end else days[#days+1]=token end
      else
        local n = tonumber(token) or token:lower()
        if n=="sun" then n="0" elseif n=="mon" then n="1" elseif n=="tue" then n="2" elseif n=="wed" then n="3" elseif n=="thu" then n="4" elseif n=="fri" then n="5" elseif n=="sat" then n="6" end
        days[#days+1] = tonumber(n) or n
      end
    end
    local labels, seen = {}, {}
    for _, d in ipairs(days) do local k=tostring(d); if not seen[k] and names[k] then seen[k]=true; labels[#labels+1]=names[k] end end
    table.sort(labels)
    local text = (#labels==0) and ("по дням "..dow) or (#labels==1 and ("по "..labels[1]) or ("по "..table.concat(labels, ", ", 1, #labels-1).." и "..labels[#labels]))
    return time_str ~= "" and (text.." в "..time_str) or text
  end

  if dow == "*" and mon == "*" and dom == "*" then
    return "каждый день в "..time_str
  end

  if dow == "*" and mon == "*" and dom ~= "*" then
    local ords = {}
    for token in (dom..","):gmatch("([^,]+),") do
      local dnum = tonumber(token); ords[#ords+1] = dnum and (tostring(dnum) .. "-го") or (token.."-го")
    end
    local text = (#ords==0 and "ежемесячно") or (#ords==1 and ("ежемесячно "..ords[1].." числа") or ("ежемесячно "..table.concat(ords, " и ").." числа"))
    return text.." в "..time_str
  end

  return "по расписанию: "..spec
end

-- ---------- Работа с конфигом GEO ----------
local function normalize_rows(data)
  local out = {}
  for _, it in ipairs(data) do
    if type(it) == "table" and it.dest then
      out[#out+1] = {
        name = tostring(it.name or ""),
        url  = tostring(it.url  or ""),
        dest = tostring(it.dest)
      }
    end
  end
  return out
end

local function load_geo_cfg()
  local raw = read_file(GEO_CFG)
  local data = parse_jsonc_or_empty(raw)
  return normalize_rows(data)
end

local function save_geo_cfg(rows)
  return write_json_file(GEO_CFG, rows)
end

local function write_geo_script(rows)
  local lines = {
    "#!/bin/sh",
    "# Autogenerated updater for GEO files (list in " .. GEO_CFG .. ")",
    "set -e",
    "LOCK=\"/tmp/tproxy-manager-geo-update.lock\"",
    "if command -v flock >/dev/null 2>&1; then",
    "  exec 9>\"$LOCK\"",
    "  if ! flock -n 9; then logger -t " .. SYSLOG_TAG .. " \"SKIP: already running\"; exit 0; fi",
    "else",
    "  ( set -o noclobber; : >\"$LOCK\" ) 2>/dev/null || { logger -t " .. SYSLOG_TAG .. " \"SKIP: already running\"; exit 0; }",
    "  trap 'rm -f \"$LOCK\"' EXIT INT TERM",
    "fi",
    "logger -t " .. SYSLOG_TAG .. " \"starting update\""
  }
  for _, r in ipairs(rows or {}) do
    if r.url and r.url ~= "" and r.dest and r.dest ~= "" then
      local esc_url  = (r.url:gsub('"','\\"'))
      local esc_dest = (r.dest:gsub('"','\\"'))
      local esc_name = ((r.name or ""):gsub('"','\\"'))
      lines[#lines+1] = string.format([[
# %s
if command -v curl >/dev/null; then
  tmp="%s.tmp"
  mkdir -p "$(dirname "%s")"
  if curl -L --fail --silent --show-error -o "$tmp" "%s"; then
    mv "$tmp" "%s"
    logger -t %s "OK: %s -> %s"
  else
    rm -f "$tmp"
    logger -t %s "FAIL: %s"
  fi
elif command -v wget >/dev/null; then
  tmp="%s.tmp"
  mkdir -p "$(dirname "%s")"
  if wget -q -O "$tmp" "%s"; then
    mv "$tmp" "%s"
    logger -t %s "OK: %s -> %s"
  else
    rm -f "$tmp"
    logger -t %s "FAIL: %s"
  fi
else
  logger -t %s "FAIL: no curl/wget"
fi
]], esc_name,
      esc_dest, esc_dest, esc_url, esc_dest, SYSLOG_TAG, esc_url, esc_dest,
      SYSLOG_TAG, esc_url,
      esc_dest, esc_dest, esc_url, esc_dest, SYSLOG_TAG, esc_url, esc_dest,
      SYSLOG_TAG, esc_url,
      SYSLOG_TAG)
    end
  end
  write_file(GEO_SCRIPT, table.concat(lines, "\n") .. "\n")
  sys.call(string.format("chmod +x %s", shellescape(GEO_SCRIPT)))
  return true
end

-- ===== UI / обработчики =====
local function render(ctx)
  -- Берём из ctx только универсальные сообщения/редирект
  local m = ctx.m
  local set_err, get_err, set_info, get_info = ctx.set_err, ctx.get_err, ctx.set_info, ctx.get_info
  local redirect_here = ctx.redirect_here

  -- Вставляем локальные стили (как было в базовом модуле)
  do
    local sec = m:section(SimpleSection)
    local css = sec:option(DummyValue, "_css_updates"); css.rawhtml = true
    function css.cfgvalue()
      return [[
<style>
/* Общие коробки/контейнеры */
.box{padding:.5rem;border:1px solid #e5e7eb;border-radius:.5rem}
.editor-wrap{max-width:860px}
.editor-wrap textarea{width:100%!important;font-family:monospace}
.editor-wide{max-width:1200px}

/* Маленькие кнопки и инлайн-формы */
.small-btn{padding:.25rem .55rem}
.inline-edit{display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;margin:.6rem 0}
.inline-edit input[type="text"]{width:28%;min-width:180px}
.inline-row{display:flex;align-items:center;gap:.25rem;flex-wrap:nowrap}
.btn-green{background:#16a34a!important;border-color:#16a34a!important;color:#fff!important;font-weight:700!important}

/* Таблица источников GEO */
table.geo-table{width:100%;border-collapse:collapse; table-layout:fixed; word-break:break-all}
table.geo-table th, table.geo-table td{border:1px solid #e5e7eb;padding:.35rem;text-align:left;vertical-align:top}
table.geo-table th{background:#f9fafb}
table.geo-table.geo-upd{ table-layout:auto }
table.geo-table.geo-upd col.col-idx{ width:auto }
table.geo-table.geo-upd th:first-child, table.geo-table.geo-upd td:first-child{ white-space:nowrap }

/* Сообщения */
.msg{padding:.5rem .7rem;border-radius:.5rem;margin:.4rem 0;white-space:pre-wrap}
.msg.err{border:1px solid #fecaca;background:#fef2f2;color:#b91c1c}
.msg.info{border:1px solid #bbf7d0;background:#f0fdf4;color:#166534}
</style>]]
    end
  end

  -- список для таблицы
  local cfg = load_geo_cfg()
  local edit_idx = tonumber(http.formvalue("_geo_edit_idx") or http.formvalue("_geo_edit") or "")

  -- Таблица источников + cron controls
  do
    local sec = m:section(SimpleSection, "Управление обновлениями")
    local list = sec:option(DummyValue, "_geo_list"); list.rawhtml = true
    function list.cfgvalue()
      local rows = {}
      rows[#rows+1] = "<table class='geo-table geo-upd'><colgroup><col class='col-idx'><col><col><col><col><col></colgroup><thead><tr><th>#</th><th>Название</th><th>URL</th><th>Путь</th><th>Дата обновления</th><th>Действия</th></tr></thead><tbody>"
      for i, r in ipairs(cfg) do
        rows[#rows+1] = string.format(
          "<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td>%s</td>" ..
          "<td>" ..
          "<button class='cbi-button cbi-button-apply btn-green small-btn' name='_geo_update_one' value='%s'>Обновить</button> " ..
          "<button class='cbi-button cbi-button-action small-btn' name='_geo_edit' value='%s'>Редактировать</button> " ..
          "<button class='cbi-button cbi-button-remove small-btn' name='_geo_delete' value='%s' onclick=\"return confirm('Удалить источник #%s?')\">Удалить</button>" ..
          "</td></tr>",
          tostring(i),
          pcdata(r.name or ""),
          pcdata(r.url or ""),
          pcdata(r.dest or ""),
          pcdata(mtime_str(r.dest or "")),
          tostring(i), tostring(i), tostring(i), tostring(i)
        )
      end
      if #cfg == 0 then
        rows[#rows+1] = "<tr><td colspan='6' style='color:#6b7280'>Список пуст</td></tr>"
      end

      local spec = current_cron_spec() or ""
      local placeholder = "*/30 * * * *"
      local human = (spec ~= "" and cron_spec_human(spec)) or "Автозапуск обновлений отключён"

      rows[#rows+1] = string.format([[
<tr>
  <td><em>Всего: %s</em></td>
  <td colspan="4">
    <div class="inline-row"><span><em>Расписание:</em></span>
      <input type="text" id="geo_cron" name="geo_cron" style="width:24%%" value="%s" placeholder="%s" title="минуты часы день_месяца месяц день_недели (например: 30 4 * * 0)">
      <select id="geo_cron_presets" style="max-width:220px">
        <option value="">— пресет —</option>
        <option value="0 5 * * *">Каждый день 05:00</option>
        <option value="*/30 * * * *">Каждые 30 минут</option>
        <option value="30 4 * * 0">По воскресеньям 04:30</option>
        <option value="0 3 1 * *">1-го числа 03:00</option>
      </select>
      <button class="cbi-button cbi-button-apply small-btn" name="_geo_install_cron" value="1">Создать/обновить автозапуск</button>
      <button class="cbi-button cbi-button-remove small-btn" name="_geo_remove_cron" value="1">Удалить автозапуск</button>
    </div>
    <div style='margin-top:.2rem; color:#6b7280'>%s</div>
    <div style='margin-top:.1rem; color:#9ca3af'>Формат: <code>мин чч дд мм дн</code>, примеры: <code>0 5 * * *</code> (каждый день в 5:00), <code>30 4 * * 0</code> (по воскресеньям в 4:30)</div>
    <script>
      (function(){
        var sel = document.getElementById('geo_cron_presets');
        var inp = document.getElementById('geo_cron');
        if(sel && inp){
          sel.addEventListener('change', function(){ if(this.value){ inp.value = this.value; } });
        }
      })();
    </script>
  </td>
  <td>
    <button class="cbi-button cbi-button-apply btn-green" name="_geo_update_all" value="1">Обновить все</button>
  </td>
</tr>]], tostring(#cfg), pcdata(spec), pcdata(placeholder), pcdata(human))

      rows[#rows+1] = "</tbody></table>"
      return table.concat(rows, "\n")
    end
  end

  -- Форма редактирования конкретной записи
  if edit_idx then
    local sec = m:section(SimpleSection, "Редактировать источник #" .. edit_idx)
    local dv = sec:option(DummyValue, "_geo_edit_form"); dv.rawhtml = true
    function dv.cfgvalue()
      local r = cfg[edit_idx]
      if not r then return "(Неверный индекс)" end
      return string.format([[
<div class="box editor-wrap inline-edit">
  <div>Название: <input type="text" name="edit_name" style="width:20%%" value="%s"></div>
  <div>URL: <input type="text" name="edit_url" style="width:35%%" value="%s"></div>
  <div>Путь: <input type="text" name="edit_dest" style="width:35%%" value="%s"></div>
  <div>
    <button class="cbi-button cbi-button-apply" name="_geo_apply_edit" value="1">Сохранить</button>
    <button class="cbi-button cbi-button-reset" name="_geo_cancel_edit" value="1">Отменить</button>
  </div>
</div>
<input type="hidden" name="_geo_edit_idx" value="%s">]],
        pcdata(r.name or ""), pcdata(r.url or ""), pcdata(r.dest or ""), tostring(edit_idx))
    end
  end

  -- Блок добавления новой записи
  if not edit_idx then
    local sec = m:section(SimpleSection, "Добавить источник")
    local dv = sec:option(DummyValue, "_geo_add"); dv.rawhtml = true
    function dv.cfgvalue()
      return [[
<div class="box editor-wrap inline-edit">
  <div>Название: <input type="text" name="add_name" style="width:20%%" placeholder="например, geoip"></div>
  <div>URL: <input type="text" name="add_url" style="width:35%%" placeholder="https://.../файл.dat"></div>
  <div>Путь: <input type="text" name="add_dest" style="width:35%%" placeholder="/usr/share/xray/geoip.dat"></div>
  <div><button class="cbi-button cbi-button-apply" name="_geo_add" value="1">Добавить</button></div>
</div>]]
    end
  end

  -- Текстовый JSON-редактор полного списка
  do
    local sec = m:section(SimpleSection)
    local dv = sec:option(DummyValue, "_geo_edit_json"); dv.rawhtml = true
    local raw = read_file(GEO_CFG); if raw == "" then raw = "[]" end
    function dv.cfgvalue()
      local content = read_file(GEO_CFG); if content == "" then content = "[]" end
      return [[
<details>
  <summary style="cursor:pointer;font-weight:600">Общий список источников (JSON) — развернуть/свернуть</summary>
  <div class="box editor-wrap editor-wide" style="margin-top:.5rem">
    <textarea name="geo_sources" rows="12" spellcheck="false">]] .. pcdata(content) .. [[</textarea>
    <div class="inline-row" style="margin-top:.4rem">
      <button class="cbi-button cbi-button-apply"  name="_geo_save" value="1">Сохранить список</button>
      <button class="cbi-button cbi-button-action" name="_geo_write_script" value="1">Пересоздать скрипт</button>
      <span style="color:#6b7280">Список источников: <code>]] .. pcdata(GEO_CFG) .. [[</code> · Скрипт: <code>]] .. pcdata(GEO_SCRIPT) .. [[</code></span>
    </div>
  </div>
</details>
]]
    end
  end

  -- ---------- Обработчики действий ----------
  do
    local function load_rows_again()
      return load_geo_cfg()
    end

    if http.formvalue("_geo_add") == "1" then
      local rows = load_rows_again()
      local name = (http.formvalue("add_name") or ""):gsub("^%s+",""):gsub("%s+$","")
      local url  = (http.formvalue("add_url")  or ""):gsub("^%s+",""):gsub("%s+$","")
      local dest = (http.formvalue("add_dest") or ""):gsub("^%s+",""):gsub("%s+$","")
      if dest ~= "" then
        rows[#rows+1] = { name = name, url = url, dest = dest }
        save_geo_cfg(rows)
        write_geo_script(rows)
        set_err(nil); set_info("Источник добавлен: "..(name ~= "" and name or dest))
      else
        set_err("Нужно указать путь назначения (dest)."); set_info(nil)
      end
      redirect_here("updates"); return m
    end

    if http.formvalue("_geo_update_one") then
      local idx = tonumber(http.formvalue("_geo_update_one"))
      local rows = load_rows_again()
      local r = (idx and rows[idx]) and rows[idx] or nil
      if r and r.url ~= "" and r.dest ~= "" then
        local ok = fetch_to(r.url, r.dest)
        set_info(ok and ("Обновлено: "..(r.name or r.dest)) or ("Ошибка обновления: "..(r.name or r.dest)))
        set_err(nil)
      end
      redirect_here("updates"); return m
    end

    if http.formvalue("_geo_update_all") == "1" then
      local rows = load_rows_again()
      local ok_count, total = 0, 0
      for _, r in ipairs(rows) do
        if r.url and r.url ~= "" and r.dest and r.dest ~= "" then
          total = total + 1
          if fetch_to(r.url, r.dest) then ok_count = ok_count + 1 end
        end
      end
      set_info(string.format("Обновлено %d из %d источников", ok_count, total)); set_err(nil)
      redirect_here("updates"); return m
    end

    if http.formvalue("_geo_edit") then
      local idx = tonumber(http.formvalue("_geo_edit"))
      if idx then
        http.redirect(disp.build_url("admin","network","tproxy_manager") .. "?tab=updates&_geo_edit_idx=" .. idx)
        return m
      end
    end

    if http.formvalue("_geo_apply_edit") == "1" then
      local idx = tonumber(http.formvalue("_geo_edit_idx") or "")
      local rows = load_rows_again()
      if idx and rows[idx] then
        local dest = (http.formvalue("edit_dest") or ""):gsub("^%s+",""):gsub("%s+$","")
        if dest == "" then
          set_err("Нужно указать путь назначения (dest)."); set_info(nil)
          http.redirect(disp.build_url("admin","network","tproxy_manager") .. "?tab=updates&_geo_edit_idx=" .. tostring(idx))
          return m
        end
        rows[idx].name = (http.formvalue("edit_name") or "")
        rows[idx].url  = (http.formvalue("edit_url")  or "")
        rows[idx].dest = dest
        save_geo_cfg(rows)
        set_err(nil); set_info("Источник обновлён: "..(rows[idx].name or rows[idx].dest))
      end
      redirect_here("updates"); return m
    end

    if http.formvalue("_geo_cancel_edit") == "1" then
      redirect_here("updates"); return m
    end

    if http.formvalue("_geo_delete") then
      local idx = tonumber(http.formvalue("_geo_delete"))
      local rows = load_rows_again()
      if idx and rows[idx] then
        local name = rows[idx].name or rows[idx].dest
        table.remove(rows, idx)
        save_geo_cfg(rows)
        write_geo_script(rows)
        set_info("Удалён источник: "..(name or ("#"..tostring(idx)))); set_err(nil)
      end
      redirect_here("updates"); return m
    end

    if http.formvalue("_geo_save") == "1" then
      local raw = http.formvalue("geo_sources") or "[]"
      local data = parse_jsonc_or_empty(raw)
      local rows = normalize_rows(data)
      save_geo_cfg(rows)
      write_geo_script(rows)
      set_err(nil); set_info("Список источников сохранён")
      redirect_here("updates"); return m
    end

    if http.formvalue("_geo_write_script") == "1" then
      local rows = load_rows_again()
      write_geo_script(rows)
      set_info("Скрипт обновления пересоздан"); set_err(nil)
      redirect_here("updates"); return m
    end

    if http.formvalue("_geo_install_cron") == "1" then
      local rows = load_rows_again()
      write_geo_script(rows)
      local spec = (http.formvalue("geo_cron") or ""):gsub("%s+"," ")
      if spec == "" then spec = "0 5 * * *" end
      local fields = {}
      for w in spec:gmatch("%S+") do fields[#fields+1] = w end
      if #fields ~= 5 then
        set_err("Некорректное выражение cron: требуется 5 полей (мин чч дд мм дн). Получено: "..spec); set_info(nil)
      else
        cron_install(spec)
        set_info("Cron установлен: "..spec); set_err(nil)
      end
      redirect_here("updates"); return m
    end

    if http.formvalue("_geo_remove_cron") == "1" then
      cron_remove()
      set_info("Cron удалён"); set_err(nil)
      redirect_here("updates"); return m
    end

    local sec = m:section(SimpleSection)
    local dv = sec:option(DummyValue, "_geo_msgs"); dv.rawhtml = true; dv.title = ""
    function dv.cfgvalue()
      local e = get_err(); local i = get_info()
      local out = {}
      if e ~= "" then out[#out+1] = "<div class='msg err'>"..pcdata(e).."</div>" end
      if i ~= "" then out[#out+1] = "<div class='msg info'>"..pcdata(i).."</div>" end
      if i ~= "" then set_info(nil) end
      return table.concat(out)
    end
  end
end

return { render = render }
