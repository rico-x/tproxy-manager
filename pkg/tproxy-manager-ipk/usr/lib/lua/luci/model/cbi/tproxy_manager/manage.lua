-- /usr/lib/lua/luci/model/cbi/tproxy_manager/manage.lua
local fs    = require "nixio.fs"
local sys   = require "luci.sys"
local jsonc = require "luci.jsonc"
local http  = require "luci.http"
local disp  = require "luci.dispatcher"
local xml   = require "luci.xml"
local ucim  = require "luci.model.uci"
local uci   = ucim.cursor()
local cbi   = require "luci.cbi"
local SimpleSection, DummyValue, Button =
  cbi.SimpleSection, cbi.DummyValue, cbi.Button

-- Алиасы
local pcdata     = xml.pcdata
local formvalue  = http.formvalue

-- Пакет/пути
local PKG      = "tproxy-manager"
local BASE_DIR = "/etc/tproxy-manager"

-- ---------- минимальные файловые хелперы ----------
local function atomic_write(path, data)
  data = (data or ""):gsub("\r\n","\n")
  local dir, base = path:match("^(.*)/([^/]+)$")
  local tmpdir = dir and dir or "/tmp"
  if dir and not fs.access(dir) then
    sys.call("mkdir -p '"..dir:gsub("'", "'\\''").."'")
  end
  local tmp = string.format("%s/.%s.%d.tmp", tmpdir, base or "tmp", math.random(1, 10^9))
  fs.writefile(tmp, data)
  fs.rename(tmp, path)
end
local function read_file(p)  return fs.readfile(p) or "" end
local function write_file(p, s) atomic_write(p, s or "") end

-- Сообщения с TTL
local ERR_F   = "/tmp/tproxy_manager_last_error"
local INF_F   = "/tmp/tproxy_manager_last_info"
local ERR_TTL = 60

local function set_err(s)  if s and s~="" then write_file(ERR_F, s) else fs.remove(ERR_F) end end
local function get_err()
  local st = fs.stat(ERR_F)
  if st and st.mtime and (os.time() - st.mtime) > ERR_TTL then
    fs.remove(ERR_F); return ""
  end
  return read_file(ERR_F)
end
local function set_info(s) if s and s~="" then write_file(INF_F, s) else fs.remove(INF_F) end end
local function get_info()  return read_file(INF_F) end

-- Общий system log (модулям может понадобиться)
local function combined_log()
  local out = sys.exec("logread 2>/dev/null | tail -n 200")
  return (out and out ~= "") and out or "(нет строк лога)"
end

-- service helpers (общие для всех модулей)
local function svc_status_txt(name)
  local txt = sys.exec(string.format("[ -x /etc/init.d/%s ] && /etc/init.d/%s status 2>&1 || echo 'N/A'", name, name)) or ""
  return txt:gsub("%s+$","")
end
local function svc_running(txt)
  if not txt or txt == "" then return false end
  local s = txt:lower()
  if s:match("not[%s%-_]*running") or s:match("stopped") then return false end
  return s:find("%f[%a]running%f[%A]") ~= nil
end
local function is_enabled(name)
  return sys.call(string.format("[ -x /etc/init.d/%s ] && /etc/init.d/%s enabled >/dev/null 2>&1", name, name)) == 0
end
local function svc_do(name, op)
  if not name or not op then return end
  if not name:match("^[%w%-%_]+$") then return end
  if not ({start=true,stop=true,enable=true,disable=true})[op] then return end
  sys.call(string.format("[ -x /etc/init.d/%s ] && /etc/init.d/%s %s >/dev/null 2>&1", name, name, op))
end

-- Универсальный блок статуса сервиса
local function service_block(sec, svc, label, tabname)
  local d = sec:option(DummyValue, "_"..svc.."_stat")
  d.rawhtml = true
  function d.cfgvalue()
    local stxt = svc_status_txt(svc)
    local run  = svc_running(stxt)
    local en   = is_enabled(svc)
    return string.format(
      "<div class='svc-row'><div class='svc-title'><strong>%s</strong>: " ..
      "<span class='svc-badge %s'>%s</span> · <span class='svc-badge %s'>%s</span></div></div>",
      pcdata(label),
      run and "ok" or "err", run and "работает" or "остановлен",
      en and "ok" or "err",  en  and "в автозапуске" or "не в автозапуске"
    )
  end

  local bstart = sec:option(Button, "_"..svc.."_start"); bstart.title = ""; bstart.inputtitle = "Запустить"
  bstart.inputstyle = "apply"
  function bstart.render(self, section) if svc_running(svc_status_txt(svc)) then return end; Button.render(self, section) end
  function bstart.write(self, section) if not self.map:formvalue(self:cbid(section)) then return end; svc_do(svc,"start"); set_err(nil); http.redirect(disp.build_url("admin","network","tproxy_manager").."?tab="..(tabname or "")) end

  local bstop  = sec:option(Button, "_"..svc.."_stop"); bstop.title = ""; bstop.inputtitle = "Остановить"
  bstop.inputstyle = "remove"
  function bstop.render(self, section) if not svc_running(svc_status_txt(svc)) then return end; Button.render(self, section) end
  function bstop.write(self, section) if not self.map:formvalue(self:cbid(section)) then return end; svc_do(svc,"stop"); set_err(nil); http.redirect(disp.build_url("admin","network","tproxy_manager").."?tab="..(tabname or "")) end

  local ben   = sec:option(Button, "_"..svc.."_enable"); ben.title = ""; ben.inputtitle = "Добавить в автозапуск"
  ben.inputstyle = "apply"
  function ben.render(self, section) if is_enabled(svc) then return end; Button.render(self, section) end
  function ben.write(self, section) if not self.map:formvalue(self:cbid(section)) then return end; svc_do(svc,"enable"); set_err(nil); http.redirect(disp.build_url("admin","network","tproxy_manager").."?tab="..(tabname or "")) end

  local bdis  = sec:option(Button, "_"..svc.."_disable"); bdis.title = ""; bdis.inputtitle = "Убрать из автозапуска"
  bdis.inputstyle = "remove"
  function bdis.render(self, section) if not is_enabled(svc) then return end; Button.render(self, section) end
  function bdis.write(self, section) if not self.map:formvalue(self:cbid(section)) then return end; svc_do(svc,"disable"); set_err(nil); http.redirect(disp.build_url("admin","network","tproxy_manager").."?tab="..(tabname or "")) end
end

-- Форма-значения
local function fval(name)
  local v = formvalue(name)
  if type(v) == 'table' then return v[1] or '' else return v or '' end
end
local function fval_last(name)
  local v = formvalue(name)
  if type(v) == 'table' then return v[#v] or '' else return v or '' end
end

-- Утилиты (нужны модулям)
local function urlencode(s) return (http and http.urlencode) and http.urlencode(s) or tostring(s or "") end
local function pick_form_or_uci(form_val, uci_val)
  return (form_val ~= nil and form_val ~= "") and form_val or (uci_val or "")
end
local function is_port(v)
  if not v or v == "" or not v:match("^%d+$") then return false end
  local n = tonumber(v)
  return n >= 1 and n <= 65535
end
local function append_line_unique(path, line)
  if not line or line == "" then return end
  local body = read_file(path)
  for ln in (body .. "\n"):gmatch("([^\n]*)\n") do
    if ln:gsub("^%s+",""):gsub("%s+$","") == line then return end
  end
  write_file(path, (body ~= "" and (body:match("\n$") and body or body.."\n") or "") .. line .. "\n")
end

-- Ссылка на самих себя
local function self_url(opts)
  opts = opts or {}
  local url = disp.build_url("admin","network","tproxy_manager")
  local qp = {}
  if opts.tab and #opts.tab>0 then qp[#qp+1] = "tab="..urlencode(opts.tab) end
  if #qp>0 then url = url .. "?" .. table.concat(qp,"&") end
  return url
end
local function redirect_here(tab)
  http.redirect(self_url({ tab = tab }))
end

-- ensure dirs
do
  local st = fs.stat(BASE_DIR); if not (st and st.type == "directory") then fs.mkdir(BASE_DIR) end
end

-- ensure UCI defaults (TPROXY обязателен; остальные модули по умолчанию выключены)
do
  uci:section(PKG,"main","main",{})
  local changed = false
  local function ensure(k, def)
    local v = uci:get(PKG,"main",k)
    if v == nil or v == "" then uci:set(PKG,"main",k,def); changed = true end
  end
  -- Флаги модулей
  ensure("enable_xray",    "0")
  ensure("enable_mihomo",  "0")
  ensure("enable_updates", "0")

  -- Базовые TPROXY-параметры
  ensure("log_enabled", "1")
  ensure("nft_table", "tproxy")
  ensure("ifaces", "br-lan")
  ensure("ipv6_enabled", "1")
  ensure("tproxy_port", "61219")
  ensure("fwmark_tcp", "0x1")
  ensure("fwmark_udp", "0x2")
  ensure("rttab_tcp", "100")
  ensure("rttab_udp", "101")
  ensure("port_mode", "bypass")
  ensure("ports_file", BASE_DIR.."/tproxy-manager.ports")
  ensure("bypass_v4_file", BASE_DIR.."/tproxy-manager.v4")
  ensure("bypass_v6_file", BASE_DIR.."/tproxy-manager.v6")
  ensure("src_mode", "off")
  ensure("src_only_v4_file",  BASE_DIR.."/tproxy-manager.src4.only")
  ensure("src_only_v6_file",  BASE_DIR.."/tproxy-manager.src6.only")
  ensure("src_bypass_v4_file",BASE_DIR.."/tproxy-manager.src4.bypass")
  ensure("src_bypass_v6_file",BASE_DIR.."/tproxy-manager.src6.bypass")

  if changed then uci:commit(PKG) end
end

-- Текущие признаки активных модулей из UCI
local ENABLE_XRAY    = (uci:get(PKG,"main","enable_xray")    == "1")
local ENABLE_MIHOMO  = (uci:get(PKG,"main","enable_mihomo")  == "1")
local ENABLE_UPDATES = (uci:get(PKG,"main","enable_updates") == "1")

-- Попробуем сетевую модель (ядру TPROXY может пригодиться)
local netm_init = nil
do
  local ok, res = pcall(function() return require("luci.model.network").init() end)
  if ok then netm_init = res end
end

-- ---------- Построение формы ----------
-- Убрали описание (только заголовок)
local m = cbi.SimpleForm("tproxy_manager", "TPROXY Manager")
m.submit = true
m.reset  = false

-- Базовые стили (общие)
do
  local s = m:section(SimpleSection)
  local dv = s:option(DummyValue, "_css_base"); dv.rawhtml = true
  function dv.cfgvalue() return [[
<style>
.cbi-page-actions{display:none!important}
.cbi-section{margin:.12rem 0}
.cbi-value{margin:.04rem 0}
/* service status row */
.svc-row{margin:.02rem 0;padding:.06rem .2rem;border-radius:.2rem;background:rgba(255,255,255,.03)}
.svc-title{margin:0}
.svc-badge{font-weight:600}
.svc-badge.ok{color:#16a34a}
.svc-badge.err{color:#dc2626}
/* сервисные кнопки в одну линию */
#cbi-tproxy_manager .cbi-value[id*="_start"],
#cbi-tproxy_manager .cbi-value[id*="_stop"],
#cbi-tproxy_manager .cbi-value[id*="_enable"],
#cbi-tproxy_manager .cbi-value[id*="_disable"]{
  display:inline-block; vertical-align:middle; margin:0 2px 0 0; padding:0; border:0;
}
#cbi-tproxy_manager .cbi-value[id*="_start"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id*="_stop"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id*="_enable"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id*="_disable"] .cbi-value-title{display:none}
.msg{padding:.5rem .7rem;border-radius:.5rem;margin:.4rem 0;white-space:pre-wrap}
.msg.err{border:1px solid #fecaca;background:#fef2f2;color:#b91c1c}
.msg.info{border:1px solid #bbf7d0;background:#f0fdf4;color:#166534}
.box{padding:.5rem;border:1px solid #e5e7eb;border-radius:.5rem}
.inline-row{display:flex;align-items:center;gap:.25rem;flex-wrap:nowrap}
.editor-wrap{max-width:860px}
.editor-wide{max-width:1200px}
.leases-table{ width:100%; border-collapse:collapse }
.leases-table th, .leases-table td{border:1px solid #e5e7eb; padding:.35rem; vertical-align:top}
.leases-table th{background:#f9fafb}
/* прибираем зазор непосредственно после блока доп.настроек: */
#extra-mods{ margin: .25rem 0 0 0; }
#extra-mods + .cbi-section{ margin-top: 0 !important; }
</style>]] end
end

-- Hidden + JS guard (вверх — не даёт визуальных отступов)
do
  local s = m:section(SimpleSection)
  local dv = s:option(DummyValue, "_hidden"); dv.rawhtml = true
  function dv.cfgvalue()
    local function esc(x) return pcdata(x or "") end
    return string.format([[
<input type="hidden" name="tab" value="%s"/>
<script>
(function(){
  window.__xray_dirty = false;
  document.addEventListener('input', function(e){
    var n = e && e.target && e.target.name;
    if (n === 'uniedit_text' || n === 'json_text' || n === 'clash_text' || n === 'mihomo_text' || n === 'geo_sources') window.__xray_dirty = true;
  }, true);
  window.__xray_guard = function(){ return (!window.__xray_dirty) || confirm('Есть несохранённые изменения. Перейти без сохранения?'); };
  setTimeout(function(){
    var infos = document.querySelectorAll('.msg.info');
    infos.forEach(function(el){ el.style.transition='opacity .4s'; el.style.opacity='0';
      setTimeout(function(){ if (el && el.parentNode) el.parentNode.removeChild(el); }, 450);
    });
  }, 5000);
})();
</script>]],
      esc(fval("tab") or "tproxy")
    )
  end
end

-- navbar (идёт перед доп.настройками)
do
  local s = m:section(SimpleSection)
  local nav = s:option(DummyValue, "_nav"); nav.rawhtml = true
  function nav.cfgvalue()
    local cur = fval("tab") or "tproxy"
    local function link(id, title, enabled)
      if enabled == false then return "" end
      local url = self_url({ tab = id })
      local cls = (cur==id) and "class='cbi-button cbi-button-apply'" or "class='cbi-button cbi-button-action'"
      return string.format("<a %s style='margin-right:.4rem' href='%s' onclick='return window.__xray_guard?window.__xray_guard():true'>%s</a>", cls, url, pcdata(title))
    end
    local out = {}
    out[#out+1] = link("tproxy", "TPROXY", true)
    out[#out+1] = link("xray",   "XRAY",   (uci:get(PKG,"main","enable_xray") == "1"))
    out[#out+1] = link("mihomo", "MIHOMO", (uci:get(PKG,"main","enable_mihomo") == "1"))
    out[#out+1] = link("updates","Обновление геобаз", (uci:get(PKG,"main","enable_updates") == "1"))
    return "<div style='margin:.2rem 0 .2rem 0'>" .. table.concat(out, "") .. "</div>"
  end
end

-- Обработчик сохранения флагов модулей (без отдельной формы)
if http.formvalue("_save_modules") == "1" then
  local ex = http.formvalue("enable_xray") == "1" and "1" or "0"
  local em = http.formvalue("enable_mihomo") == "1" and "1" or "0"
  local eu = http.formvalue("enable_updates") == "1" and "1" or "0"
  uci:set(PKG,"main","enable_xray",    ex)
  uci:set(PKG,"main","enable_mihomo",  em)
  uci:set(PKG,"main","enable_updates", eu)
  uci:commit(PKG)
  set_info("Настройки модулей сохранены.")
  redirect_here(fval("tab") or "tproxy")
  return m
end

-- Дополнительные настройки — СРАЗУ перед модулями, без лишнего отступа снизу
do
  local s = m:section(SimpleSection)
  local dv = s:option(DummyValue, "_extra"); dv.rawhtml = true
  function dv.cfgvalue()
    local cur = fval("tab") or "tproxy"
    local ex = (uci:get(PKG,"main","enable_xray")    == "1") and "checked" or ""
    local em = (uci:get(PKG,"main","enable_mihomo")  == "1") and "checked" or ""
    local eu = (uci:get(PKG,"main","enable_updates") == "1") and "checked" or ""
    return string.format([[
<details id="extra-mods">
  <summary style="cursor:pointer">Дополнительные настройки</summary>
  <div class="box" style="max-width:860px; margin-top:.4rem">
    <div class="inline-row" style="flex-wrap:wrap; gap:.8rem">
      <label><input type="checkbox" name="enable_xray" value="1" %s> Вкладка XRAY</label>
      <label><input type="checkbox" name="enable_mihomo" value="1" %s> Вкладка MIHOMO</label>
      <label><input type="checkbox" name="enable_updates" value="1" %s> Вкладка Обновления геобаз</label>
    </div>
    <div style="margin-top:.5rem">
      <button class="cbi-button cbi-button-apply" name="_save_modules" value="1">Сохранить</button>
      <input type="hidden" name="tab" value="%s"/>
    </div>
  </div>
</details>]],
      ex, em, eu, pcdata(cur)
    )
  end
end

-- redirect на TPROXY по умолчанию
if not http.formvalue("tab") or http.formvalue("tab") == "" then
  http.redirect(disp.build_url("admin","network","tproxy_manager") .. "?tab=tproxy")
  return m
end

local cur_tab = fval("tab") or "tproxy"

-- Общий контекст для модулей
local ctx = {
  PKG = PKG, BASE_DIR = BASE_DIR,
  m = m, uci = uci, http = http, sys = sys, fs = fs, disp = disp, jsonc = jsonc, xml = xml,
  pcdata = pcdata, fval = fval, fval_last = fval_last,
  self_url = self_url, redirect_here = redirect_here,
  combined_log = combined_log, service_block = service_block,
  set_err = set_err, get_err = get_err, set_info = set_info, get_info = get_info,

  -- утилиты
  write_file = write_file, read_file = read_file,
  pick_form_or_uci = pick_form_or_uci,
  append_line_unique = append_line_unique,
  is_port = is_port,
  netm_init = netm_init,
}

-- Загрузка модулей согласно вкладке и UCI-флагам
if cur_tab == "tproxy" then
  require("luci.model.cbi.tproxy_manager.modules.tproxy").render(ctx)
elseif cur_tab == "xray" and (uci:get(PKG,"main","enable_xray") == "1") then
  require("luci.model.cbi.tproxy_manager.modules.xray").render(ctx)
elseif cur_tab == "mihomo" and (uci:get(PKG,"main","enable_mihomo") == "1") then
  require("luci.model.cbi.tproxy_manager.modules.mihomo").render(ctx)
elseif cur_tab == "updates" and (uci:get(PKG,"main","enable_updates") == "1") then
  require("luci.model.cbi.tproxy_manager.modules.updates").render(ctx)
else
  http.redirect(self_url({ tab = "tproxy" }))
  return m
end

-- Сообщения (ошибка/инфо) — в самом низу, чтобы не вставали между «доп.настройками» и модулем
do
  local s = m:section(SimpleSection)
  local msg = s:option(DummyValue, "_msgs"); msg.rawhtml = true; msg.title = ""
  function msg.cfgvalue()
    local e = get_err(); local i = get_info()
    local out = {}
    if e ~= "" then out[#out+1] = "<div class='msg err'>"..pcdata(e).."</div>" end
    if i ~= "" then out[#out+1] = "<div class='msg info'>"..pcdata(i).."</div>" end
    if i ~= "" then set_info(nil) end
    return table.concat(out)
  end
end

return m
