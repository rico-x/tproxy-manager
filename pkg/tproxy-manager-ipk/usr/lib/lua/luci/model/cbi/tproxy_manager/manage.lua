local fs    = require "nixio.fs"
local sys   = require "luci.sys"
local jsonc = require "luci.jsonc"
local http  = require "luci.http"
local disp  = require "luci.dispatcher"
local xml   = require "luci.xml"
local ucim  = require "luci.model.uci"
local uci   = ucim.cursor()
local cbi   = require "luci.cbi"
local SimpleSection, TypedSection, NamedSection, Value, DummyValue, Button =
  cbi.SimpleSection, cbi.TypedSection, cbi.NamedSection, cbi.Value, cbi.DummyValue, cbi.Button

-- Aliases
local pcdata     = xml.pcdata
local formvalue  = http.formvalue

-- UCI package and paths (renamed)
local PKG        = "tproxy-manager"
local BASE_DIR   = "/etc/tproxy-manager"
local XRAY_DIR   = "/etc/xray"
local CLASH_DIR  = "/etc/clash"
local LOG_TEST   = "/tmp/tproxy_manager_xray_test.log"
local CLASH_TEST_LOG = "/tmp/tproxy_manager_clash_test.log"

-- ---------- helpers ----------
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

local function write_json_file(path, text)
  text = (text or ""):gsub("\r\n", "\n")
  local cleaned = strip_json_comments(text)
  local ok, parsed = pcall(jsonc.parse, cleaned)
  if not ok or parsed == nil then
    return nil, "Некорректный JSON (ошибка разбора)"
  end
  write_file(path, text)
  return true
end

-- Сообщения с TTL
local ERR_F   = "/tmp/tproxy_manager_last_error"
local INF_F   = "/tmp/tproxy_manager_last_info"
local ERR_TTL = 60

local function set_err(s)  if s and s~="" then write_file(ERR_F, s) else fs.remove(ERR_F) end end
local function get_err()
  local st = fs.stat(ERR_F)
  if st and st.mtime and (os.time() - st.mtime) > ERR_TTL then
    fs.remove(ERR_F)
    return ""
  end
  return read_file(ERR_F)
end
local function set_info(s) if s and s~="" then write_file(INF_F, s) else fs.remove(INF_F) end end
local function get_info()  return read_file(INF_F) end

local function get_xray_bin()
  if fs.access("/usr/bin/xray") then return "/usr/bin/xray"
  elseif fs.access("/usr/sbin/xray") then return "/usr/sbin/xray"
  else return "xray" end
end
local XRAY_BIN = get_xray_bin()

local function get_clash_bin()
  if fs.access("/usr/bin/clash") then return "/usr/bin/clash"
  elseif fs.access("/usr/sbin/clash") then return "/usr/sbin/clash"
  else return "clash" end
end
local CLASH_BIN = get_clash_bin()

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

local function combined_log()
  local out = sys.exec("logread 2>/dev/null | tail -n 200")
  return (out and out ~= "") and out or "(нет строк лога)"
end

local function urlencode(s) return (http and http.urlencode) and http.urlencode(s) or s end
local function fval(name)
  local v = formvalue(name)
  if type(v) == 'table' then return v[1] or '' else return v or '' end
end
local function fval_last(name)
  local v = formvalue(name)
  if type(v) == 'table' then return v[#v] or '' else return v or '' end
end
local function pick_form_or_uci(form_val, uci_val)
  return (form_val ~= nil and form_val ~= "") and form_val or (uci_val or "")
end

local function self_url(opts)
  opts = opts or {}
  local url = disp.build_url("admin","network","tproxy_manager")
  local qp = {}
  if opts.tab and #opts.tab>0 then qp[#qp+1] = "tab="..urlencode(opts.tab) end
  if opts.list_file and #opts.list_file>0 then qp[#qp+1] = "list_file="..urlencode(opts.list_file) end
  if opts.json_file and #opts.json_file>0 then qp[#qp+1] = "json_file="..urlencode(opts.json_file) end
  if opts.clash_file and #opts.clash_file>0 then qp[#qp+1] = "clash_file="..urlencode(opts.clash_file) end
  if opts.port_mode and #opts.port_mode>0 then qp[#qp+1] = "tpx_port_mode="..urlencode(opts.port_mode) end
  if opts.src_mode  and #opts.src_mode>0  then qp[#qp+1] = "tpx_src_mode="..urlencode(opts.src_mode)  end
  if #qp>0 then url = url .. "?" .. table.concat(qp,"&") end
  return url
end

local function redirect_here(tab)
  http.redirect(self_url({
    tab       = tab,
    list_file = fval_last("list_file"),
    json_file = fval_last("json_file"),
    clash_file = fval_last("clash_file"),
    port_mode = fval("tpx_port_mode"),
    src_mode  = fval("tpx_src_mode"),
  }))
end

-- ensure dirs
do
  local st = fs.stat(BASE_DIR); if not (st and st.type == "directory") then fs.mkdir(BASE_DIR) end
  local st2 = fs.stat(XRAY_DIR); if not (st2 and st2.type == "directory") then fs.mkdir(XRAY_DIR) end
  local st3 = fs.stat(CLASH_DIR); if not (st3 and st3.type == "directory") then fs.mkdir(CLASH_DIR) end
end

-- ensure UCI defaults
do
  uci:section(PKG,"main","main",{})
  local changed = false
  local function ensure(k, def)
    local v = uci:get(PKG,"main",k)
    if v == nil or v == "" then uci:set(PKG,"main",k,def); changed = true end
  end
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

-- network model (optional)
local netm_init = nil
do
  local ok, res = pcall(function() return require("luci.model.network").init() end)
  if ok then netm_init = res end
end

local function is_port(v)
  if not v or v == "" or not v:match("^%d+$") then return false end
  local n = tonumber(v)
  return n >= 1 and n <= 65535
end

-- ---------- общие UI-компоненты ----------
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
  function bstart.write(self, section) if not self.map:formvalue(self:cbid(section)) then return end; svc_do(svc,"start"); set_err(nil); redirect_here(tabname) end

  local bstop  = sec:option(Button, "_"..svc.."_stop"); bstop.title = ""; bstop.inputtitle = "Остановить"
  bstop.inputstyle = "remove"
  function bstop.render(self, section) if not svc_running(svc_status_txt(svc)) then return end; Button.render(self, section) end
  function bstop.write(self, section) if not self.map:formvalue(self:cbid(section)) then return end; svc_do(svc,"stop"); set_err(nil); redirect_here(tabname) end

  local ben   = sec:option(Button, "_"..svc.."_enable"); ben.title = ""; ben.inputtitle = "Добавить в автозапуск"
  ben.inputstyle = "apply"
  function ben.render(self, section) if is_enabled(svc) then return end; Button.render(self, section) end
  function ben.write(self, section) if not self.map:formvalue(self:cbid(section)) then return end; svc_do(svc,"enable"); set_err(nil); redirect_here(tabname) end

  local bdis  = sec:option(Button, "_"..svc.."_disable"); bdis.title = ""; bdis.inputtitle = "Убрать из автозапуска"
  bdis.inputstyle = "remove"
  function bdis.render(self, section) if not is_enabled(svc) then return end; Button.render(self, section) end
  function bdis.write(self, section) if not self.map:formvalue(self:cbid(section)) then return end; svc_do(svc,"disable"); set_err(nil); redirect_here(tabname) end
end

local function append_line_unique(path, line)
  if not line or line == "" then return end
  local body = read_file(path)
  for ln in (body .. "\n"):gmatch("([^\n]*)\n") do
    if ln:gsub("^%s+",""):gsub("%s+$","") == line then return end
  end
  write_file(path, (body ~= "" and (body:match("\n$") and body or body.."\n") or "") .. line .. "\n")
end

-- Build SimpleForm
local m = SimpleForm("tproxy_manager", "TPROXY Manager",
  "Редактирование конфигов Xray/Clash и настроек TPROXY, просмотр статусов и перезапуск сервисов.")
m.submit = true
m.reset  = false

-- navbar
do
  local s = m:section(SimpleSection)
  local nav = s:option(DummyValue, "_nav"); nav.rawhtml = true
  function nav.cfgvalue()
    local cur = fval("tab") or "tproxy"
    local function link(id, title)
      local url = self_url({
        tab=id,
        list_file=fval_last("list_file"),
        json_file=fval_last("json_file"),
        clash_file=fval_last("clash_file"),
        port_mode=fval("tpx_port_mode"),
        src_mode=fval("tpx_src_mode")
      })
      local cls = (cur==id) and "class='cbi-button cbi-button-apply'" or "class='cbi-button cbi-button-action'"
      return string.format("<a %s style='margin-right:.4rem' href='%s'>%s</a>", cls, url, pcdata(title))
    end
    return "<div style='margin:.2rem 0 .2rem 0'>" ..
      link("tproxy", "TPROXY") ..
      link("xray", "XRAY") ..
      link("clash", "CLASH") ..
      link("updates", "Обновление геобаз") ..
      "</div>"
  end
end

-- hidden persist + guard + авто-скрытие info
do
  local s = m:section(SimpleSection)
  local dv = s:option(DummyValue, "_hidden"); dv.rawhtml = true
  function dv.cfgvalue()
    local function esc(x) return pcdata(x or "") end
    return string.format([[
<input type="hidden" name="tab" value="%s"/>
<input type="hidden" name="tpx_port_mode" value="%s"/>
<input type="hidden" name="tpx_src_mode" value="%s"/>
<input type="hidden" name="clash_file" value="%s"/>
<script>
(function(){
  window.__xray_dirty = false;
  document.addEventListener('input', function(e){
    var n = e && e.target && e.target.name;
    if (n === 'uniedit_text' || n === 'json_text' || n === 'clash_text') window.__xray_dirty = true;
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
      esc(fval("tab") or "tproxy"),
      esc(fval("tpx_port_mode")),
      esc(fval("tpx_src_mode")),
      esc(fval_last("clash_file") or "")
    )
  end
end

-- css (scoped to #cbi-tproxy_manager)
do
  local s = m:section(SimpleSection)
  local dv = s:option(DummyValue, "_css"); dv.rawhtml = true
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
#cbi-tproxy_manager .cbi-value[id*="_xray_stat"],
#cbi-tproxy_manager .cbi-value[id*="_xray_start"],
#cbi-tproxy_manager .cbi-value[id*="_xray_stop"],
#cbi-tproxy_manager .cbi-value[id*="_xray_enable"],
#cbi-tproxy_manager .cbi-value[id*="_xray_disable"],
#cbi-tproxy_manager .cbi-value[id*="_tproxy-manager_stat"],
#cbi-tproxy_manager .cbi-value[id*="_tproxy-manager_start"],
#cbi-tproxy_manager .cbi-value[id*="_tproxy-manager_stop"],
#cbi-tproxy_manager .cbi-value[id*="_tproxy-manager_enable"],
#cbi-tproxy_manager .cbi-value[id*="_tproxy-manager_disable"],
#cbi-tproxy_manager .cbi-value[id*="_clash_stat"],
#cbi-tproxy_manager .cbi-value[id*="_clash_start"],
#cbi-tproxy_manager .cbi-value[id*="_clash_stop"],
#cbi-tproxy_manager .cbi-value[id*="_clash_enable"],
#cbi-tproxy_manager .cbi-value[id*="_clash_disable"]{
  display:inline-block; vertical-align:middle; margin:0 2px 0 0; padding:0; border:0;
}
#cbi-tproxy_manager .cbi-value[id*="_xray_start"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id*="_xray_stop"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id*="_xray_enable"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id*="_xray_disable"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id*="_tproxy-manager_start"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id*="_tproxy-manager_stop"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id*="_tproxy-manager_enable"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id*="_tproxy-manager_disable"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id*="_clash_start"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id*="_clash_stop"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id*="_clash_enable"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id*="_clash_disable"] .cbi-value-title{display:none}

/* general boxes */
.box{padding:.5rem;border:1px solid #e5e7eb;border-radius:.5rem}

.editor-wrap{max-width:860px}
.editor-wrap textarea{width:100%!important;font-family:monospace}
.editor-wide{max-width:1200px}
.editor-680{max-width:100%}

/* hide titles for JSON area block */
#cbi-tproxy_manager .cbi-value[id$="_json_area"] .cbi-value-title{display:none!important}
#cbi-tproxy_manager .cbi-value[id$="_json_area"] .cbi-value-field{margin-left:0!important;width:auto!important;max-width:none!important;display:block!important}
#cbi-tproxy_manager .cbi-value[id$="_json_area"] .json-editor{width:680px; max-width:100%}
#cbi-tproxy_manager .cbi-value[id$="_json_area"] .json-editor textarea{width:100%!important; font-family:monospace}

/* small inline action buttons */
#cbi-tproxy_manager .cbi-value[id$="_refreshlog"],
#cbi-tproxy_manager .cbi-value[id$="_clearlog"],
#cbi-tproxy_manager .cbi-value[id$="_savejson"],
#cbi-tproxy_manager .cbi-value[id$="_test"],
#cbi-tproxy_manager .cbi-value[id$="_clearlog_json"],
#cbi-tproxy_manager .cbi-value[id$="_refreshlog_clash"],
#cbi-tproxy_manager .cbi-value[id$="_clearlog_clash"],
#cbi-tproxy_manager .cbi-value[id$="_saveclash"],
#cbi-tproxy_manager .cbi-value[id$="_test_clash"],
#cbi-tproxy_manager .cbi-value[id$="_clearlog_clash_config"]{display:inline-block; margin:1px 4px; padding:0; border:0; vertical-align:middle;}
#cbi-tproxy_manager .cbi-value[id$="_refreshlog"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id$="_clearlog"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id$="_savejson"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id$="_test"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id$="_clearlog_json"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id$="_refreshlog_clash"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id$="_clearlog_clash"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id$="_saveclash"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id$="_test_clash"] .cbi-value-title,
#cbi-tproxy_manager .cbi-value[id$="_clearlog_clash_config"] .cbi-value-title{display:none}

.small-btn{padding:.25rem .55rem}
.inline-edit{display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;margin:.6rem 0}
.inline-edit input[type="text"]{width:28%;min-width:180px}
.inline-row{display:flex;align-items:center;gap:.25rem;flex-wrap:nowrap}
.btn-green{background:#16a34a!important;border-color:#16a34a!important;color:#fff!important;font-weight:700!important}

.tpx-two{display:flex;gap:.8rem;align-items:flex-start;flex-wrap:wrap}
.tpx-two .col{flex:1 1 360px;min-width:320px}

/* GEO tables */
table.geo-table{width:100%;border-collapse:collapse; table-layout:fixed; word-break:break-all}
table.geo-table th, table.geo-table td{border:1px solid #e5e7eb;padding:.35rem;text-align:left;vertical-align:top}
table.geo-table th{background:#f9fafb}
table.geo-table.geo-upd{ table-layout:auto }
table.geo-table.geo-upd col.col-idx{ width:auto }
table.geo-table.geo-upd th:first-child, table.geo-table.geo-upd td:first-child{ white-space:nowrap }

/* сообщения */
.msg{padding:.5rem .7rem;border-radius:.5rem;margin:.4rem 0;white-space:pre-wrap}
.msg.err{border:1px solid #fecaca;background:#fef2f2;color:#b91c1c}
.msg.info{border:1px solid #bbf7d0;background:#f0fdf4;color:#166534}

/* DHCP leases */
table.leases-table{ width:100%; border-collapse:collapse; table-layout:auto }
table.leases-table th, table.leases-table td{border:1px solid #e5e7eb; padding:.35rem; vertical-align:top}
table.leases-table th{background:#f9fafb}
table.leases-table col.col-ip  { width:12% }
table.leases-table col.col-host{ width:auto }
table.leases-table col.col-mac { width:14% }
table.leases-table col.col-act { width:14% }
table.leases-table td:nth-child(1),
table.leases-table td:nth-child(3),
table.leases-table td:nth-child(4),
table.leases-table th:nth-child(1),
table.leases-table th:nth-child(3),
table.leases-table th:nth-child(4){ white-space:nowrap }
</style>]] end
end

-- redirect to TPROXY tab by default (preserve token automatically via SimpleForm)
if not http.formvalue("tab") or http.formvalue("tab") == "" then
  http.redirect(disp.build_url("admin","network","tproxy_manager") .. "?tab=tproxy")
  return m
end

local cur_tab = fval("tab") or "tproxy"

-- Shared ctx for modules
local ctx = {
  PKG = PKG, BASE_DIR = BASE_DIR, XRAY_DIR = XRAY_DIR, CLASH_DIR = CLASH_DIR,
  XRAY_BIN = XRAY_BIN, CLASH_BIN = CLASH_BIN,
  LOG_TEST = LOG_TEST, CLASH_TEST_LOG = CLASH_TEST_LOG,
  m = m, uci = uci, http = http, sys = sys, fs = fs, disp = disp, jsonc = jsonc, xml = xml,
  pcdata = pcdata, fval = fval, fval_last = fval_last, pick_form_or_uci = pick_form_or_uci,
  self_url = self_url, redirect_here = redirect_here, combined_log = combined_log,
  service_block = service_block, set_err = set_err, get_err = get_err, set_info = set_info, get_info = get_info,
  write_file = write_file, read_file = read_file, write_json_file = write_json_file, strip_json_comments = strip_json_comments,
  is_port = is_port, append_line_unique = append_line_unique, netm_init = netm_init,
}

-- Load module based on tab
if cur_tab == "tproxy" then
  require("luci.model.cbi.tproxy_manager.modules.tproxy").render(ctx)
elseif cur_tab == "xray" then
  require("luci.model.cbi.tproxy_manager.modules.xray").render(ctx)
elseif cur_tab == "clash" then
  require("luci.model.cbi.tproxy_manager.modules.clash").render(ctx)
elseif cur_tab == "updates" then
  require("luci.model.cbi.tproxy_manager.modules.updates").render(ctx)
end

return m