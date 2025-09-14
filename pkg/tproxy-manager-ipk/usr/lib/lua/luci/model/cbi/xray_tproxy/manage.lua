-- /usr/lib/lua/luci/model/cbi/xray_tproxy/manage.lua
local fs    = require "nixio.fs"
local sys   = require "luci.sys"
local jsonc = require "luci.jsonc"
local http  = require "luci.http"
local disp  = require "luci.dispatcher"
local xml   = require "luci.xml"
local ucim  = require "luci.model.uci"
local uci   = ucim.cursor()

-- Aliases
local pcdata     = xml.pcdata
local formvalue  = http.formvalue

-- UCI package and paths
local PKG      = "xray-proxy"
local XRAY_DIR = "/etc/xray"
local LOG_TEST = "/tmp/xray_test.log"

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
local ERR_F   = "/tmp/xray_tproxy_last_error"
local INF_F   = "/tmp/xray_tproxy_last_info"
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
  local url = disp.build_url("admin","network","xray_tproxy")
  local qp = {}
  if opts.tab and #opts.tab>0 then qp[#qp+1] = "tab="..urlencode(opts.tab) end
  if opts.list_file and #opts.list_file>0 then qp[#qp+1] = "list_file="..urlencode(opts.list_file) end
  if opts.json_file and #opts.json_file>0 then qp[#qp+1] = "json_file="..urlencode(opts.json_file) end
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
    port_mode = fval("tpx_port_mode"),
    src_mode  = fval("tpx_src_mode"),
  }))
end

-- ensure dir
do
  local st = fs.stat(XRAY_DIR); if not (st and st.type == "directory") then fs.mkdir(XRAY_DIR) end
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
  ensure("nft_table", "xray")
  ensure("ifaces", "br-lan")
  ensure("ipv6_enabled", "1")
  ensure("tproxy_port", "61219")
  ensure("fwmark_tcp", "0x1")
  ensure("fwmark_udp", "0x2")
  ensure("rttab_tcp", "100")
  ensure("rttab_udp", "101")
  ensure("port_mode", "bypass")
  ensure("ports_file", "/etc/xray/xray-tproxy.ports")
  ensure("bypass_v4_file", "/etc/xray/xray-tproxy.v4")
  ensure("bypass_v6_file", "/etc/xray/xray-tproxy.v6")
  ensure("src_mode", "off")
  ensure("src_only_v4_file",  "/etc/xray/xray-tproxy.src4.only")
  ensure("src_only_v6_file",  "/etc/xray/xray-tproxy.src6.only")
  ensure("src_bypass_v4_file","/etc/xray/xray-tproxy.src4.bypass")
  ensure("src_bypass_v6_file","/etc/xray/xray-tproxy.src6.bypass")
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

-- ---------- form ----------
local m = SimpleForm("xray_tproxy", "TPROXY Manager",
  "Редактирование конфигов Xray и настроек TPROXY, просмотр статусов и перезапуск сервисов.")
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
        port_mode=fval("tpx_port_mode"),
        src_mode=fval("tpx_src_mode")
      })
      local cls = (cur==id) and "class='cbi-button cbi-button-apply'" or "class='cbi-button cbi-button-action'"
      return string.format("<a %s style='margin-right:.4rem' href='%s'>%s</a>", cls, url, pcdata(title))
    end
    return "<div style='margin:.2rem 0 .2rem 0'>" ..
      link("tproxy", "TPROXY") ..
      link("xray", "XRAY") ..
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
<script>
(function(){
  window.__xray_dirty = false;
  document.addEventListener('input', function(e){
    var n = e && e.target && e.target.name;
    if (n === 'uniedit_text' || n === 'json_text') window.__xray_dirty = true;
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
      esc(fval("tpx_src_mode"))
    )
  end
end

-- css
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
#cbi-xray_tproxy .cbi-value[id*="_xray_stat"],
#cbi-xray_tproxy .cbi-value[id*="_xray_start"],
#cbi-xray_tproxy .cbi-value[id*="_xray_stop"],
#cbi-xray_tproxy .cbi-value[id*="_xray_enable"],
#cbi-xray_tproxy .cbi-value[id*="_xray_disable"],
#cbi-xray_tproxy .cbi-value[id*="_xray-tproxy_stat"],
#cbi-xray_tproxy .cbi-value[id*="_xray-tproxy_start"],
#cbi-xray_tproxy .cbi-value[id*="_xray-tproxy_stop"],
#cbi-xray_tproxy .cbi-value[id*="_xray-tproxy_enable"],
#cbi-xray_tproxy .cbi-value[id*="_xray-tproxy_disable"]{
  display:inline-block; vertical-align:middle; margin:0 2px 0 0; padding:0; border:0;
}
#cbi-xray_tproxy .cbi-value[id*="_xray_start"] .cbi-value-title,
#cbi-xray_tproxy .cbi-value[id*="_xray_stop"] .cbi-value-title,
#cbi-xray_tproxy .cbi-value[id*="_xray_enable"] .cbi-value-title,
#cbi-xray_tproxy .cbi-value[id*="_xray_disable"] .cbi-value-title,
#cbi-xray_tproxy .cbi-value[id*="_xray-tproxy_start"] .cbi-value-title,
#cbi-xray_tproxy .cbi-value[id*="_xray-tproxy_stop"] .cbi-value-title,
#cbi-xray_tproxy .cbi-value[id*="_xray-tproxy_enable"] .cbi-value-title,
#cbi-xray_tproxy .cbi-value[id*="_xray-tproxy_disable"] .cbi-value-title{display:none}

/* general boxes */
.box{padding:.5rem;border:1px solid #e5e7eb;border-radius:.5rem}

.editor-wrap{max-width:860px}
.editor-wrap textarea{width:100%!important;font-family:monospace}
.editor-wide{max-width:1200px}
.editor-680{max-width:100%}

/* hide titles for JSON area block */
#cbi-xray_tproxy .cbi-value[id$="_json_area"] .cbi-value-title{display:none!important}
#cbi-xray_tproxy .cbi-value[id$="_json_area"] .cbi-value-field{margin-left:0!important;width:auto!important;max-width:none!important;display:block!important}
#cbi-xray_tproxy .cbi-value[id$="_json_area"] .json-editor{width:680px; max-width:100%}
#cbi-xray_tproxy .cbi-value[id$="_json_area"] .json-editor textarea{width:100%!important; font-family:monospace}

/* small inline action buttons */
#cbi-xray_tproxy .cbi-value[id$="_refreshlog"],
#cbi-xray_tproxy .cbi-value[id$="_clearlog"],
#cbi-xray_tproxy .cbi-value[id$="_savejson"],
#cbi-xray_tproxy .cbi-value[id$="_test"],
#cbi-xray_tproxy .cbi-value[id$="_clearlog_json"]{display:inline-block; margin:1px 4px; padding:0; border:0; vertical-align:middle;}
#cbi-xray_tproxy .cbi-value[id$="_refreshlog"] .cbi-value-title,
#cbi-xray_tproxy .cbi-value[id$="_clearlog"] .cbi-value-title,
#cbi-xray_tproxy .cbi-value[id$="_savejson"] .cbi-value-title,
#cbi-xray_tproxy .cbi-value[id$="_test"] .cbi-value-title,
#cbi-xray_tproxy .cbi-value[id$="_clearlog_json"] .cbi-value-title{display:none}

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

-- redirect to TPROXY tab by default
if not http.formvalue("tab") or http.formvalue("tab") == "" then
  http.redirect(disp.build_url("admin","network","xray_tproxy") .. "?tab=tproxy")
  return m
end

local cur_tab = fval("tab") or "tproxy"

-- =====================================================================
-- =============================== TPROXY ===============================
-- =====================================================================
if cur_tab == "tproxy" then
  do
    local ss = m:section(SimpleSection, "Статус и управление сервисом TPROXY")
    service_block(ss, "xray-tproxy", "TPROXY", "tproxy")
  end

  local main_s = m:section(SimpleSection, "TPROXY — основные настройки")

  -- Interfaces (left col)
  do
    local dv = main_s:option(DummyValue, "_ifaces"); dv.rawhtml = true
    function dv.cfgvalue()
      local current = (uci:get(PKG,"main","ifaces") or ""):gsub(","," "):gsub("%s+"," ")
      local set = {}; for w in current:gmatch("(%S+)") do set[w]=true end

      local exclude = {}
      uci:foreach("firewall", "zone", function(s)
        if (s.name == "wwan") then
          local secname = s[".name"]
          local nets = uci:get_list("firewall", secname, "network") or {}
          local devs = uci:get_list("firewall", secname, "device") or {}
          for _, d in ipairs(devs) do exclude[d] = true end
          local nm = netm_init
          if nm then
            for _, n in ipairs(nets) do
              local iface = nm:get_interface(n)
              if iface then
                if iface.get_device then
                  local d = iface:get_device()
                  if d and d.name then exclude[d:name()] = true end
                end
                if iface.get_devices then
                  local ds = iface:get_devices()
                  if ds then
                    for _, dv in ipairs(ds) do
                      if dv and dv.name then exclude[dv:name()] = true end
                    end
                  end
                end
                if iface.ifname then
                  local ifn = iface:ifname()
                  if ifn then exclude[ifn] = true end
                end
              end
            end
          end
        end
      end)

      local ipv6 = uci:get(PKG,"main","ipv6_enabled") or ""
      local buf = {}
      buf[#buf+1] = string.format(
        "<div class='box'><div style='display:flex;align-items:center;gap:.6rem;margin-bottom:.4rem'>"
          .. "<label style='margin-right:.8rem'><input type='checkbox' name='tpx_ipv6_enabled' value='1' %s/> IPv6</label>"
          .. "<strong>Интерфейсы</strong></div>",
        (ipv6=="1") and "checked" or ""
      )

      for _,d in ipairs((sys.net and sys.net.devices and sys.net.devices()) or {}) do
        if d ~= "lo" and not d:match("^wwan") and not exclude[d] then
          local chk = set[d] and "checked" or ""
          buf[#buf+1] = string.format(
            '<label style="display:inline-block;margin-right:.5rem"><input type="checkbox" name="tpx_if_%s" value="1" %s/> %s</label>',
            pcdata(d), chk, pcdata(d)
          )
        end
      end
      buf[#buf+1] = "</div>"
      local out = {}
      out[#out+1] = "<div class='tpx-two'><div class='col'>"
      out[#out+1] = table.concat(buf)
      out[#out+1] = "</div>"
      return table.concat(out)
    end
  end

  -- Ports (right col)
  do
    local dv = main_s:option(DummyValue, "_ports"); dv.rawhtml = true
    function dv.cfgvalue()
      local u_p_all = uci:get(PKG,"main","tproxy_port") or ""
      local u_p_tcp = uci:get(PKG,"main","tproxy_port_tcp") or ""
      local u_p_udp = uci:get(PKG,"main","tproxy_port_udp") or ""
      local f_p_all = http.formvalue("tpx_port") or ""
      local f_p_tcp = http.formvalue("tpx_port_tcp") or ""
      local f_p_udp = http.formvalue("tpx_port_udp") or ""
      local f_split = http.formvalue("tpx_split") ~= nil

      local p_all = (f_p_all ~= "" and f_p_all) or u_p_all
      local p_tcp = (f_p_tcp ~= "" and f_p_tcp) or u_p_tcp
      local p_udp = (f_p_udp ~= "" and f_p_udp) or u_p_udp

      local uci_split = (u_p_tcp ~= "" or u_p_udp ~= "") and not (u_p_tcp == u_p_all and u_p_udp == u_p_all)
      local split_on = f_split or uci_split

      local eff_tcp = (p_tcp ~= "" and p_tcp or p_all)
      local eff_udp = (p_udp ~= "" and p_udp or p_all)

      local right = ([[<div class="box">
        <div class="inline-row"><label><input type="checkbox" id="tpx_split" name="tpx_split" value="1" %s/> Разделить TCP/UDP</label></div>
        <div id="p_all_row" style="margin-top:.25rem"><label>Порт:</label>
          <input type="number" id="tpx_port" name="tpx_port" value="%s" min="1" max="65535" step="1" style="width:120px">
        </div>
        <div id="p_tcp_row" style="display:none;margin-top:.25rem"><label>Порт TCP:</label>
          <input type="number" id="tpx_port_tcp" name="tpx_port_tcp" value="%s" min="1" max="65535" step="1" style="width:120px">
        </div>
        <div id="p_udp_row" style="display:none;margin-top:.25rem"><label>Порт UDP:</label>
          <input type="number" id="tpx_port_udp" name="tpx_port_udp" value="%s" min="1" max="65535" step="1" style="width:120px">
        </div>
        <script>
          (function(){
            var form = document.querySelector('form'); if(form){ form.setAttribute('novalidate','novalidate'); }
            var split=document.getElementById('tpx_split');
            var allr=document.getElementById('p_all_row'), t=document.getElementById('p_tcp_row'), u=document.getElementById('p_udp_row');
            var ipAll=document.getElementById('tpx_port'), ipT=document.getElementById('tpx_port_tcp'), ipU=document.getElementById('tpx_port_udp');
            function upd(){
              var on = split && split.checked;
              allr.style.display = on ? 'none' : 'block';
              t.style.display = on ? 'block' : 'none';
              u.style.display = on ? 'block' : 'none';
              if(on){
                ipAll.disabled = true; ipAll.required = false;
                ipT.disabled = false;  ipU.disabled = false;
                ipT.required = true;   ipU.required = true;
              }else{
                ipAll.disabled = false; ipAll.required = true;
                ipT.disabled = true;    ipU.disabled = true;
                ipT.required = false;   ipU.required = false;
                ipT.value=''; ipU.value='';
              }
            }
            if(split){ split.addEventListener('change',function(){
              if (window.__xray_dirty && !confirm('Есть несохранённые изменения. Перейти без сохранения?')) { split.checked = !split.checked; return; }
              upd();
            }); }
            upd();
          })();
        </script>
      </div>]]):format(
        split_on and "checked" or "",
        pcdata(p_all), pcdata(eff_tcp), pcdata(eff_udp)
      )
      return "<div class='col'>" .. right .. "</div></div>"
    end
  end

  -- Modes
  do
    local dv = main_s:option(DummyValue, "_modes"); dv.rawhtml = true
    function dv.cfgvalue()
      local pm = pick_form_or_uci(fval("tpx_port_mode"), uci:get(PKG,"main","port_mode"))
      local sm = pick_form_or_uci(fval("tpx_src_mode"),  uci:get(PKG,"main","src_mode"))
      local function opt(val, cur, title)
        return string.format('<option value="%s"%s>%s</option>', val, (val==cur) and " selected" or "", title)
      end
      return ([[<div class="box">
        <div class="inline-row"><label>Режим по портам:</label>
          <select name="tpx_port_mode">%s%s</select>
        </div>
        <div class="inline-row" style="margin-top:.25rem"><label>Режим по источникам:</label>
          <select id="tpx_src_mode" name="tpx_src_mode">%s%s%s</select>
        </div>
        <script>
        (function(){
          function qs(s){ return document.querySelector(s) }
          function buildUrl(){
            var base = ']].. pcdata(disp.build_url("admin","network","xray_tproxy").."?tab=tproxy") ..[[';
            var pm = (qs('select[name="tpx_port_mode"]')||{}).value || '';
            var sm = (qs('#tpx_src_mode')||{}).value || '';
            var lf = (qs('#unified-editor select[name="list_file"]')||{}).value || '';
            var jf = (qs('#json-editor select[name="json_file"]')||{}).value || '';
            var url = base + '&tpx_port_mode=' + encodeURIComponent(pm) + '&tpx_src_mode=' + encodeURIComponent(sm);
            if (lf) url += '&list_file=' + encodeURIComponent(lf);
            if (jf) url += '&json_file=' + encodeURIComponent(jf);
            return url;
          }
          var pmSelect = qs('select[name="tpx_port_mode"]');
          var smSelect = qs('#tpx_src_mode');
          function go(){ if (!window.__xray_guard || window.__xray_guard()) location.href = buildUrl(); }
          if (pmSelect) pmSelect.addEventListener('change', go);
          if (smSelect) pmSelect && smSelect.addEventListener('change', go);
        })();
        </script>
      </div>]]):format(
        opt("bypass",pm,"bypass"),
        opt("only",pm,"only"),
        opt("off",sm,"off"),
        opt("only",sm,"only"),
        opt("bypass",sm,"bypass")
      )
    end
  end

  -- Unified editor + DHCP picker
  do
    local se = m:section(SimpleSection, "")
    local dv = se:option(DummyValue, "_uniedit"); dv.rawhtml = true
    function dv.cfgvalue()
      local function getu(k) return uci:get(PKG,"main",k) or "" end

      local pmode_form = fval("tpx_port_mode")
      local smode      = pick_form_or_uci(fval("tpx_src_mode"),  uci:get(PKG,"main","src_mode"))
      local pmode      = pick_form_or_uci(pmode_form, uci:get(PKG,"main","port_mode"))

      local ports = getu("ports_file")
      local bv4   = getu("bypass_v4_file")
      local bv6   = getu("bypass_v6_file")
      local so4   = getu("src_only_v4_file")
      local so6   = getu("src_only_v6_file")
      local sb4   = getu("src_bypass_v4_file")
      local sb6   = getu("src_bypass_v6_file")

      local options = {}
      if ports ~= "" then options[#options+1] = {ports, "Порты ("..((pmode and pmode~="") and pmode or "?")..")", "none"} end
      if bv4   ~= "" then options[#options+1] = {bv4,   "bypass IPv4", "none"} end
      if bv6   ~= "" then options[#options+1] = {bv6,   "bypass IPv6", "none"} end
      if so4   ~= "" then options[#options+1] = {so4,   "src only IPv4", "only"} end
      if so6   ~= "" then options[#options+1] = {so6,   "src only IPv6", "only"} end
      if sb4   ~= "" then options[#options+1] = {sb4,   "src bypass IPv4", "bypass"} end
      if sb6   ~= "" then options[#options+1] = {sb6,   "src bypass IPv6", "bypass"} end

      if #options == 0 then
        return "<div class='box editor-wrap' style='color:#6b7280'>В UCI ("..PKG..") не заданы пути файлов списков. Укажите пути в «Дополнительных настройках».</div>"
      end

      local chosen = fval("list_file")
      local found=false; for _,o in ipairs(options) do if o[1]==chosen then found=true end end
      if not found then chosen = options[1][1] end

      local function visible_for_mode(kind, sm)
        if kind=="none" then return true end
        if sm=="only"  and kind=="only"  then return true end
        if sm=="bypass" and kind=="bypass" then return true end
        return false
      end
      local chosen_kind = "none"
      for _,o in ipairs(options) do if o[1]==chosen then chosen_kind=o[3] end end
      if not visible_for_mode(chosen_kind, smode) then
        for _,o in ipairs(options) do if visible_for_mode(o[3], smode) then chosen = o[1]; break end end
      end

      local content = read_file(chosen)

      local desc = ""
      if chosen == ports then
        if     pmode == "bypass" then desc = "Трафик на перечисленные порты идёт напрямую (остальные через прокси)."
        elseif pmode == "only"   then desc = "Трафик на перечисленные порты идёт через прокси (остальные напрямую)."
        else desc = "Файл с портами; текущий режим по портам в UCI не задан." end
      elseif chosen == bv4 then desc = "IPv4 адреса/сети, которые не будут проксироваться."
      elseif chosen == bv6 then desc = "IPv6 адреса/сети, которые не будут проксироваться."
      elseif chosen == so4 then desc = "IPv4 источники, которые будут идти через прокси."
      elseif chosen == so6 then desc = "IPv6 источники, которые будут идти через прокси."
      elseif chosen == sb4 then desc = "IPv4 источники, которые будут идти напрямую."
      elseif chosen == sb6 then desc = "IPv6 источники, которые будут идти напрямую." end

      local sel = {}
      sel[#sel+1] = "<div id='unified-editor' class='editor-wrap editor-wide'>"
      sel[#sel+1] = "<div class='inline-row'><label>Файл для редактирования:</label><select name='list_file'>"
      for _,o in ipairs(options) do
        local path, label, kind = o[1], o[2], o[3]
        local selattr = (path == chosen) and " selected" or ""
        local show = (kind=='none') or (smode=='only' and kind=='only') or (smode=='bypass' and kind=='bypass')
        local style = show and "" or " style=\"display:none\""
        sel[#sel+1] = string.format("<option value=\"%s\" data-src-kind=\"%s\"%s%s>%s — %s</option>",
          pcdata(path), pcdata(kind), selattr, style, pcdata(path), pcdata(label))
      end
      sel[#sel+1] = "</select><button class=\"cbi-button cbi-button-apply small-btn\" name=\"_uniedit_save\" value=\"1\">Сохранить файл</button></div>"
      sel[#sel+1] = "<div style='margin:.2rem 0 .5rem 0; color:#6b7280'>" .. pcdata(desc) .. "</div>"

      sel[#sel+1] = string.format("<textarea name='uniedit_text' rows='16' spellcheck='false'>%s</textarea>", pcdata(content))

      sel[#sel+1] = [[
<div id="uniedit_hint" style="margin-top:.35rem; color:#9ca3af"></div>
<script>
(function(){
  function qs(s){ return document.querySelector(s) }
  var ta = qs('textarea[name="uniedit_text"]');
  var fileSel = qs('#unified-editor select[name="list_file"]');
  var hint = qs('#uniedit_hint');
  var key = 'uniedit:' + (fileSel ? fileSel.value : '');

  function isIPv4(s){
    var m = s.match(/^(\d{1,3})(?:\.(\d{1,3})){3}$/); if(!m) return false;
    return s.split('.').every(function(n){ n=+n; return n>=0 && n<=255; });
  }
  function isIPv4CIDR(s){
    var m = s.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d|[1-2]\d|3[0-2])$/);
    return !!(m && isIPv4(m[1]));
  }
  function isIPv6(s){ return /:/.test(s); }
  function isIPv6CIDR(s){ return /:/.test(s) && /\/(\d|[1-9]\d|1[01]\d|12[0-8])$/.test(s); }

  function validate(){
    if(!ta||!hint) return;
    var bad = [];
    var lines = ta.value.split(/\r?\n/);
    for(var i=0;i<lines.length;i++){
      var ln = lines[i].trim();
      if(!ln || ln[0]=='#' || ln[0]==';') continue;
      var ok = isIPv4(ln) || isIPv4CIDR(ln) || isIPv6(ln) || isIPv6CIDR(ln);
      if(!ok) bad.push((i+1)+': '+ln);
    }
    if(bad.length){
      hint.style.color = '#b45309';
      hint.innerHTML = 'Подозрительные строки ('+bad.length+'):<br><code style="white-space:pre-wrap">'+bad.slice(0,10).join('\n')+(bad.length>10?'\n…':'' )+'</code>';
      ta.style.outline = '2px solid #f59e0b';
    }else{
      hint.style.color = '#9ca3af';
      hint.textContent = 'Похоже корректно: IPv4/IPv6 (возможен CIDR). Строки с #/; игнорируются.';
      ta.style.outline = '';
    }
  }

  function savePos(){
    try{
      var st = { scroll: ta.scrollTop, selStart: ta.selectionStart||0, selEnd: ta.selectionEnd||0 };
      localStorage.setItem(key, JSON.stringify(st));
    }catch(e){}
  }
  function restorePos(){
    try{
      var st = JSON.parse(localStorage.getItem(key)||'{}');
      if(typeof st.scroll === 'number') ta.scrollTop = st.scroll;
      if(typeof st.selStart === 'number' && typeof st.selEnd === 'number'){
        ta.selectionStart = st.selStart; ta.selectionEnd = st.selEnd;
      }
    }catch(e){}
  }

  if(ta){
    restorePos();
    ta.addEventListener('input', function(){ window.__xray_dirty = true; validate(); savePos(); });
    ta.addEventListener('scroll', savePos);
    ta.addEventListener('keyup', savePos);
    validate();
  }

  var sel = document.querySelector('#unified-editor select[name="list_file"]');
  if (!sel) return;
  sel.addEventListener('change', function(){
    if (window.__xray_guard && !window.__xray_guard()) { this.value = this.getAttribute('data-prev') || this.value; return; }
    var base = ']] .. pcdata(disp.build_url("admin","network","xray_tproxy").."?tab=tproxy") .. [[';
    var pm = (document.querySelector('select[name="tpx_port_mode"]')||{}).value || '';
    var sm = (document.querySelector('#tpx_src_mode')||{}).value || '';
    var jf = (document.querySelector('#json-editor select[name="json_file"]')||{}).value || '';
    var url = base + '&tpx_port_mode=' + encodeURIComponent(pm) + '&tpx_src_mode=' + encodeURIComponent(sm);
    if (jf) url += '&json_file=' + encodeURIComponent(jf);
    url += '&list_file=' + encodeURIComponent(sel.value);
    location.href = url;
  });
  sel.setAttribute('data-prev', sel.value);
})();
</script>]]

      -- DHCP leases picker
      local leases = {}
      for line in (read_file("/tmp/dhcp.leases").."\n"):gmatch("([^\n]*)\n") do
        local ts, mac, ip, host = line:match("^(%d+)%s+(%S+)%s+(%S+)%s+(%S+)")
        if ip and ip:match("^%d+%.%d+%.%d+%.%d+$") then
          leases[#leases+1] = { ip = ip, mac = mac, host = (host and host ~= "*" and host) or "" }
        end
      end
      sel[#sel+1] = "<details style='margin-top:.6rem'><summary style='cursor:pointer;font-weight:600'>DHCP аренды (быстро добавить в src only/bypass v4)</summary>"
      sel[#sel+1] = "<div class='box' style='margin-top:.4rem'>"
      if #leases == 0 then
        sel[#sel+1] = "<div style='color:#6b7280'>Нет активных аренд.</div>"
      else
        sel[#sel+1] = "<table class='leases-table'><colgroup><col class='col-ip'><col class='col-host'><col class='col-mac'><col class='col-act'></colgroup><thead><tr><th>IP</th><th>Имя</th><th>MAC</th><th>Действия</th></tr></thead><tbody>"
        for _, r in ipairs(leases) do
          sel[#sel+1] = string.format(
            "<tr><td><code>%s</code></td><td>%s</td><td><code>%s</code></td>" ..
            "<td>" ..
            "<button class='cbi-button cbi-button-apply small-btn' name='_dhcp_add_only' value='%s'>+ only</button> " ..
            "<button class='cbi-button cbi-button-action small-btn' name='_dhcp_add_bypass' value='%s'>+ bypass</button>" ..
            "</td></tr>",
            pcdata(r.ip), pcdata(r.host or ""), pcdata(r.mac or ""), pcdata(r.ip), pcdata(r.ip)
          )
        end
        sel[#sel+1] = "</tbody></table>"
      end
      sel[#sel+1] = "</div></details>"

      sel[#sel+1] = "</div>"
      return table.concat(sel, "\n")
    end
  end

  -- Advanced
  do
    local dv = m:section(SimpleSection, "Дополнительные настройки (свернутая панель)"):option(DummyValue, "_advanced")
    dv.rawhtml = true
    function dv.cfgvalue()
      local function getu(k) return uci:get(PKG,"main",k) or "" end
      local nft = getu("nft_table")
      local fwt = getu("fwmark_tcp")
      local fwu = getu("fwmark_udp")
      local rtt = getu("rttab_tcp")
      local rtu = getu("rttab_udp")

      local ports_file   = getu("ports_file")
      local bypass_v4    = getu("bypass_v4_file")
      local bypass_v6    = getu("bypass_v6_file")
      local src_o4       = getu("src_only_v4_file")
      local src_o6       = getu("src_only_v6_file")
      local src_b4       = getu("src_bypass_v4_file")
      local src_b6       = getu("src_bypass_v6_file")
      local loge         = getu("log_enabled")

      return ([[<div id="adv-wrap"><details>
        <summary><strong>Развернуть/свернуть дополнительные параметры</strong></summary>
        <div style="display:grid;grid-template-columns:minmax(220px, 360px) 1fr;gap:.35rem .6rem;align-items:center">
          <label>Логирование</label><input type="checkbox" name="tpx_log_enabled" value="1" %s>

          <label>nft_table</label><input type="text" name="tpx_nft_table" value="%s">
          <label>fwmark_tcp</label><input type="text" name="tpx_fwmark_tcp" value="%s">
          <label>fwmark_udp</label><input type="text" name="tpx_fwmark_udp" value="%s">
          <label>rttab_tcp</label><input type="text" name="tpx_rttab_tcp" value="%s">
          <label>rttab_udp</label><input type="text" name="tpx_rttab_udp" value="%s">

          <label>ports_file</label><input type="text" name="tpx_ports_file" value="%s">
          <label>bypass_v4_file</label><input type="text" name="tpx_bypass_v4_file" value="%s">
          <label>bypass_v6_file</label><input type="text" name="tpx_bypass_v6_file" value="%s">

          <label>src_only_v4_file</label><input type="text" name="tpx_src_only_v4_file" value="%s">
          <label>src_only_v6_file</label><input type="text" name="tpx_src_only_v6_file" value="%s">
          <label>src_bypass_v4_file</label><input type="text" name="tpx_src_bypass_v4_file" value="%s">
          <label>src_bypass_v6_file</label><input type="text" name="tpx_src_bypass_v6_file" value="%s">
        </div>
      </details></div]]):format(
        (loge=="1") and "checked" or "",
        pcdata(nft), pcdata(fwt), pcdata(fwu), pcdata(rtt), pcdata(rtu),
        pcdata(ports_file), pcdata(bypass_v4), pcdata(bypass_v6),
        pcdata(src_o4), pcdata(src_o6), pcdata(src_b4), pcdata(src_b6)
      )
    end
  end

  -- Save handlers (TPROXY) + DHCP info + сообщения
  local function save_tproxy_main()
    -- DHCP quick add
    local ip_only  = http.formvalue("_dhcp_add_only")
    local ip_bypass= http.formvalue("_dhcp_add_bypass")
    if ip_only and ip_only ~= "" then
      local path = uci:get(PKG,"main","src_only_v4_file") or ""
      if path ~= "" then
        append_line_unique(path, ip_only)
        set_info(string.format("Добавлено %s → src_only_v4_file: %s", ip_only, path))
        set_err(nil)
      end
      redirect_here("tproxy"); return
    end
    if ip_bypass and ip_bypass ~= "" then
      local path = uci:get(PKG,"main","src_bypass_v4_file") or ""
      if path ~= "" then
        append_line_unique(path, ip_bypass)
        set_info(string.format("Добавлено %s → src_bypass_v4_file: %s", ip_bypass, path))
        set_err(nil)
      end
      redirect_here("tproxy"); return
    end

    local want_save = http.formvalue("_save_tproxy_main") == "1"

    if want_save then
      local split = http.formvalue("tpx_split") ~= nil
      if split then
        local pt = http.formvalue("tpx_port_tcp") or ""
        local pu = http.formvalue("tpx_port_udp") or ""
        if not (is_port(pt) and is_port(pu)) then
          set_err("Включен режим разделения TCP/UDP: требуется указать оба порта в диапазоне 1..65535.")
          return
        end
      else
        local p = http.formvalue("tpx_port") or ""
        if not is_port(p) then
          set_err("Нужно указать общий порт (1..65535).")
          return
        end
      end

      set_err(nil)

      uci:section(PKG,"main","main",{})
      uci:set(PKG,"main","log_enabled", http.formvalue("tpx_log_enabled") and "1" or "0")

      local selected = {}
      for _,d in ipairs((sys.net and sys.net.devices and sys.net.devices()) or {}) do
        if d ~= "lo" and not d:match("^wwan") and http.formvalue("tpx_if_"..d) then selected[#selected+1]=d end
      end
      if #selected > 0 then uci:set(PKG,"main","ifaces", table.concat(selected," ")) else uci:delete(PKG,"main","ifaces") end
      uci:set(PKG,"main","ipv6_enabled", http.formvalue("tpx_ipv6_enabled") and "1" or "0")

      if split then
        local pt = http.formvalue("tpx_port_tcp")
        local pu = http.formvalue("tpx_port_udp")
        uci:set(PKG,"main","tproxy_port_tcp", pt)
        uci:set(PKG,"main","tproxy_port_udp", pu)
        local p = http.formvalue("tpx_port")
        if p and p~="" then uci:set(PKG,"main","tproxy_port", p) end
      else
        local p = http.formvalue("tpx_port")
        uci:set(PKG,"main","tproxy_port", p)
        uci:delete(PKG,"main","tproxy_port_tcp")
        uci:delete(PKG,"main","tproxy_port_udp")
      end

      local pm = fval("tpx_port_mode")
      if pm == "bypass" or pm == "only" then uci:set(PKG,"main","port_mode", pm) else uci:delete(PKG,"main","port_mode") end

      local sm = fval("tpx_src_mode")
      if sm == "off" or sm == "only" or sm == "bypass" then uci:set(PKG,"main","src_mode", sm) else uci:delete(PKG,"main","src_mode") end

      local function S(k,v) if v and v~="" then uci:set(PKG,"main",k,v) else uci:delete(PKG,"main",k) end end
      S("nft_table", http.formvalue("tpx_nft_table"))
      S("fwmark_tcp", http.formvalue("tpx_fwmark_tcp"))
      S("fwmark_udp", http.formvalue("tpx_fwmark_udp"))
      S("rttab_tcp",  http.formvalue("tpx_rttab_tcp"))
      S("rttab_udp",  http.formvalue("tpx_rttab_udp"))
      S("ports_file",        http.formvalue("tpx_ports_file"))
      S("bypass_v4_file",    http.formvalue("tpx_bypass_v4_file"))
      S("bypass_v6_file",    http.formvalue("tpx_bypass_v6_file"))
      S("src_only_v4_file",  http.formvalue("tpx_src_only_v4_file"))
      S("src_only_v6_file",  http.formvalue("tpx_src_only_v6_file"))
      S("src_bypass_v4_file",http.formvalue("tpx_src_bypass_v4_file"))
      S("src_bypass_v6_file",http.formvalue("tpx_src_bypass_v6_file"))

      uci:commit(PKG)
      set_info("Настройки TPROXY сохранены")
    end

    if http.formvalue("_uniedit_save") == "1" then
      local path = fval_last("list_file")
      if path and path ~= "" then
        local text = http.formvalue("uniedit_text") or ""
        write_file(path, text)
        set_info("Файл списка сохранён: " .. path)
        set_err(nil)
      end
    end
  end
  save_tproxy_main()

  -- Save/Cancel row
  do
    local ss = m:section(SimpleSection)
    local dv = ss:option(DummyValue, "_savecancel_row"); dv.rawhtml = true
    function dv.cfgvalue()
      return [[
<div class="inline-row">
  <button class="cbi-button cbi-button-apply" name="_save_tproxy_main" value="1">Сохранить настройки TPROXY</button>
  <button class="cbi-button cbi-button-reset" name="_cancel_tproxy_main" value="1">Отменить изменения</button>
</div>]]
    end
    local b  = ss:option(Button, "_save_tproxy_main"); b.title=""; b.inputtitle="Save"; b.inputstyle="apply"
    function b.render() end
    function b.write(self, section)
      if not http.formvalue("_save_tproxy_main") then return end
      redirect_here("tproxy")
    end
    local cancel = ss:option(Button, "_cancel_tproxy_main"); cancel.title = ""; cancel.inputtitle = "Cancel"; cancel.inputstyle = "reset"
    function cancel.render() end
    function cancel.write(self, section)
      if not http.formvalue("_cancel_tproxy_main") then return end
      redirect_here("tproxy")
    end
  end

  -- Сообщения
  do
    local msg = m:section(SimpleSection); local dv = msg:option(DummyValue, "_tpx_msgs"); dv.rawhtml = true
    function dv.cfgvalue()
      local e = get_err(); local i = get_info()
      local out = {}
      if e ~= "" then out[#out+1] = "<div class='msg err'>"..pcdata(e).."</div>" end
      if i ~= "" then out[#out+1] = "<div class='msg info'>"..pcdata(i).."</div>" end
      if i ~= "" then set_info(nil) end
      return table.concat(out)
    end
  end

-- =====================================================================
-- ================================ XRAY ================================
-- =====================================================================
elseif cur_tab == "xray" then
  -- Toolbar handlers
  if http.formvalue("_refreshlog") then set_err(nil); redirect_here("xray"); return m end
  if http.formvalue("_clearlog") then
    sys.call("/etc/init.d/log restart >/dev/null 2>&1")
    set_err(nil)
    redirect_here("xray"); return m
  end
  if http.formvalue("_test") then
    sys.call(string.format("%s -test -format json -confdir %q >%s 2>&1", XRAY_BIN, XRAY_DIR, LOG_TEST))
    set_err(nil)
    redirect_here("xray"); return m
  end
  if http.formvalue("_clearlog_json") then
    write_file(LOG_TEST, "")
    set_err(nil)
    redirect_here("xray"); return m
  end

  -- Статус Xray (без «сохранить и перезапустить»)
  do
    local ss = m:section(SimpleSection, "Статус и управление сервисом Xray")
    service_block(ss, "xray", "Xray", "xray")
  end

  -- Combined log
  do
    local sl  = m:section(SimpleSection)
    local log = sl:option(DummyValue, "_log"); log.rawhtml = true
    function log.cfgvalue()
      return "<details><summary><strong>Общий лог (logread)</strong></summary>" ..
             "<div class='box editor-wrap'><pre style='white-space:pre-wrap;max-height:30rem;overflow:auto'>" ..
             pcdata(combined_log()) .. "</pre>" ..
             "<div style='margin-top:.5rem'><button class='cbi-button cbi-button-action small-btn' style='margin-right:4px; padding:0; border:0' name='_refreshlog' value='1'>Обновить</button> " ..
             "<button class='cbi-button cbi-button-remove small-btn' style='padding:0; border:0' name='_clearlog' value='1'>Очистить</button></div>" ..
             "</div></details>"
    end
    local rfr = sl:option(Button, "_refreshlog"); rfr.title = ""; rfr.inputtitle = "Refresh"
    rfr.inputstyle = "action"; function rfr.render() end
    function rfr.write(self, section) if not self.map:formvalue(self:cbid(section)) then return end; redirect_here("xray") end
    local clr = sl:option(Button, "_clearlog"); clr.title = ""; clr.inputtitle = "Clear log"
    clr.inputstyle = "remove"; function clr.render() end
    function clr.write(self, section) if not self.map:formvalue(self:cbid(section)) then return end; sys.call("/etc/init.d/log restart >/dev/null 2>&1"); redirect_here("xray") end
  end

  -- XRAY JSON editor (save-only)
  do
    local sx = m:section(SimpleSection, "Xray (JSON-файлы в /etc/xray)")
    local function list_json(dir)
      local t, it = {}, fs.dir(dir)
      if it then for name in it do if name:match("%.json$") then t[#t+1] = name end end end
      table.sort(t); return t
    end
    local json_files = list_json(XRAY_DIR)
    local chosen = fval("json_file")
    local found=false; for _,f in ipairs(json_files) do if f==chosen then found=true; break end end
    if not found then chosen = json_files[1] end

    -- create/delete
    if http.formvalue("_json_create") == "1" then
      local name = (http.formvalue("new_json_name") or ""):gsub("^%s+",""):gsub("%s+$","")
      if name ~= "" and not name:find("[/\\]") and name:match("%.json$") then
        local path = XRAY_DIR .. "/" .. name
        if not fs.access(path) then write_file(path, "{\n}\n") end
        set_err(nil)
        http.redirect(self_url({tab="xray", json_file=name, list_file=fval_last("list_file"), port_mode=fval("tpx_port_mode"), src_mode=fval("tpx_src_mode")}))
      else
        set_err("Некорректное имя файла. Требуется *.json без слэшей.")
        redirect_here("xray")
      end
      return m
    end

    if http.formvalue("_json_delete") == "1" then
      local jf = fval_last("json_file") or ""
      if jf ~= "" then fs.remove(XRAY_DIR .. "/" .. jf) end
      set_err(nil)
      redirect_here("xray"); return m
    end

    -- selector box
    do
      local url = disp.build_url("admin","network","xray_tproxy")
      local buf = {}
      buf[#buf+1] = "<div class='box editor-wrap editor-680' id='json-editor'>"
      buf[#buf+1] = [[
  <div class="inline-row" style="margin:.3rem 0;">
    <span>Новый файл:</span>
    <input type="text" name="new_json_name" placeholder="01_example.json" style="width:200px">
    <button class="cbi-button cbi-button-apply" name="_json_create" value="1">Создать</button>
  </div>
  <div style="color:#6b7280;margin-top:.2rem">Имя должно соответствовать шаблону <code>*.json</code>, без слэшей.</div>
  <hr style="border:none;border-top:1px solid #e5e7eb;margin:.5rem 0"/>]]
      buf[#buf+1] = "<label>Файл для редактирования</label>"
      buf[#buf+1] = "<select name='json_file'>"
      for _, f in ipairs(json_files) do
        local sel = (f==chosen) and " selected" or ""
        buf[#buf+1] = string.format("<option value=\"%s\"%s>%s</option>", pcdata(f), sel, pcdata(f))
      end
      buf[#buf+1] = "</select>"
      buf[#buf+1] = [[
<script>
(function(){
  function qs(s){ return document.querySelector(s) }
  var sel = document.querySelector('#json-editor select[name="json_file"]');
  if (!sel) return;
  sel.addEventListener('change', function(){
    if (window.__xray_guard && !window.__xray_guard()) { this.value = this.getAttribute('data-prev') || this.value; return; }
    var base = ']] .. pcdata(url) .. [[';
    var pm = (qs('select[name="tpx_port_mode"]')||{}).value || '';
    var sm = (qs('#tpx_src_mode')||{}).value || '';
    var lf = (qs('#unified-editor select[name="list_file"]')||{}).value || '';
    var target = base + "?tab=xray&tpx_port_mode="+encodeURIComponent(pm)+"&tpx_src_mode="+encodeURIComponent(sm)+"&list_file="+encodeURIComponent(lf)+"&json_file="+encodeURIComponent(sel.value);
    location.href = target;
  });
  sel.setAttribute('data-prev', sel.value);
})();
</script>]]
      buf[#buf+1] = [[
<button class="cbi-button cbi-button-remove" name="_json_delete" value="1"
  onclick="return confirm('Удалить выбранный файл?')">Удалить</button>]]
      buf[#buf+1] = "</div><div style='height:5px'></div>"
      local dvsel = sx:option(DummyValue, "_selector"); dvsel.rawhtml=true
      function dvsel.cfgvalue() return table.concat(buf) end
    end

    if chosen then
      local jedit = sx:option(DummyValue, "_json_area"); jedit.rawhtml = true
      function jedit.cfgvalue()
        local content = read_file(XRAY_DIR .. "/" .. chosen)
        return [[
<textarea name="json_text" rows="22" style="width:650px" spellcheck="false">]] .. pcdata(content) .. [[</textarea>
<div style="height:5px"></div>
<div class="box editor-wrap editor-680" id="json-status-box">
  <div id="json_status" style="margin:.08rem 0 .14rem 0; font-weight:600"></div>
</div>
<script>
(function(){
  function stripJsonComments(str){
    var out = '', i = 0, n = str.length, inStr = false, esc = false;
    while (i < n) {
      var c = str[i], d = str[i+1];
      if (inStr){ out+=c; if(esc){esc=false}else if(c==='\\'){esc=true}else if(c==='"'){inStr=false} i++; continue; }
      if (c==='"'){ inStr=true; out+=c; i++; continue; }
      if (c==='/' && d=== '/') { i+=2; while(i<n && str[i] !== '\n') i++; continue; }
      if (c==='/' && d==='*') { i+=2; while(i<n-1 && !(str[i]==='*' && str[i+1]==='/')) i++; i+=2; continue; }
      out+=c; i++;
    } return out;
  }
  var ta=document.querySelector('textarea[name="json_text"]'), badge=document.getElementById('json_status');
  function debounce(fn,ms){var t;return function(){clearTimeout(t);t=setTimeout(fn,ms)}}
  function validate(){ if(!ta||!badge)return; try{ JSON.parse(stripJsonComments(ta.value)); badge.textContent='JSONC валиден (комментарии разрешены)'; badge.style.color='#16a34a'; }catch(e){ badge.textContent='Ошибка JSON: '+e.message; badge.style.color='#dc2626'; } }
  if(ta){ ta.addEventListener('input', debounce(validate,250)); validate();

    var key = 'json:' + (document.querySelector('#json-editor select[name="json_file"]')||{}).value;
    try{
      var st = JSON.parse(localStorage.getItem(key)||'{}');
      if(typeof st.scroll === 'number') ta.scrollTop = st.scroll;
      if(typeof st.selStart === 'number' && typeof st.selEnd === 'number'){
        ta.selectionStart = st.selStart; ta.selectionEnd = st.selEnd;
      }
      function savePos(){
        try{ localStorage.setItem(key, JSON.stringify({scroll: ta.scrollTop, selStart: ta.selectionStart||0, selEnd: ta.selectionEnd||0})); }catch(e){}
      }
      ta.addEventListener('scroll', savePos);
      ta.addEventListener('keyup', savePos);
      ta.addEventListener('blur', savePos);
    }catch(e){}
  }
})();
</script>
]]
      end

      local bsave = sx:option(Button, "_savejson"); bsave.title = ""; bsave.inputtitle = "Сохранить"
      bsave.inputstyle = "apply"
      function bsave.write(self, section)
        if not self.map:formvalue(self:cbid(section)) then return end
        local new = http.formvalue("json_text") or ""
        local jf  = fval_last("json_file") or chosen
        local ok, err = write_json_file(XRAY_DIR .. "/" .. jf, new)
        if not ok then set_err(err or "save error")
        else set_err(nil); set_info("JSON сохранён: "..jf) end
        redirect_here("xray")
      end
    end

    local dout = sx:option(DummyValue, "_testout"); dout.rawhtml = true; dout.title = ""
    function dout.cfgvalue()
      local out = read_file(LOG_TEST)
      return "<details><summary>Результат последней проверки</summary>" ..
             "<div class='box editor-wrap editor-680'><pre style='white-space:pre-wrap'>" .. pcdata(out ~= "" and out or "(ещё не запускалось)") .. "</pre>" ..
             "<div style='margin-top:.5rem'><button class='cbi-button cbi-button-action small-btn' style='margin-right:4px; padding:0; border:0' name='_test' value='1'>Проверить конфигурацию</button> " ..
             "<button class='cbi-button cbi-button-remove small-btn' style='padding:0; border:0' name='_clearlog_json' value='1'>Очистить</button></div>" ..
             "</div></details>"
    end

    local btest = sx:option(Button, "_test"); btest.title = ""; btest.inputtitle = "Validate directory"
    btest.inputstyle = "action"; function btest.render() end
    function btest.write(self, section)
      if not self.map:formvalue(self:cbid(section)) then return end
      sys.call(string.format("%s -test -format json -confdir %q >%s 2>&1", XRAY_BIN, XRAY_DIR, LOG_TEST))
      redirect_here("xray")
    end

    local clrj = sx:option(Button, "_clearlog_json"); clrj.title = ""; clrj.inputtitle = "Clear log"
    clrj.inputstyle = "remove"; function clrj.render() end
    function clrj.write(self, section)
      if not self.map:formvalue(self:cbid(section)) then return end
      write_file(LOG_TEST, "")
      redirect_here("xray")
    end

    local msg = sx:option(DummyValue, "_xray_msgs"); msg.rawhtml = true; msg.title = ""
    function msg.cfgvalue()
      local e = get_err(); local i = get_info()
      local out = {}
      if e ~= "" then out[#out+1] = "<div class='msg err'>"..pcdata(e).."</div>" end
      if i ~= "" then out[#out+1] = "<div class='msg info'>"..pcdata(i).."</div>" end
      if i ~= "" then set_info(nil) end
      return table.concat(out)
    end
  end

-- =====================================================================
-- ============================== UPDATES ===============================
-- =====================================================================
elseif cur_tab == "updates" then
  local GEO_CFG       = XRAY_DIR .. "/geo-sources.conf"
  local GEO_SCRIPT    = "/usr/bin/xray-geo-update.sh"
  local CRON_FILE     = "/etc/crontabs/root"
  local CRON_TAG      = "# xray-geo-update"
  local SYSLOG_TAG    = "xray-geoip-update"

  local function mtime_str(path)
    local st = fs.stat(path)
    if not st or not st.mtime then return "(не найдено)" end
    local size = st.size or 0
    return os.date("%Y-%m-%d %H:%M:%S", st.mtime) .. string.format(" · %d bytes", size)
  end
  local function shellescape(s)
    if not s then return "''" end
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
      if dir and not fs.access(dir) then sys.call("mkdir -p " .. shellescape(dir)) end
      fs.rename(tmp, dest)
      log_sys(string.format("OK: %s -> %s", url or "", dest or ""))
    else
      fs.remove(tmp)
      log_sys(string.format("FAIL: %s", url or ""))
    end
    return ok
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

  local function load_geo_cfg()
    local raw = read_file(GEO_CFG)
    if raw == "" then return {} end
    local ok, data = pcall(jsonc.parse, strip_json_comments(raw))
    if not ok or type(data) ~= "table" then return {} end
    local out = {}
    for _, it in ipairs(data) do
      if type(it) == "table" and it.dest then
        out[#out+1] = { name=tostring(it.name or ""), url=tostring(it.url or ""), dest=tostring(it.dest) }
      end
    end
    return out
  end
  local function save_geo_cfg(rows)
    local text = jsonc.stringify(rows, true)
    return write_json_file(GEO_CFG, text)
  end

  local function write_geo_script(cfg_rows)
    local lines = {
      "#!/bin/sh",
      "# Autogenerated updater for Xray GEO files (list in " .. GEO_CFG .. ")",
      "set -e",
      "LOCK=\"/tmp/xray-geo-update.lock\"",
      "if command -v flock >/dev/null 2>&1; then",
      "  exec 9>\"$LOCK\"",
      "  if ! flock -n 9; then logger -t " .. SYSLOG_TAG .. " \"SKIP: already running\"; exit 0; fi",
      "else",
      "  ( set -o noclobber; : >\"$LOCK\" ) 2>/dev/null || { logger -t " .. SYSLOG_TAG .. " \"SKIP: already running\"; exit 0; }",
      "  trap 'rm -f \"$LOCK\"' EXIT INT TERM",
      "fi",
      "logger -t " .. SYSLOG_TAG .. " \"starting update\""
    }
    for _, r in ipairs(cfg_rows) do
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
    sys.call(string.format("chmod +x %s", "'"..GEO_SCRIPT.."'" ))
    return true
  end

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

  local cfg = load_geo_cfg()
  local edit_idx = tonumber(http.formvalue("_geo_edit_idx") or http.formvalue("_geo_edit") or "")

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

  do
    local sec = m:section(SimpleSection)
    local dv = sec:option(DummyValue, "_geo_edit_json"); dv.rawhtml = true
    local raw = read_file(GEO_CFG); if raw == "" then raw = "[]" end
    function dv.cfgvalue()
      return [[
<details>
  <summary style="cursor:pointer;font-weight:600">Общий список источников (JSON) — развернуть/свернуть</summary>
  <div class="box editor-wrap editor-wide" style="margin-top:.5rem">
    <textarea name="geo_sources" rows="12" spellcheck="false">]] .. pcdata(raw) .. [[</textarea>
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

  do
    local function load_geo_cfg2()
      local raw = read_file(GEO_CFG)
      if raw == "" then return {} end
      local ok, data = pcall(jsonc.parse, strip_json_comments(raw))
      if not ok or type(data) ~= "table" then return {} end
      local out = {}
      for _, it in ipairs(data) do
        if type(it) == "table" and it.dest then
          out[#out+1] = { name=tostring(it.name or ""), url=tostring(it.url or ""), dest=tostring(it.dest) }
        end
      end
      return out
    end

    if http.formvalue("_geo_add") == "1" then
      local rows = load_geo_cfg2()
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
      redirect_here("updates")
    end

    if http.formvalue("_geo_update_one") then
      local idx = tonumber(http.formvalue("_geo_update_one"))
      local rows = load_geo_cfg2()
      local r = (idx and rows[idx]) and rows[idx] or nil
      if r and r.url ~= "" and r.dest ~= "" then
        local ok = fetch_to(r.url, r.dest)
        set_info(ok and ("Обновлено: "..(r.name or r.dest)) or ("Ошибка обновления: "..(r.name or r.dest)))
        set_err(nil)
      end
      redirect_here("updates")
    end

    if http.formvalue("_geo_update_all") == "1" then
      local rows = load_geo_cfg2()
      local ok_count, total = 0, 0
      for _, r in ipairs(rows) do
        if r.url ~= "" and r.dest ~= "" then total = total + 1; if fetch_to(r.url, r.dest) then ok_count = ok_count + 1 end end
      end
      set_info(string.format("Обновлено %d из %d источников", ok_count, total)); set_err(nil)
      redirect_here("updates")
    end

    if http.formvalue("_geo_edit") then
      local idx = tonumber(http.formvalue("_geo_edit"))
      if idx then
        http.redirect(self_url({tab="updates",list_file=fval_last("list_file"),json_file=fval_last("json_file")}) .. "&_geo_edit_idx=" .. idx)
        return m
      end
    end

    if http.formvalue("_geo_apply_edit") == "1" then
      local idx = tonumber(http.formvalue("_geo_edit_idx") or "")
      local rows = load_geo_cfg2()
      if idx and rows[idx] then
        local dest = (http.formvalue("edit_dest") or ""):gsub("^%s+",""):gsub("%s+$","")
        if dest == "" then
          set_err("Нужно указать путь назначения (dest)."); set_info(nil)
          http.redirect(self_url({tab="updates",list_file=fval_last("list_file"),json_file=fval_last("json_file")}) .. "&_geo_edit_idx=" .. idx)
          return m
        end
        rows[idx].name = (http.formvalue("edit_name") or "")
        rows[idx].url  = (http.formvalue("edit_url")  or "")
        rows[idx].dest = dest
        save_geo_cfg(rows)
        set_err(nil); set_info("Источник обновлён: "..(rows[idx].name or rows[idx].dest))
      end
      redirect_here("updates")
      return m
    end

    if http.formvalue("_geo_cancel_edit") == "1" then
      redirect_here("updates")
    end

    if http.formvalue("_geo_delete") then
      local idx = tonumber(http.formvalue("_geo_delete"))
      local rows = load_geo_cfg2()
      if idx and rows[idx] then
        local name = rows[idx].name or rows[idx].dest
        table.remove(rows, idx); save_geo_cfg(rows); write_geo_script(rows)
        set_info("Удалён источник: "..(name or ("#"..tostring(idx)))); set_err(nil)
      end
      redirect_here("updates")
    end

    if http.formvalue("_geo_save") == "1" then
      local raw = http.formvalue("geo_sources") or "[]"
      local ok, tbl = pcall(jsonc.parse, strip_json_comments(raw))
      if ok and type(tbl) == "table" then
        local rows = {}
        for _, it in ipairs(tbl) do
          if type(it)=="table" and it.dest then
            rows[#rows+1] = { name=tostring(it.name or ""), url=tostring(it.url or ""), dest=tostring(it.dest) }
          end
        end
        save_geo_cfg(rows)
        write_geo_script(rows)
        set_err(nil); set_info("Список источников сохранён")
      else
        set_err("Некорректный JSON списка источников."); set_info(nil)
      end
      redirect_here("updates")
    end

    if http.formvalue("_geo_write_script") == "1" then
      local rows = load_geo_cfg2()
      write_geo_script(rows)
      set_info("Скрипт обновления пересоздан"); set_err(nil)
      redirect_here("updates")
    end

    if http.formvalue("_geo_install_cron") == "1" then
      local rows = load_geo_cfg2()
      write_geo_script(rows)

      local spec = (http.formvalue("geo_cron") or ""):gsub("%s+"," ")
      if spec == "" or spec:find("выключен") then spec = "0 5 * * *" end
      local fields = {}
      for w in spec:gmatch("%S+") do fields[#fields+1] = w end
      if #fields ~= 5 then
        set_err("Некорректное выражение cron: требуется 5 полей (мин чч дд мм дн). Получено: "..spec); set_info(nil)
      else
        cron_install(spec)
        set_info("Cron установлен: "..spec); set_err(nil)
      end
      redirect_here("updates")
    end

    if http.formvalue("_geo_remove_cron") == "1" then
      cron_remove()
      set_info("Cron удалён"); set_err(nil)
      redirect_here("updates")
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

return m
