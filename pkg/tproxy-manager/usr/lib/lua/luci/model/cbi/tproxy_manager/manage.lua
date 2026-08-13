-- /usr/lib/lua/luci/model/cbi/tproxy_manager/manage.lua
local fs    = require "nixio.fs"
local sys   = require "luci.sys"
local jsonc = require "luci.jsonc"
local http  = require "luci.http"
local disp  = require "luci.dispatcher"
local xml   = require "luci.xml"
local utils = require "luci.model.cbi.tproxy_manager.utils"
local _     = require "luci.model.cbi.tproxy_manager.i18n"
local engines = require "tproxy_manager.engines"
local ucim  = require "luci.model.uci"
local uci   = ucim.cursor()
local cbi   = require "luci.cbi"
local SimpleSection, DummyValue, Button =
  cbi.SimpleSection, cbi.DummyValue, cbi.Button

-- Aliases
local pcdata     = xml.pcdata
local formvalue  = http.formvalue

-- Package paths
local PKG      = "tproxy-manager"
local BASE_DIR = "/etc/tproxy-manager"

local read_file  = utils.read_file
local write_file = utils.write_file

-- TTL messages
local ERR_F   = "/tmp/tproxy_manager_last_error"
local INF_F   = "/tmp/tproxy_manager_last_info"
local ERR_TTL = 60
local messages = utils.make_temp_message_store(ERR_F, INF_F, ERR_TTL)
local set_err, get_err = messages.set_err, messages.get_err
local set_info, get_info = messages.set_info, messages.get_info

-- Common system log for modules.
local function combined_log()
  local out = sys.exec("logread 2>/dev/null | tail -n 200")
  return (out and out ~= "") and out or _("(no log lines)")
end

-- Shared service helpers.
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

-- Shared service status block.
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
      run and "ok" or "err", run and _("running") or _("stopped"),
      en and "ok" or "err",  en  and _("enabled") or _("disabled")
    )
  end

  local bstart = sec:option(Button, "_"..svc.."_start"); bstart.title = ""; bstart.inputtitle = _("Start")
  bstart.inputstyle = "apply"
  function bstart.render(self, section) if svc_running(svc_status_txt(svc)) then return end; Button.render(self, section) end
  function bstart.write(self, section) if not self.map:formvalue(self:cbid(section)) then return end; svc_do(svc,"start"); set_err(nil); http.redirect(disp.build_url("admin","network","tproxy_manager").."?tab="..(tabname or "")) end

  local bstop  = sec:option(Button, "_"..svc.."_stop"); bstop.title = ""; bstop.inputtitle = _("Stop")
  bstop.inputstyle = "remove"
  function bstop.render(self, section) if not svc_running(svc_status_txt(svc)) then return end; Button.render(self, section) end
  function bstop.write(self, section) if not self.map:formvalue(self:cbid(section)) then return end; svc_do(svc,"stop"); set_err(nil); http.redirect(disp.build_url("admin","network","tproxy_manager").."?tab="..(tabname or "")) end

  local ben   = sec:option(Button, "_"..svc.."_enable"); ben.title = ""; ben.inputtitle = _("Enable autostart")
  ben.inputstyle = "apply"
  function ben.render(self, section) if is_enabled(svc) then return end; Button.render(self, section) end
  function ben.write(self, section) if not self.map:formvalue(self:cbid(section)) then return end; svc_do(svc,"enable"); set_err(nil); http.redirect(disp.build_url("admin","network","tproxy_manager").."?tab="..(tabname or "")) end

  local bdis  = sec:option(Button, "_"..svc.."_disable"); bdis.title = ""; bdis.inputtitle = _("Disable autostart")
  bdis.inputstyle = "remove"
  function bdis.render(self, section) if not is_enabled(svc) then return end; Button.render(self, section) end
  function bdis.write(self, section) if not self.map:formvalue(self:cbid(section)) then return end; svc_do(svc,"disable"); set_err(nil); http.redirect(disp.build_url("admin","network","tproxy_manager").."?tab="..(tabname or "")) end
end

-- Form values
local function request_arg(name)
  local args = disp.context and disp.context.requestargs
  local v = type(args) == "table" and args[name] or nil
  if type(v) == "table" then return v[1] or "" end
  if v ~= nil and v ~= "" then return v end

  local function query_value(qs)
    qs = tostring(qs or "")
    for part in qs:gmatch("[^&]+") do
      local k, val = part:match("^([^=]*)=?(.*)$")
      if http.urldecode(k or "") == name then
        return http.urldecode((val or ""):gsub("+", " "))
      end
    end
    return nil
  end

  local ok, qs = pcall(function() return http.getenv("QUERY_STRING") end)
  v = ok and query_value(qs) or nil
  if v ~= nil and v ~= "" then return v end

  local ok_uri, uri = pcall(function() return http.getenv("REQUEST_URI") end)
  local uri_qs = ok_uri and tostring(uri or ""):match("%?(.*)$") or nil
  v = query_value(uri_qs)
  if v ~= nil and v ~= "" then return v end

  return nil
end
local function fval(name)
  local v = formvalue(name)
  if v == nil or v == "" then v = request_arg(name) end
  if type(v) == 'table' then return v[1] or '' else return v or '' end
end
local function fval_last(name)
  local v = formvalue(name)
  if v == nil or v == "" then v = request_arg(name) end
  if type(v) == 'table' then return v[#v] or '' else return v or '' end
end

-- Utilities used by modules.
local function urlencode(s) return (http and http.urlencode) and http.urlencode(s) or tostring(s or "") end
local function pick_form_or_uci(form_val, uci_val)
  return (form_val ~= nil and form_val ~= "") and form_val or (uci_val or "")
end
-- append_line_unique: adds a line and REPORTS what happened. It used to return
-- nothing, so the quick-add buttons announced "added" for a duplicate and for
-- a write that never reached the disk alike.
--   "added"       - the line is now in the file
--   "exists"      - it was already there; nothing was written
--   "permissions" - written, but the file mode could not be secured
--   "failed"      - not written
local function append_line_unique(path, line)
  if not line or line == "" then return "failed" end
  local body = read_file(path)
  for ln in (body .. "\n"):gmatch("([^\n]*)\n") do
    if ln:gsub("^%s+",""):gsub("%s+$","") == line then return "exists" end
  end
  local ok, why = write_file(path,
    (body ~= "" and (body:match("\n$") and body or body.."\n") or "") .. line .. "\n")
  if ok then return "added" end
  if why == "permissions" then return "permissions" end
  return "failed"
end

-- Current page URL helper.
local function self_url(opts)
  opts = opts or {}
  local url = disp.build_url("admin","network","tproxy_manager")
  local qp = {}
  if opts.tab and #opts.tab>0 then qp[#qp+1] = "tab="..urlencode(opts.tab) end
  local keys = {}
  for k, v in pairs(opts) do
    if k ~= "tab" and v ~= nil and tostring(v) ~= "" then keys[#keys+1] = k end
  end
  table.sort(keys)
  for __, k in ipairs(keys) do
    qp[#qp+1] = urlencode(k) .. "=" .. urlencode(opts[k])
  end
  if #qp>0 then url = url .. "?" .. table.concat(qp,"&") end
  return url
end
local function redirect_here(tab)
  http.redirect(self_url({ tab = tab }))
end

-- ensure dirs
do
  utils.ensure_dir(BASE_DIR)
end

-- ensure main section exists, but do not rewrite installer defaults from LuCI
do
  local has_main = uci:get(PKG, "main") or sys.call("uci -q get " .. utils.shellescape(PKG .. ".main") .. " >/dev/null 2>&1") == 0
  if not has_main then
    uci:section(PKG,"main","main",{})
    -- Section creation is the one commit whose failure would leave every
    -- later read falling back to defaults; surface it in the log rather
    -- than continuing silently.
    local ok_sec, why_sec = utils.commit_uci(uci, PKG)
    if not ok_sec and why_sec == "commit" then
      sys.exec("logger -t tproxy-manager 'failed to create the main UCI section'")
    end
  end
end

local function uci_get_main(option, fallback)
  local value = uci:get(PKG, "main", option)
  if value ~= nil and value ~= false and value ~= "" then return value end

  local out = sys.exec("uci -q get " .. utils.shellescape(PKG .. ".main." .. option) .. " 2>/dev/null") or ""
  out = utils.trim(out)
  if out ~= "" then return out end

  return fallback
end

-- Active core tab is controlled by proxy_engine. Legacy enable_* keys stay in UCI
-- for compatibility, but the UI no longer uses them for navigation.
local PROXY_ENGINE = engines.current(uci, PKG)
local ENABLE_XRAY     = PROXY_ENGINE == "xray"
local ENABLE_MIHOMO   = PROXY_ENGINE == "mihomo"
local ENABLE_SINGBOX  = PROXY_ENGINE == "singbox"
local ENABLE_UPDATES  = true
local ENABLE_WATCHDOG = true

-- Network model is useful for the TPROXY core.
local netm_init = nil
do
  local ok, res = pcall(function() return require("luci.model.network").init() end)
  if ok then netm_init = res end
end

-- ---------- Form rendering ----------
-- Keep the page compact: title only, no description.
local m = cbi.SimpleForm("tproxy_manager", "TPROXY Manager")
m.submit = true
m.reset  = false

-- Shared base styles.
do
  local s = m:section(SimpleSection)
  local dv = s:option(DummyValue, "_css_base"); dv.rawhtml = true
  function dv.cfgvalue() return [[
<style>
/* ----------------------------------------------------------------------------
   Token layer.

   luci-theme-bootstrap already ships a complete token set and flips every value
   for the dark scheme through :root[data-darkmode="true"]. This package used to
   hardcode 28 hex colours instead, which is why a light-background rule such as
   `th{background:#f9fafb}` left the theme's own text colour on top of it at a
   contrast of 1.76 on a dark router. Nothing here invents a palette: it names
   the theme's variables so every module can use them, and overrides only the
   two values where the theme's own semantic colour does not reach WCAG AA as
   13px text.
   ------------------------------------------------------------------------- */
:root{
  /* semantic text: the darker variant reads on a light ground */
  --tpm-ok:var(--success-color-low,#007936);
  --tpm-bad:var(--error-color-low,#b14946);
  --tpm-warn:var(--warn-color-low,#8a6412);
  /* surfaces and lines, straight from the theme */
  --tpm-surface:var(--background-color-low,#f9fafb);
  --tpm-line:var(--border-color-medium,#e5e7eb);
  /* --text-color-medium measures 4.13 on the dark ground and 3.95 on the light
     one, so secondary text uses the -high step and separates itself by size and
     weight instead of by contrast */
  --tpm-muted:var(--text-color-high,#404040);
  /* tints composed from the theme's rgb triplets, so they follow the ground */
  --tpm-ok-tint:rgba(var(--success-color-high-rgb,0,166,108),.12);
  --tpm-bad-tint:rgba(var(--error-color-high-rgb,209,86,83),.12);
  --tpm-neutral-tint:rgba(127,127,127,.12);
  /* the service row only needs to be separated, not filled: at .12 the lifted
     background cost the success badge 0.7 of contrast and pushed it under AA */
  --tpm-row-tint:rgba(127,127,127,.06);
  /* spacing scale: replaces 21 ad-hoc steps */
  --tpm-1:.25rem; --tpm-2:.5rem; --tpm-3:.75rem; --tpm-4:1rem; --tpm-5:1.5rem;
  /* measures: replaces 560/860/960/1200px scattered across three files */
  --tpm-measure-form:34rem; --tpm-measure-text:54rem; --tpm-measure-wide:75rem;
  /* one monospace stack; two different ones stopped digits lining up */
  --tpm-mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  --tpm-fs-code:.92em; --tpm-fs-meta:.82em; --tpm-fs-micro:.72em;
}
:root[data-darkmode="true"]{
  /* on the dark ground the light-scheme variants are too dark to read; the
     theme's own --error-color-high only reaches 3.99 as text, so this one value
     is lifted within the same hue to clear 4.5 */
  --tpm-ok:var(--success-color-high,#00ac59);
  --tpm-bad:#f97066;
  --tpm-warn:var(--warn-color-high,#efbd0b);
}
.cbi-page-actions{display:none!important}
.cbi-section{margin:var(--tpm-1) 0}
.cbi-value{margin:0}
/* service status row */
.svc-row{margin:0;padding:.06rem var(--tpm-1);border-radius:.2rem;background:var(--tpm-row-tint)}
.svc-title{margin:0}
.svc-badge{font-weight:600}
.svc-badge.ok{color:var(--tpm-ok)}
.svc-badge.err{color:var(--tpm-bad)}
.svc-badge.warn{color:var(--tpm-warn)}
/* service buttons in one line */
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
/* messages: tinted from the theme, so the text colour is always the theme's */
.msg{padding:var(--tpm-2) var(--tpm-3);border-radius:.5rem;margin:var(--tpm-2) 0;white-space:pre-wrap;border:1px solid var(--tpm-line)}
.msg.err{background:var(--tpm-bad-tint);border-color:var(--tpm-bad);color:var(--tpm-bad)}
.msg.info{background:var(--tpm-ok-tint);border-color:var(--tpm-ok);color:var(--tpm-ok)}
.box{padding:var(--tpm-2);border:1px solid var(--tpm-line);border-radius:.5rem}
.inline-row{display:flex;align-items:center;gap:var(--tpm-1);flex-wrap:wrap}
.editor-wrap{max-width:var(--tpm-measure-text)}
.editor-wide{max-width:var(--tpm-measure-wide)}
.editor-wrap textarea,.editor-wide textarea{width:100%;max-width:100%;box-sizing:border-box;font-family:var(--tpm-mono)}
/* every wide table scrolls inside its own container, never the page */
.tpm-tablewrap{overflow-x:auto;-webkit-overflow-scrolling:touch;max-width:100%}
.tpm-num{font-variant-numeric:tabular-nums}
/* A proxy link is ~400 characters. Printed in full it made every row of the link
   list several hundred pixels tall, so it is clamped to three lines and expands
   to the whole value on hover or keyboard focus. The clamp lives on an inner
   element on purpose: -webkit-box on the <td> itself would stop it being a table
   cell and collapse the table layout. The full value is also in the cell's title
   attribute, so the native tooltip works too. */
.wd-clamp{
  display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;
  overflow:hidden;word-break:break-all;
}
.wd-code:hover .wd-clamp,
.wd-code:focus-within .wd-clamp{-webkit-line-clamp:unset;overflow:visible}
/* the list editor used a hard width:520px with max-width:none, which forced the
   whole page to scroll sideways on anything narrower than ~540px */
.tpm-editor{width:100%;max-width:100%;box-sizing:border-box;font-family:var(--tpm-mono);font-size:var(--tpm-fs-code)}
.tpm-filesel{max-width:min(100%,26rem)}
/* Per-engine init script path: one line of text plus a pencil. The input and the
   save row stay out of the layout until something is actually being edited, so the
   engine block keeps the height it had before the field existed. */
.tpm-engine-row{display:flex;align-items:center;flex-wrap:wrap;gap:.3rem}
.tpm-svc-view{font-family:var(--tpm-mono);font-size:var(--tpm-fs-meta)}
.tpm-svc-edit{
  border:0;background:transparent;cursor:pointer;padding:0 .2rem;line-height:1;
  color:var(--tpm-muted);font-size:1em;
}
.tpm-svc-edit:hover{color:var(--tpm-ok)}
.tpm-svc-path{
  display:none;flex:1 1 18rem;min-width:0;max-width:min(100%,34rem);
  font-family:var(--tpm-mono);font-size:var(--tpm-fs-meta);
}
.tpm-engine-row.editing .tpm-svc-view,
.tpm-engine-row.editing .tpm-svc-edit{display:none}
.tpm-engine-row.editing .tpm-svc-path{display:block}
.tpm-svc-actions{display:none;align-items:center;flex-wrap:wrap;gap:var(--tpm-2);margin-top:var(--tpm-2)}
.editing-any .tpm-svc-actions{display:flex}
.tpm-svc-hint{color:var(--tpm-muted);font-size:var(--tpm-fs-meta)}
/* Shared code-editor chrome. The Xray and sing-box tabs each carried their own
   copy of this and Mihomo had none at all, so the three engine tabs looked like
   three different products. Deliberately dark in both schemes: it is a window
   into a config file, the same way a terminal is. */
.tpm-codeblock{display:block;width:min(100%,var(--tpm-measure-text));max-width:100%;clear:both}
.tpm-codebox{
  position:relative;border:1px solid var(--tpm-line);border-radius:.35rem;
  background:#0f172a;overflow:hidden;
}
.tpm-codebox textarea{
  display:block;width:100%;box-sizing:border-box;margin:0;padding:.65rem;
  border:0;outline:0;resize:vertical;background:transparent;color:#d1d5db;
  font:13px/1.45 var(--tpm-mono);tab-size:2;white-space:pre;overflow:auto;
}
.leases-table{ width:100%; border-collapse:collapse }
.leases-table th, .leases-table td{border:1px solid var(--tpm-line); padding:.35rem; vertical-align:top}
.leases-table th{background:var(--tpm-surface); color:inherit}
/* keep the gap after the extra settings block compact */
#extra-mods{ margin: var(--tpm-1) 0 0 0; }
#extra-mods + .cbi-section{ margin-top: 0 !important; }
/* ---- narrow screens: tables stop being tables ----------------------------
   Below this width eight columns get 24-107px each, which turned one row of the
   link list into 624px of vertical smear and the whole table into 19395px. Rows
   become cards; the column headings come back as labels from data-th.        */
@media (max-width:760px){
  .tpm-cards thead{display:none}
  .tpm-cards tr{display:block;border:1px solid var(--tpm-line);border-radius:.4rem;margin:0 0 var(--tpm-2);padding:var(--tpm-1) var(--tpm-2)}
  .tpm-cards td{display:block;border:0!important;padding:.15rem 0!important;width:auto!important}
  .tpm-cards td[data-th]::before{
    content:attr(data-th) " ";
    display:inline-block;min-width:8.5em;
    color:var(--tpm-muted);font-size:var(--tpm-fs-micro);text-transform:uppercase;letter-spacing:.04em;
  }
  .tpm-cards td:empty{display:none}
  /* A proxy link is ~400 characters; printed in full it took 204px of a 441px
     card, i.e. almost half the vertical cost of the whole list. Two lines with an
     ellipsis is enough to recognise a server, and the full value is already in
     the cell's title attribute. */
  .tpm-cards .wd-clamp{-webkit-line-clamp:2}
  /* Tried flowing the short fields inline to save rows; measured on the device it
     made cards TALLER (266px -> 350px), because inline-block boxes wrap with the
     label and add line-box gaps. Left as one field per line. */
  .tpm-cards td[data-th]{line-height:1.35}
  .wd-grid{grid-template-columns:1fr!important}
}
</style>]] end
end

-- Hidden state and dirty guard.
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
    if (n === 'uniedit_text' || n === 'json_text' || n === 'clash_text' || n === 'mihomo_text' || n === 'singbox_text' || n === 'geo_sources' || n === 'watchdog_template_text' || n === 'watchdog_template_path' || n === 'watchdog_links_text' || n === 'watchdog_proxy2mihomo' || n === 'watchdog_proxy2singbox' || n === 'watchdog_batch_check_port_start' || n === 'watchdog_batch_check_batch_size' || n === 'watchdog_batch_check_concurrency' || n === 'wd_add_link' || n === 'wd_edit_link' || n === 'watchdog_happ_capture_ttl' || n === 'watchdog_happ_capture_port' || n === 'watchdog_happ_capture_log' || n === 'happ_capture_start_ttl' || n === 'happ_capture_start_port' || n === 'happ_capture_start_log' || (n && n.indexOf('sub_') === 0)) window.__xray_dirty = true;
  }, true);
  window.__xray_guard = function(){ return (!window.__xray_dirty) || confirm(']] .. pcdata(_("There are unsaved changes. Leave without saving?")) .. [['); };
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

-- Navigation before extra settings.
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
    out[#out+1] = link("xray",   "XRAY",   ENABLE_XRAY)
    out[#out+1] = link("mihomo", "MIHOMO", ENABLE_MIHOMO)
    out[#out+1] = link("singbox", "SING-BOX", ENABLE_SINGBOX)
    out[#out+1] = link("updates", _("GEO updates"), ENABLE_UPDATES)
    out[#out+1] = link("watchdog","WATCHDOG", ENABLE_WATCHDOG)
    return "<div style='margin:.2rem 0 .2rem 0'>" .. table.concat(out, "") .. "</div>"
  end
end

-- Redirect to TPROXY by default.
if fval("tab") == "" then
  http.redirect(disp.build_url("admin","network","tproxy_manager") .. "?tab=tproxy")
  return m
end

local cur_tab = fval("tab") or "tproxy"
if (cur_tab == "xray" and not ENABLE_XRAY)
  or (cur_tab == "mihomo" and not ENABLE_MIHOMO)
  or (cur_tab == "singbox" and not ENABLE_SINGBOX) then
  http.redirect(self_url({ tab = "tproxy" }))
  return m
end

-- Shared module context.
local ctx = {
  PKG = PKG, BASE_DIR = BASE_DIR,
  m = m, uci = uci, http = http, sys = sys, fs = fs, disp = disp, jsonc = jsonc, xml = xml,
  pcdata = pcdata, fval = fval, fval_last = fval_last,
  self_url = self_url, redirect_here = redirect_here,
  combined_log = combined_log, service_block = service_block,
  set_err = set_err, get_err = get_err, set_info = set_info, get_info = get_info,

  -- Utilities
  utils = utils,
  _ = _,
  engines = engines,
  proxy_engine = PROXY_ENGINE,
  write_file = write_file, read_file = read_file,
  pick_form_or_uci = pick_form_or_uci,
  append_line_unique = append_line_unique,
  trim = utils.trim,
  shellescape = utils.shellescape,
  is_port = utils.is_port,
  is_ipv4 = utils.is_ipv4,
  is_uint = utils.is_uint,
  is_abs_path = utils.is_abs_path,
  is_iface_name = utils.is_iface_name,
  is_nft_table_name = utils.is_nft_table_name,
  is_fwmark = utils.is_fwmark,
  parse_kv_text = utils.parse_kv_text,
  netm_init = netm_init,
}

-- Load modules according to the selected tab and UCI flags.
if cur_tab == "tproxy" then
  require("luci.model.cbi.tproxy_manager.modules.tproxy").render(ctx)
elseif cur_tab == "xray" and ENABLE_XRAY then
  require("luci.model.cbi.tproxy_manager.modules.xray").render(ctx)
elseif cur_tab == "mihomo" and ENABLE_MIHOMO then
  require("luci.model.cbi.tproxy_manager.modules.mihomo").render(ctx)
elseif cur_tab == "singbox" and ENABLE_SINGBOX then
  require("luci.model.cbi.tproxy_manager.modules.singbox").render(ctx)
elseif cur_tab == "updates" and ENABLE_UPDATES then
  require("luci.model.cbi.tproxy_manager.modules.updates").render(ctx)
elseif cur_tab == "watchdog" and ENABLE_WATCHDOG then
  require("luci.model.cbi.tproxy_manager.modules.watchdog").render(ctx)
else
  http.redirect(self_url({ tab = "tproxy" }))
  return m
end

-- Messages are rendered at the bottom to keep module layout stable.
do
  local s = m:section(SimpleSection)
  local msg = s:option(DummyValue, "_msgs"); msg.rawhtml = true; msg.title = ""
  function msg.cfgvalue()
    local e = get_err(); local i = get_info()
    local out = {}
    if e ~= "" then out[#out+1] = "<div class='msg err'>"..pcdata(e).."</div>" end
    if i ~= "" then out[#out+1] = "<div class='msg info'>"..pcdata(i).."</div>" end
    return table.concat(out)
  end
end

return m
