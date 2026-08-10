local cbi = require "luci.cbi"
local SimpleSection, DummyValue, Button = cbi.SimpleSection, cbi.DummyValue, cbi.Button

local fs   = require "nixio.fs"
local sys  = require "luci.sys"
local http = require "luci.http"
local disp = require "luci.dispatcher"
local xml  = require "luci.xml"
local utils = require "luci.model.cbi.tproxy_manager.utils"
local _ = require "luci.model.cbi.tproxy_manager.i18n"
local pcdata = xml.pcdata

local SINGBOX_DIR = "/etc/sing-box"
local SINGBOX_TEST_LOG = "/tmp/tproxy_manager_singbox_test.log"
local SINGBOX_VERSION_SCRIPT = "/usr/bin/tproxy-manager-singbox-version.lua"

local read_file = utils.read_file
local write_file = utils.write_file

local function get_singbox_bin()
  if fs.access("/usr/bin/sing-box") then return "/usr/bin/sing-box"
  elseif fs.access("/usr/sbin/sing-box") then return "/usr/sbin/sing-box"
  else return "sing-box" end
end

local SINGBOX_BIN = get_singbox_bin()

local function run_cmd_capture(cmd)
  local marker = "__TPM_SINGBOX_RC__:"
  local wrapped = string.format("(%s) 2>&1; printf '\\n%s%%s' \"$?\"", cmd, marker)
  local out = sys.exec(wrapped) or ""
  local rc = tonumber(out:match(marker .. "([%-%d]+)%s*$")) or 1
  out = out:gsub("\n?" .. marker .. "[%-%d]+%s*$", "")
  return rc, utils.trim(out)
end

local function run_singbox_version(args)
  local parts = { utils.shellescape(SINGBOX_VERSION_SCRIPT) }
  for __, arg in ipairs(args or {}) do
    parts[#parts + 1] = utils.shellescape(arg)
  end
  return run_cmd_capture(table.concat(parts, " "))
end

local function parse_tsv_versions(text)
  local out = {}
  for line in ((text or "") .. "\n"):gmatch("([^\n]*)\n") do
    local tag, published, prerelease, asset = line:match("^([^\t]+)\t([^\t]*)\t([^\t]*)\t([^\t]*)$")
    if tag then
      out[#out + 1] = {
        tag = tag,
        published = published,
        prerelease = prerelease == "1",
        asset = asset,
      }
    end
  end
  return out
end

local function basename(path, fallback)
  local name = tostring(path or ""):match("([^/]+)$")
  return name ~= "" and name or fallback
end

local function list_json(dir)
  local t, it = {}, fs.dir(dir)
  if it then
    for name in it do
      if name:match("%.json$") then t[#t + 1] = name end
    end
  end
  table.sort(t)
  return t
end

local function validate_singbox_text(text)
  if not utils.validate_jsonc_text(text or "") then
    write_file(SINGBOX_TEST_LOG, "JSON parse error\n")
    return false
  end
  local tmp = string.format("/tmp/tproxy-manager-singbox-check.%d.json", math.random(1, 10^9))
  write_file(tmp, text or "")
  local cmd = string.format("%s check -c %q >%s 2>&1", SINGBOX_BIN, tmp, SINGBOX_TEST_LOG)
  local ok = sys.call(cmd) == 0
  fs.remove(tmp)
  return ok
end

local function ensure_default_config()
  utils.ensure_dir(SINGBOX_DIR)
  if not fs.access(SINGBOX_DIR .. "/tproxy-manager.json") then
    write_file(SINGBOX_DIR .. "/tproxy-manager.json", [[{
  "log": {
    "level": "warn"
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 10808
    },
    {
      "type": "tproxy",
      "tag": "tproxy-in",
      "listen": "::",
      "listen_port": 61219
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "direct"
  }
}
]])
  end
end

ensure_default_config()

local function render(ctx)
  local m = ctx.m
  local fval, fval_last = ctx.fval, ctx.fval_last
  local self_url, redirect_here = ctx.self_url, ctx.redirect_here
  local combined_log, set_err, get_err, set_info, get_info =
    ctx.combined_log, ctx.set_err, ctx.get_err, ctx.set_info, ctx.get_info
  local service_block = ctx.service_block

  if http.formvalue("_refreshlog_singbox") then set_err(nil); redirect_here("singbox"); return m end
  if http.formvalue("_clearlog_singbox") then
    -- Restarting `log` is what actually drops the ring buffer. Clearing
    -- the banner regardless read as success even when it failed.
    if sys.call("/etc/init.d/log restart >/dev/null 2>&1") == 0 then
      set_err(nil)
    else
      set_info(nil); set_err(_("Failed to clear the log."))
    end
    redirect_here("singbox"); return m
  end
  if http.formvalue("_test_singbox") then
    local default_config = basename(ctx.uci:get(ctx.PKG, "main", "singbox_profile_config_file"), "tproxy-manager.json")
    local config_file = fval_last("singbox_file_selected")
    if config_file == "" then config_file = fval_last("singbox_file") end
    if config_file == "" or config_file:find("[/\\]") then config_file = default_config end
    sys.call(string.format("%s check -c %q >%s 2>&1", SINGBOX_BIN, SINGBOX_DIR .. "/" .. config_file, SINGBOX_TEST_LOG))
    set_err(nil); redirect_here("singbox"); return m
  end
  if http.formvalue("_clearlog_singbox_config") then
    local ok, why = write_file(SINGBOX_TEST_LOG, "")
    if ok then
      set_err(nil)
    elseif why == "permissions" then
      set_info(nil)
      set_err(_("Settings saved, but the configuration file permissions could not be secured."))
    else
      set_info(nil); set_err(_("Failed to clear the log."))
    end
    redirect_here("singbox"); return m
  end
  if http.formvalue("_singbox_version_refresh") == "1" then
    local rc, out = run_singbox_version({ "status", "--refresh" })
    if rc == 0 then set_info(_("sing-box version information refreshed.")) else set_err(out ~= "" and out or _("Failed to refresh sing-box version information.")) end
    redirect_here("singbox"); return m
  end
  if http.formvalue("_singbox_update_latest") == "1" then
    local rc, out = run_singbox_version({ "status", "--refresh" })
    local status = utils.parse_kv_text(out)
    local tag = utils.trim(status.LATEST_TAG or "")
    if rc ~= 0 or tag == "" then
      set_err(out ~= "" and out or _("Latest sing-box version is not available."))
    else
      local install_rc, install_out = run_singbox_version({ "install", tag })
      if install_rc == 0 then set_info(install_out ~= "" and install_out or _("sing-box updated.")) else set_err(install_out ~= "" and install_out or _("sing-box update failed.")) end
    end
    redirect_here("singbox"); return m
  end
  if http.formvalue("_singbox_install_version") == "1" then
    local tag = utils.trim(http.formvalue("singbox_install_tag"))
    if tag == "" then
      set_err(_("Select sing-box version to install."))
    else
      local rc, out = run_singbox_version({ "install", tag })
      if rc == 0 then set_info(out ~= "" and out or _("sing-box version installed.")) else set_err(out ~= "" and out or _("sing-box install failed.")) end
    end
    redirect_here("singbox"); return m
  end
  if http.formvalue("_singbox_rollback") == "1" then
    local rc, out = run_singbox_version({ "rollback" })
    if rc == 0 then set_info(out ~= "" and out or _("sing-box rollback completed.")) else set_err(out ~= "" and out or _("sing-box rollback failed.")) end
    redirect_here("singbox"); return m
  end

  do
    local ss = m:section(SimpleSection, _("sing-box service status and controls"))
    service_block(ss, "tproxy-manager-sing-box", "sing-box", "singbox")
  end

  do
    local sec = m:section(SimpleSection)
    local dv = sec:option(DummyValue, "_singbox_version")
    dv.rawhtml = true
    function dv.cfgvalue()
      local status_rc, status_out = run_singbox_version({ "status" })
      local status = utils.parse_kv_text(status_out)
      local list_rc, list_out = run_singbox_version({ "list" })
      local versions = list_rc == 0 and parse_tsv_versions(list_out) or {}
      local color = status.STATUS_COLOR or "gray"
      local css_color = color == "green" and "#16a34a" or color == "blue" and "#2563eb" or color == "orange" and "#d97706" or "#6b7280"
      local rows = {}
      rows[#rows + 1] = "<details><summary><strong>" .. _("sing-box version") .. "</strong></summary>"
      rows[#rows + 1] = "<div class='box editor-wrap editor-680' style='margin-top:.5rem'>"
      rows[#rows + 1] = string.format([[
<div style="display:grid;grid-template-columns:12rem 1fr;gap:.35rem .7rem;align-items:center">
  <div>%s</div><div><code>%s</code></div>
  <div>%s</div><div><span style="font-weight:700;color:%s">%s</span></div>
  <div>%s</div><div>%s</div>
  <div>%s</div><div>%s</div>
  <div>%s</div><div><code>%s</code></div>
</div>]],
        pcdata(_("Binary path")),
        pcdata(status.BIN or SINGBOX_BIN),
        pcdata(_("Current version")),
        css_color,
        pcdata((status.CURRENT_VERSION or "") ~= "" and status.CURRENT_VERSION or _("unknown")),
        pcdata(_("Latest stable")),
        pcdata((status.LATEST_TAG or "") ~= "" and status.LATEST_TAG or _("unknown")),
        pcdata(_("Router architecture")),
        pcdata((status.ARCH or "") ~= "" and status.ARCH or _("unknown")),
        pcdata(_("Selected asset")),
        pcdata(status.ASSET or "")
      )
      if status.ERROR and status.ERROR ~= "" then
        rows[#rows + 1] = "<div style='margin-top:.5rem;color:#dc2626'>" .. pcdata(status.ERROR) .. "</div>"
      end
      rows[#rows + 1] = "<div style='margin-top:.6rem'>"
      rows[#rows + 1] = "<button class='cbi-button cbi-button-action' name='_singbox_version_refresh' value='1'>" .. _("Refresh versions") .. "</button> "
      rows[#rows + 1] = "<button class='cbi-button cbi-button-apply' name='_singbox_update_latest' value='1' onclick=\"return confirm('" .. pcdata(_("Update sing-box to latest stable version?")) .. "')\">" .. _("Update to latest") .. "</button> "
      rows[#rows + 1] = "<button class='cbi-button cbi-button-reset' name='_singbox_rollback' value='1' onclick=\"return confirm('" .. pcdata(_("Rollback sing-box to previous binary?")) .. "')\"" .. ((status.BACKUP_FILE or "") == "" and " disabled" or "") .. ">" .. _("Rollback previous binary") .. "</button>"
      rows[#rows + 1] = "</div>"
      rows[#rows + 1] = "<div style='margin-top:.7rem'>"
      rows[#rows + 1] = "<select name='singbox_install_tag' style='max-width:18rem'>"
      for __, item in ipairs(versions) do
        local suffix = item.prerelease and " prerelease" or ""
        rows[#rows + 1] = string.format("<option value='%s'>%s%s · %s</option>", pcdata(item.tag), pcdata(item.tag), pcdata(suffix), pcdata(item.published))
      end
      if #versions == 0 then rows[#rows + 1] = "<option value=''>" .. pcdata(_("No repository versions available")) .. "</option>" end
      rows[#rows + 1] = "</select> "
      rows[#rows + 1] = "<button class='cbi-button cbi-button-apply' name='_singbox_install_version' value='1' onclick=\"return confirm('" .. pcdata(_("Install selected sing-box version?")) .. "')\">" .. _("Install selected version") .. "</button>"
      rows[#rows + 1] = "</div>"
      if status_rc ~= 0 then rows[#rows + 1] = "<pre style='white-space:pre-wrap;color:#dc2626'>" .. pcdata(status_out) .. "</pre>" end
      rows[#rows + 1] = "</div></details>"
      return table.concat(rows, "\n")
    end
  end

  do
    local sl = m:section(SimpleSection)
    local log = sl:option(DummyValue, "_log_singbox"); log.rawhtml = true
    function log.cfgvalue()
      return "<details><summary><strong>" .. _("System log (logread)") .. "</strong></summary>" ..
             "<div class='box editor-wrap'><pre style='white-space:pre-wrap;max-height:30rem;overflow:auto'>" ..
             pcdata(combined_log()) .. "</pre>" ..
             "<div style='margin-top:.5rem'><button class='cbi-button cbi-button-action small-btn' style='margin-right:4px; padding:0; border:0' name='_refreshlog_singbox' value='1'>" .. _("Refresh") .. "</button> " ..
             "<button class='cbi-button cbi-button-remove small-btn' style='padding:0; border:0' name='_clearlog_singbox' value='1'>" .. _("Clear") .. "</button></div>" ..
             "</div></details>"
    end
  end

  do
    local sx = m:section(SimpleSection, _("sing-box (JSON files in /etc/sing-box)"))
    local config_files = list_json(SINGBOX_DIR)
    local default_config = basename(ctx.uci:get(ctx.PKG, "main", "singbox_profile_config_file"), "tproxy-manager.json")
    local chosen = fval("singbox_file")
    if chosen == "" then chosen = default_config end
    local found = false
    for __, f in ipairs(config_files) do if f == chosen then found = true; break end end
    if not found then
      for __, f in ipairs(config_files) do if f == default_config then chosen = f; found = true; break end end
    end
    if not found then chosen = config_files[1] end

    local function is_known_json_file(name)
      if not name or name == "" or name:find("[/\\]") then return false end
      for __, f in ipairs(config_files) do if f == name then return true end end
      return false
    end

    if http.formvalue("_singbox_create") == "1" then
      local name = (http.formvalue("new_singbox_name") or ""):gsub("^%s+", ""):gsub("%s+$", "")
      if name ~= "" and not name:find("[/\\]") and name:match("%.json$") then
        local path = SINGBOX_DIR .. "/" .. name
        if not fs.access(path) then
          -- Creation is checked: redirecting to an editor for a file that
          -- was never created (and clearing the error on the way) left the
          -- user staring at an empty page with no indication of failure.
          local made, mwhy = write_file(path, "{\n}\n")
          if not made and mwhy ~= "permissions" then
            set_info(nil)
            set_err(_("Failed to save settings."))
            redirect_here("singbox")
            return m
          end
          if not made then
            set_info(nil)
            set_err(_("Settings saved, but the configuration file permissions could not be secured."))
            redirect_here("singbox")
            return m
          end
        end
        set_err(nil)
        http.redirect(self_url({ tab = "singbox", singbox_file = name }))
      else
        set_err(_("Invalid file name. Expected *.json without slashes."))
        redirect_here("singbox")
      end
      return m
    end

    if http.formvalue("_singbox_delete") == "1" then
      local cf = fval_last("singbox_file") or ""
      if is_known_json_file(cf) then
        fs.remove(SINGBOX_DIR .. "/" .. cf)
        set_err(nil)
      else
        set_err(_("Invalid file name. Expected *.json without slashes."))
      end
      redirect_here("singbox"); return m
    end

    do
      local url = disp.build_url("admin", "network", "tproxy_manager")
      local buf = {}
      buf[#buf + 1] = "<div class='box editor-wrap editor-680' id='singbox-editor'>"
      buf[#buf + 1] = string.format([[
  <div class="inline-row" style="margin:.3rem 0;">
    <span>%s:</span>
    <input type="text" name="new_singbox_name" placeholder="config.json" style="width:200px">
    <button class="cbi-button cbi-button-apply" name="_singbox_create" value="1" onclick="return window.__xray_guard?window.__xray_guard():true">%s</button>
  </div>
  <div style="color:#6b7280;margin-top:.2rem">%s <code>*.json</code>, %s.</div>
  <hr style="border:none;border-top:1px solid #e5e7eb;margin:.5rem 0"/>]],
        pcdata(_("New file")),
        pcdata(_("Create")),
        pcdata(_("The name must match")),
        pcdata(_("without slashes"))
      )
      buf[#buf + 1] = "<label>" .. _("File to edit") .. "</label>"
      buf[#buf + 1] = "<select name='singbox_file'>"
      for __, f in ipairs(config_files) do
        local sel = (f == chosen) and " selected" or ""
        buf[#buf + 1] = string.format("<option value=\"%s\"%s>%s</option>", pcdata(f), sel, pcdata(f))
      end
      buf[#buf + 1] = "</select>"
      buf[#buf + 1] = string.format("<input type=\"hidden\" name=\"singbox_file_selected\" value=\"%s\">", pcdata(chosen or ""))
      buf[#buf + 1] = [[
<script>
(function(){
  var sel = document.querySelector('#singbox-editor select[name="singbox_file"]');
  var hidden = document.querySelector('#singbox-editor input[name="singbox_file_selected"]');
  if (!sel) return;
  function remember(){ if(hidden) hidden.value = sel.value || ''; }
  remember();
  sel.addEventListener('change', function(){
    if (window.__xray_guard && !window.__xray_guard()) {
      this.value = this.getAttribute('data-prev') || this.value; return;
    }
    remember();
    var base = ']] .. pcdata(url) .. [[';
    location.href = base + "?tab=singbox&singbox_file=" + encodeURIComponent(sel.value);
  });
  var form = sel.closest && sel.closest('form');
  if(form) form.addEventListener('submit', remember, true);
  sel.setAttribute('data-prev', sel.value);
})();
</script>]]
      buf[#buf + 1] = string.format([[
<button class="cbi-button cbi-button-remove" name="_singbox_delete" value="1"
  onclick="return (window.__xray_guard?window.__xray_guard():true) && confirm('%s')">%s</button>]],
        pcdata(_("Delete selected file?")),
        pcdata(_("Delete"))
      )
      buf[#buf + 1] = "</div><div style='height:5px'></div>"
      local dvsel = sx:option(DummyValue, "_selector_singbox"); dvsel.rawhtml = true
      function dvsel.cfgvalue() return table.concat(buf) end
    end

    if chosen then
      local edit = sx:option(DummyValue, "_singbox_area"); edit.rawhtml = true
      function edit.cfgvalue()
        local content = read_file(SINGBOX_DIR .. "/" .. chosen)
        return [[
<style>
#cbi-tproxy_manager .singbox-editor-cbi-full .cbi-value-title{display:none!important}
#cbi-tproxy_manager .singbox-editor-cbi-full .cbi-value-field{display:block!important;margin-left:0!important;width:100%!important}
.singbox-json-editor-block{display:block;width:min(100%,680px);max-width:100%;clear:both}
.singbox-json-codebox{position:relative;width:100%;height:32rem;border:1px solid #d1d5db;border-radius:.35rem;background:#0f172a;overflow:hidden}
.singbox-json-codebox pre,
.singbox-json-codebox textarea[name="singbox_text"]{
  position:absolute;inset:0;margin:0;padding:.65rem;box-sizing:border-box;
  border:0;outline:0;resize:none;overflow:auto;
  font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  tab-size:2;white-space:pre-wrap;word-break:break-word;
}
.singbox-json-codebox pre{pointer-events:none;color:#d1d5db;background:#0f172a}
.singbox-json-codebox textarea[name="singbox_text"]{
  width:100%;height:100%;background:transparent;color:transparent;caret-color:#f8fafc;
  -webkit-text-fill-color:transparent;
}
.singbox-json-codebox textarea[name="singbox_text"]::selection{background:rgba(96,165,250,.35)}
.singbox-json-codebox .json-key{color:#93c5fd}
.singbox-json-codebox .json-string{color:#86efac}
.singbox-json-codebox .json-number{color:#fbbf24}
.singbox-json-codebox .json-bool{color:#c4b5fd}
.singbox-json-codebox .json-null{color:#fca5a5}
.singbox-json-codebox .json-comment{color:#94a3b8;font-style:italic}
.singbox-json-codebox .json-punct{color:#e2e8f0}
</style>
<div class="singbox-json-editor-block">
<div class="singbox-json-codebox">
<pre id="singbox_highlight" aria-hidden="true"></pre>
<textarea name="singbox_text" rows="22" spellcheck="false">]] .. pcdata(content) .. [[</textarea>
</div>
<div class="box editor-wrap editor-680" id="singbox-status-box">
  <div id="singbox_status" style="margin:.08rem 0 .14rem 0; font-weight:600"></div>
</div>
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
  var block=document.querySelector('.singbox-json-editor-block');
  if(block){ var row=block.closest && block.closest('.cbi-value'); if(row) row.classList.add('singbox-editor-cbi-full'); }
  var ta=document.querySelector('textarea[name="singbox_text"]'), badge=document.getElementById('singbox_status'), hi=document.getElementById('singbox_highlight');
  function debounce(fn,ms){var t;return function(){clearTimeout(t);t=setTimeout(fn,ms)}}
  function esc(s){return String(s).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c]})}
  function highlightJsonc(src){
    src=src||'';
    return esc(src).replace(/("(?:\\.|[^"\\])*"(\s*:)?|\/\/[^\n]*|\/\*[\s\S]*?\*\/|\btrue\b|\bfalse\b|\bnull\b|-?\b\d+(?:\.\d+)?(?:[eE][+\-]?\d+)?\b|[{}\[\],:])/g,function(m){
      if(/^\/\//.test(m)||/^\/\*/.test(m))return '<span class="json-comment">'+m+'</span>';
      if(/^"/.test(m))return '<span class="'+(/\s*:$/.test(m)?'json-key':'json-string')+'">'+m+'</span>';
      if(/^(true|false)$/.test(m))return '<span class="json-bool">'+m+'</span>';
      if(/^null$/.test(m))return '<span class="json-null">'+m+'</span>';
      if(/^-?\d/.test(m))return '<span class="json-number">'+m+'</span>';
      return '<span class="json-punct">'+m+'</span>';
    });
  }
  function syncHighlight(){ if(!ta||!hi)return; hi.innerHTML=highlightJsonc(ta.value)+'\n'; hi.scrollTop=ta.scrollTop; hi.scrollLeft=ta.scrollLeft; }
  function showJsonError(badge, ta, hi, prefix, message){
    badge.textContent = '';
    badge.style.color = '#dc2626';
    badge.appendChild(document.createTextNode(prefix + message + ' '));
    var m = String(message || '').match(/position (\d+)/);
    if (!m) return;
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
      if (hi) hi.scrollTop = ta.scrollTop;
    };
    badge.appendChild(jump);
  }
  function validate(){ if(!ta||!badge)return; try{ JSON.parse(stripJsonComments(ta.value)); badge.textContent=']] .. pcdata(_("JSONC is valid (comments allowed)")) .. [['; badge.style.color='#16a34a'; }catch(e){ showJsonError(badge, ta, hi, ']] .. pcdata(_("JSON error:").." ") .. [[', e.message); } }
  var validateDebounced = debounce(validate,250);
  if(ta){
    ta.addEventListener('input', function(){ syncHighlight(); validateDebounced(); });
    ta.addEventListener('scroll', syncHighlight);
    syncHighlight(); validate();
    var key = 'singbox:' + (document.querySelector('#singbox-editor select[name="singbox_file"]')||{}).value;
    try{
      var st = JSON.parse(localStorage.getItem(key)||'{}');
      if(typeof st.scroll === 'number') ta.scrollTop = st.scroll;
      if(typeof st.selStart === 'number' && typeof st.selEnd === 'number'){ ta.selectionStart = st.selStart; ta.selectionEnd = st.selEnd; }
      function savePos(){ try{ localStorage.setItem(key, JSON.stringify({scroll: ta.scrollTop, selStart: ta.selectionStart||0, selEnd: ta.selectionEnd||0})); }catch(e){} }
      ta.addEventListener('scroll', savePos);
      ta.addEventListener('keyup', savePos);
      ta.addEventListener('blur', savePos);
    }catch(e){}
  }
})();
</script>
]]
      end

      local bsave = sx:option(Button, "_savesingbox"); bsave.title = ""; bsave.inputtitle = _("Save")
      bsave.inputstyle = "apply"
      function bsave.write(self, section)
        if not self.map:formvalue(self:cbid(section)) then return end
        local new = http.formvalue("singbox_text") or ""
        local cf = fval_last("singbox_file_selected")
        if not is_known_json_file(cf) then cf = fval_last("singbox_file") end
        if not is_known_json_file(cf) then cf = chosen end
        if not validate_singbox_text(new) then
          set_err(_("Invalid sing-box configuration. File was not saved."))
          set_info(nil)
          http.redirect(self_url({ tab = "singbox", singbox_file = cf }))
          return
        end
        local wrote, wwhy = write_file(SINGBOX_DIR .. "/" .. cf, new)
        if wrote then
          set_err(nil); set_info(_("sing-box config saved:").." " .. cf)
        elseif wwhy == "permissions" then
          set_info(nil); set_err(_("Settings saved, but the configuration file permissions could not be secured."))
        else
          set_info(nil); set_err(_("Failed to save settings."))
        end
        http.redirect(self_url({ tab = "singbox", singbox_file = cf }))
      end
    end

    local dout = sx:option(DummyValue, "_testout_singbox"); dout.rawhtml = true; dout.title = ""
    function dout.cfgvalue()
      local out = read_file(SINGBOX_TEST_LOG)
      return "<details><summary>" .. _("Last validation result") .. "</summary>" ..
             "<div class='box editor-wrap editor-680'><pre style='white-space:pre-wrap'>" ..
             pcdata(out ~= "" and out or _("(not run yet)")) .. "</pre>" ..
             "<div style='margin-top:.5rem'><button class='cbi-button cbi-button-action small-btn' style='margin-right:4px; padding:0; border:0' name='_test_singbox' value='1'>" .. _("Validate configuration") .. "</button> " ..
             "<button class='cbi-button cbi-button-remove small-btn' style='padding:0; border:0' name='_clearlog_singbox_config' value='1'>" .. _("Clear") .. "</button></div>" ..
             "</div></details>"
    end

    local msg = sx:option(DummyValue, "_singbox_msgs"); msg.rawhtml = true; msg.title = ""
    function msg.cfgvalue()
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
