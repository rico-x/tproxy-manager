local cbi = require "luci.cbi"
local backup = require "tproxy_manager.backup"
local SimpleSection, DummyValue, Button = cbi.SimpleSection, cbi.DummyValue, cbi.Button

local BACKUP_MODULE_LABELS = {
  core = "TPROXY", xray = "Xray", mihomo = "Mihomo", singbox = "sing-box",
  watchdog = "Watchdog", geo = "GEO",
}

local function backup_diff_line_class(tag)
  if tag == "add" then return "bkdiff-add" end
  if tag == "del" then return "bkdiff-del" end
  return "bkdiff-same"
end

local function render(ctx)
  local m, uci, http, sys, fs, disp = ctx.m, ctx.uci, ctx.http, ctx.sys, ctx.fs, ctx.disp
  local pcdata, fval, fval_last, pick_form_or_uci = ctx.pcdata, ctx.fval, ctx.fval_last, ctx.pick_form_or_uci
  local self_url, redirect_here = ctx.self_url, ctx.redirect_here
  local service_block, set_err, get_err, set_info, get_info = ctx.service_block, ctx.set_err, ctx.get_err, ctx.set_info, ctx.get_info
  local write_file, read_file, is_port, append_line_unique = ctx.write_file, ctx.read_file, ctx.is_port, ctx.append_line_unique
  local trim, is_ipv4, is_uint, is_abs_path = ctx.trim, ctx.is_ipv4, ctx.is_uint, ctx.is_abs_path
  local is_iface_name, is_nft_table_name, is_fwmark = ctx.is_iface_name, ctx.is_nft_table_name, ctx.is_fwmark
  local combined_log = ctx.combined_log
  local netm_init = ctx.netm_init
  local utils = ctx.utils
  local engines = ctx.engines
  local proxy_engine = ctx.proxy_engine or "xray"
  local _ = ctx._ or function(s) return s end
  local PKG = ctx.PKG
  local defaults = {
    ifaces = "br-lan",
    ipv6_enabled = "1",
    tproxy_port = "61219",
    port_mode = "bypass",
    src_mode = "off",
    nft_table = "tp_mgr",
    fwmark_tcp = "0x1",
    fwmark_udp = "0x2",
    rttab_tcp = "100",
    rttab_udp = "101",
    log_enabled = "1",
    ports_file = ctx.BASE_DIR .. "/tproxy-manager.ports",
    bypass_v4_file = ctx.BASE_DIR .. "/tproxy-manager.v4",
    bypass_v6_file = ctx.BASE_DIR .. "/tproxy-manager.v6",
    src_only_v4_file = ctx.BASE_DIR .. "/tproxy-manager.src4.only",
    src_only_v6_file = ctx.BASE_DIR .. "/tproxy-manager.src6.only",
    src_bypass_v4_file = ctx.BASE_DIR .. "/tproxy-manager.src4.bypass",
    src_bypass_v6_file = ctx.BASE_DIR .. "/tproxy-manager.src6.bypass",
  }
  local function getu(k)
    local v = uci:get(PKG, "main", k)
    if v == nil or v == "" then return defaults[k] or "" end
    if type(v) ~= "string" and type(v) ~= "number" then return defaults[k] or "" end
    return tostring(v)
  end

  -- Toolbar handlers for log
  if http.formvalue("_refreshlog_tproxy") then
    set_err(nil); redirect_here("tproxy"); return m
  end
  if http.formvalue("_clearlog_tproxy") then
    -- Restarting `log` is what actually drops the ring buffer. Clearing
    -- the banner regardless read as success even when it failed.
    if sys.call("/etc/init.d/log restart >/dev/null 2>&1") == 0 then
      set_err(nil)
    else
      set_info(nil); set_err(_("Failed to clear the log."))
    end
    redirect_here("tproxy"); return m
  end
  -- engine_message: engines.lua reports a stable code plus parameters instead
  -- of an English sentence. It is outside the LuCI i18n domain, and a sentence
  -- assembled there by concatenation could never be found in the catalog — so
  -- every engine message is built here, where _() actually applies.
  local function engine_problem(p)
    if p.code == "restore_failed" then
      return _("the previous configuration could NOT be restored")
    elseif p.code == "restore_permissions" then
      return _("the restored configuration file permissions could not be secured")
    elseif p.code == "target_not_stopped" then
      return string.format(_("%s could not be stopped"), p.engine)
    elseif p.code == "previous_not_up" then
      return string.format(_("%s did not come back up"), p.engine)
    elseif p.code == "stack_not_restarted" then
      return string.format(_("could not restart %s"), p.services)
    elseif p.code == "autostart_not_restored" then
      return string.format(_("autostart could not be restored for %s: the next reboot may start the wrong engine"), p.services)
    end
    return p.code
  end

  local function engine_message(code, p)
    p = p or {}
    if code == "not_installed" then
      return string.format(_("Binary is not installed: %s"), p.binary or "")
    elseif code == "stage_failed" then
      return _("Failed to stage the engine switch - nothing was changed.")
    elseif code == "commit_failed" then
      return _("Failed to save the engine selection - no services were restarted.")
    elseif code == "did_not_start_reverted" then
      return string.format(_("%s did not start; reverted to %s."), p.target or "", p.previous or "")
    elseif code == "rollback_incomplete" then
      local parts = {}
      for _idx, problem in ipairs(p.problems or {}) do parts[#parts + 1] = engine_problem(problem) end
      local msg = string.format(_("%s did not start; ROLLBACK INCOMPLETE: %s. Check the engine and service status manually."),
        p.target or "", table.concat(parts, "; "))
      if p.stuck then
        msg = msg .. " " .. string.format(_("Still running and holding the TPROXY port: %s."), p.stuck)
      end
      return msg
    elseif code == "no_version_manager" then
      return string.format(_("No version manager configured for %s."), p.engine or "")
    elseif code == "latest_unavailable" then
      if p.out and p.out ~= "" then return p.out end
      return string.format(_("Latest %s version is not available."), p.engine or "")
    elseif code == "install_failed" then
      if p.out and p.out ~= "" then return p.out end
      return string.format(_("%s install failed."), p.engine or "")
    end
    return code
  end

  if http.formvalue("_install_engine") and engines then
    local target = engines.normalize(http.formvalue("_install_engine"))
    local ok, code, params = engines.install_latest(target)
    if ok then
      set_err(nil)
      -- The version script's own output is shown when it produced any;
      -- otherwise a plain confirmation. Passing this through engine_message()
      -- would compose "Xray installed: Xray installed."
      local out = params and params.out or ""
      if out ~= "" then
        set_info(string.format(_("%s installed: %s"), engines.def(target).label, out))
      else
        set_info(string.format(_("%s installed."), engines.def(target).label))
      end
    else
      set_info(nil)
      set_err(engine_message(code, params))
    end
    redirect_here("tproxy")
    return m
  end
  -- Exactly one engine may start at boot. Offered as a button rather than done
  -- silently on page load: it changes service state, which is the user's call.
  if http.formvalue("_fix_engine_autostart") == "1" and engines then
    local failed = engines.align_autostart(uci, PKG, proxy_engine)
    if failed == "" then
      set_err(nil)
      set_info(string.format(_("Autostart left on for %s only."), engines.def(proxy_engine).label))
    else
      set_info(nil)
      set_err(string.format(_("Could not change autostart for: %s"), failed))
    end
    redirect_here("tproxy"); return m
  end

  -- Per-engine init script paths. Written to the engine's own profile, and to
  -- the live key as well when that engine is the active one, so the UI and the
  -- watchdog immediately agree with what was entered.
  if http.formvalue("_save_engine_paths") == "1" and engines then
    local changed, failed, invalid = 0, false, nil
    for __, id in ipairs(engines.ORDER) do
      local value = trim(http.formvalue("engine_service_path_" .. id) or "")
      if value ~= "" then
        if not utils.is_abs_path(value) then
          invalid = engines.def(id).label
          break
        end
        local current = engines.profile_value(uci, PKG, id, "service_path")
        if value ~= current then
          if not utils.uci_stage(uci, PKG, "main", id .. "_profile_service_path", value) then failed = true end
          if id == proxy_engine then
            if not utils.uci_stage(uci, PKG, "main", "watchdog_service_path", value) then failed = true end
          end
          changed = changed + 1
        end
      end
    end
    if invalid then
      uci:revert(PKG)
      set_info(nil)
      set_err(string.format(_("Invalid absolute path for %s."), invalid))
    elseif failed then
      uci:revert(PKG)
      set_info(nil)
      set_err(_("Failed to save settings."))
    elseif changed == 0 then
      set_err(nil)
      set_info(_("Nothing to save: the paths are unchanged."))
    else
      local ok_commit, why = utils.commit_uci(uci, PKG)
      if ok_commit then
        set_err(nil); set_info(_("Init script paths saved."))
      elseif why == "permissions" then
        set_info(nil); set_err(_("Settings saved, but the configuration file permissions could not be secured."))
      else
        set_info(nil); set_err(_("Failed to save settings."))
      end
    end
    redirect_here("tproxy"); return m
  end

  if http.formvalue("_activate_proxy_engine") == "1" and engines then
    local target = engines.normalize(http.formvalue("proxy_engine_choice") or proxy_engine)
    local ok, msg, warn, detail = engines.activate(uci, PKG, target)
    if not ok then
      -- On failure the second value is a code and the third its parameters.
      set_info(nil)
      set_err(engine_message(msg, warn))
      redirect_here("tproxy")
      return m
    end
    -- The engine is running, but the switch may still be partial. Every
    -- warning is surfaced: reporting plain success while TPROXY still
    -- points at the previous engine's port is what this reports on.
    local notes = {}
    if warn and warn:find("permissions", 1, true) then
      notes[#notes + 1] = _("Settings saved, but the configuration file permissions could not be secured.")
    end
    if warn and warn:find("services", 1, true) then
      notes[#notes + 1] = string.format(
        _("The engine is running, but these services did not restart: %s. Traffic may still be routed to the previous engine."),
        detail or "")
    end
    if #notes > 0 then
      set_info(nil)
      set_err(string.format(_("Proxy engine activated: %s"), msg or target) .. "\n" ..
        table.concat(notes, "\n"))
    else
      set_err(nil)
      set_info(string.format(_("Proxy engine activated: %s"), msg or target))
    end
    http.redirect(self_url({ tab = engines.def(target).tab }))
    return m
  end

  -- TPROXY service
  do
    local ss = m:section(SimpleSection, _("TPROXY service status and controls"))
    service_block(ss, "tproxy-manager", "TPROXY", "tproxy")
  end

  -- Active proxy engine selector.
  if engines then
    local sec = m:section(SimpleSection)
    local dv = sec:option(DummyValue, "_active_proxy_engine")
    dv.rawhtml = true
    function dv.cfgvalue()
      local rows = {}
      rows[#rows + 1] = "<div class='box editor-wrap'>"
      rows[#rows + 1] = "<div class='inline-row' style='gap:.5rem;flex-wrap:wrap'>"
      rows[#rows + 1] = "<strong>" .. pcdata(_("Active proxy engine")) .. "</strong>"
      rows[#rows + 1] = "<select name='proxy_engine_choice'>"
      for __, id in ipairs(engines.ORDER) do
        local def = engines.def(id)
        local sel = (id == proxy_engine) and " selected" or ""
        rows[#rows + 1] = string.format("<option value='%s'%s>%s</option>", pcdata(id), sel, pcdata(def.label))
      end
      rows[#rows + 1] = "</select>"
      rows[#rows + 1] = "<button class='cbi-button cbi-button-apply' name='_activate_proxy_engine' value='1'>" .. pcdata(_("Activate")) .. "</button>"
      rows[#rows + 1] = "</div>"
      rows[#rows + 1] = "<div style='display:grid;grid-template-columns:8rem 1fr;gap:.25rem .7rem;margin-top:.55rem'>"
      for __, id in ipairs(engines.ORDER) do
        local st = engines.status(uci, PKG, id)
        local def = engines.def(id)
        local active = (id == proxy_engine)
        local badge = active and (" <span class='svc-badge ok'>ACTIVE</span>") or ""
        local installed = st.installed and _("installed") or _("not installed")
        local running = st.running and _("running") or _("stopped")
        local enabled = st.enabled and _("enabled") or _("disabled")
        local installed_cls = st.installed and "ok" or "err"
        local running_cls = st.running and "ok" or "err"
        local enabled_cls = st.enabled and "ok" or "err"
        local install_btn = ""
        if not st.installed then
          install_btn = string.format(
            " <button class='cbi-button cbi-button-apply small-btn' name='_install_engine' value='%s'" ..
            " onclick=\"return (window.__xray_guard?window.__xray_guard():true) && confirm('%s')\">%s</button>",
            pcdata(id),
            pcdata(string.format(_("Install the latest %s now?"), def.label)),
            pcdata(_("Install"))
          )
        end
        -- The init script path stays a single line of text; the input appears only
        -- when the pencil next to it is clicked. Someone running a differently
        -- packaged daemon can point the engine at their own script without the
        -- three editors taking up the block permanently.
        rows[#rows + 1] = string.format(
          "<div><strong>%s</strong>%s%s</div>" ..
          "<div class='tpm-engine-row'>" ..
          "<span class='svc-badge %s'>%s</span> · <span class='svc-badge %s'>%s</span> · <span class='svc-badge %s'>%s</span> · " ..
          "<code class='tpm-svc-view'>%s</code>" ..
          "<button type='button' class='tpm-svc-edit' title='%s' aria-label='%s'>%s</button>" ..
          "<input class='tpm-svc-path' id='engine_svc_%s' type='text' name='engine_service_path_%s' value='%s' spellcheck='false' aria-label='%s'>" ..
          "</div>",
          pcdata(def.label), badge, install_btn,
          installed_cls, pcdata(installed),
          running_cls, pcdata(running),
          enabled_cls, pcdata(enabled),
          pcdata(st.service_path or ""),
          pcdata(_("Edit the init script path")), pcdata(_("Edit the init script path")), "&#9998;",
          pcdata(id), pcdata(id), pcdata(st.service_path or ""), pcdata(_("init script"))
        )
      end
      rows[#rows + 1] = "</div>"
      rows[#rows + 1] = "<div class='tpm-svc-actions'>" ..
        "<button class='cbi-button cbi-button-apply small-btn' name='_save_engine_paths' value='1'>" ..
        pcdata(_("Save init script paths")) .. "</button>" ..
        "<span class='tpm-svc-hint'>" ..
        pcdata(_("Absolute path to the init script that starts this engine.")) .. "</span></div>"
      rows[#rows + 1] = [==[
<script>
(function(){
  var box = document.currentScript && document.currentScript.parentElement;
  if (!box) return;
  box.addEventListener('click', function(e){
    var btn = e.target.closest && e.target.closest('.tpm-svc-edit');
    if (!btn) return;
    var row = btn.closest('.tpm-engine-row');
    if (!row) return;
    row.classList.add('editing');
    box.classList.add('editing-any');
    var input = row.querySelector('.tpm-svc-path');
    if (input) { input.focus(); input.select(); }
  });
})();
</script>]==]
      -- Two engines in autostart means a race for the TPROXY port on the next
      -- boot, and whichever wins silently decides how traffic is routed.
      local autostart_on = engines.autostart_conflicts and engines.autostart_conflicts(uci, PKG) or {}
      if #autostart_on > 1 then
        local names = {}
        for __, item in ipairs(autostart_on) do names[#names + 1] = item.label end
        rows[#rows + 1] = string.format(
          "<div class='msg err' style='margin-top:.5rem'>%s<div class='inline-row' style='margin-top:.35rem'>" ..
          "<button class='cbi-button cbi-button-apply small-btn' name='_fix_engine_autostart' value='1'>%s</button></div></div>",
          pcdata(string.format(
            _("Autostart is on for more than one engine (%s): after a reboot they compete for the TPROXY port."),
            table.concat(names, ", "))),
          pcdata(string.format(_("Leave autostart on for %s only"), engines.def(proxy_engine).label))
        )
      end
      local active_status = engines.status(uci, PKG, proxy_engine)
      if not active_status.installed then
        rows[#rows + 1] = "<div style='margin-top:.55rem;color:var(--tpm-warn)'>" .. pcdata(_("Selected proxy engine binary is not installed.")) .. "</div>"
      end
      rows[#rows + 1] = "</div>"
      return table.concat(rows)
    end
  end

  -- Restart button saves UCI/list file and restarts the service.
  do
    local top = m:section(SimpleSection, ""); top.anonymous = true
    local dv = top:option(DummyValue, "_pretitle_restart"); dv.rawhtml = true
    function dv.cfgvalue()
      return string.format([[
<style>
  .tpx-btn-slim{
    display:inline-block !important;
    padding:.25rem .6rem !important;
    line-height:1.15 !important;
    height:auto !important;
    width:auto !important;
    min-width:unset !important;
    white-space:nowrap !important;
  }
  .tpx-btn-slim > span{
    color:var(--tpm-ok);
    font-weight:700;
  }
</style>
<div class="inline-row" style="margin:.25rem 0 .25rem 0">
  <button class="cbi-button cbi-button-reload tpx-btn-slim"
          name="_tproxy_restart" value="1"
          title="%s">
    <span>%s</span>
  </button>
</div>
<script>
(function(){
  var rb = document.querySelector('button[name="_tproxy_restart"]');
  if (rb) rb.addEventListener('click', function(){
    var form = this.form || document.querySelector('form'); if(!form) return;
    var s1 = form.querySelector('input[name="_save_tproxy_main"]');
    if(!s1){ s1 = document.createElement('input'); s1.type='hidden'; s1.name='_save_tproxy_main'; form.appendChild(s1); }
    s1.value = '1';
    var s2 = form.querySelector('input[name="_uniedit_save"]');
    if(!s2){ s2 = document.createElement('input'); s2.type='hidden'; s2.name='_uniedit_save'; form.appendChild(s2); }
    s2.value = '1';
  }, {passive:true});
})();
</script>]]
        ,
        pcdata(_("Save and restart TPROXY")),
        pcdata(_("Restart"))
      )
    end
  end

  -- System log below the restart button.
  do
    local sl  = m:section(SimpleSection)
    local log = sl:option(DummyValue, "_log_tproxy"); log.rawhtml = true
    function log.cfgvalue()
      return "<details><summary><strong>" .. _("System log (logread)") .. "</strong></summary>" ..
             "<div class='box editor-wrap'><pre style='white-space:pre-wrap;max-height:30rem;overflow:auto'>" ..
             pcdata(combined_log()) .. "</pre>" ..
             "<div style='margin-top:.5rem'>" ..
             "<button class='cbi-button cbi-button-action small-btn' style='margin-right:4px; padding:0; border:0' name='_refreshlog_tproxy' value='1'>" .. _("Refresh") .. "</button> " ..
             "<button class='cbi-button cbi-button-remove small-btn' style='padding:0; border:0' name='_clearlog_tproxy' value='1'>" .. _("Clear") .. "</button>" ..
             "</div></div></details>"
    end
    -- Hidden POST buttons.
    local rfr = sl:option(Button, "_refreshlog_tproxy"); rfr.title = ""; rfr.inputtitle = "Refresh"
    rfr.inputstyle = "action"; function rfr.render() end
    function rfr.write(self, section) if not self.map:formvalue(self:cbid(section)) then return end; redirect_here("tproxy") end
    local clr = sl:option(Button, "_clearlog_tproxy"); clr.title = ""; clr.inputtitle = "Clear log"
    clr.inputstyle = "remove"; function clr.render() end
    function clr.write(self, section)
      if not self.map:formvalue(self:cbid(section)) then return end
      if sys.call("/etc/init.d/log restart >/dev/null 2>&1") == 0 then
        set_err(nil)
      else
        set_info(nil); set_err(_("Failed to clear the log."))
      end
      redirect_here("tproxy")
    end
  end

  local main_s = m:section(SimpleSection, _("TPROXY main settings"))

  -- Interfaces (left col)
  do
    local dv = main_s:option(DummyValue, "_ifaces"); dv.rawhtml = true
    function dv.cfgvalue()
      local current = getu("ifaces"):gsub(","," "):gsub("%s+"," ")
      local set = {}; for w in current:gmatch("(%S+)") do set[w]=true end

      local exclude = {}
      uci:foreach("firewall", "zone", function(s)
        if (s.name == "wwan") then
          local secname = s[".name"]
          local nets = uci:get_list("firewall", secname, "network") or {}
          local devs = uci:get_list("firewall", secname, "device") or {}
          for __, d in ipairs(devs) do exclude[d] = true end
          local nm = netm_init
          if nm then
            for __, n in ipairs(nets) do
              local iface = nm:get_interface(n)
              if iface then
                if iface.get_device then
                  local d = iface:get_device()
                  if d and d.name then exclude[d:name()] = true end
                end
                if iface.get_devices then
                  local ds = iface:get_devices()
                  if ds then
                    for __, dv in ipairs(ds) do
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

      local ipv6 = getu("ipv6_enabled")
      local buf = {}
      buf[#buf+1] = string.format(
        "<div class='box'><div style='display:flex;align-items:center;gap:.6rem;margin-bottom:.4rem'>"
          .. "<label style='margin-right:.8rem'><input type='checkbox' name='tpx_ipv6_enabled' value='1' %s/> IPv6</label>"
          .. "<strong>%s</strong></div>",
        (ipv6=="1") and "checked" or "",
        pcdata(_("Interfaces"))
      )

      for __,d in ipairs((sys.net and sys.net.devices and sys.net.devices()) or {}) do
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
      local u_p_all = getu("tproxy_port")
      local u_p_tcp = getu("tproxy_port_tcp")
      local u_p_udp = getu("tproxy_port_udp")
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
        <div class="inline-row"><label><input type="checkbox" id="tpx_split" name="tpx_split" value="1" %s/> %s</label></div>
        <div id="p_all_row" style="margin-top:.25rem"><label>%s:</label>
          <input type="number" id="tpx_port" name="tpx_port" value="%s" min="1" max="65535" step="1" style="width:120px">
        </div>
        <div id="p_tcp_row" style="display:none;margin-top:.25rem"><label>%s:</label>
          <input type="number" id="tpx_port_tcp" name="tpx_port_tcp" value="%s" min="1" max="65535" step="1" style="width:120px">
        </div>
        <div id="p_udp_row" style="display:none;margin-top:.25rem"><label>%s:</label>
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
              if (window.__xray_dirty && !confirm('%s')) { split.checked = !split.checked; return; }
              upd();
            }); }
            upd();
          })();
        </script>
      </div>]]):format(
        split_on and "checked" or "",
        pcdata(_("Split TCP/UDP")),
        pcdata(_("Port")),
        pcdata(p_all),
        pcdata(_("TCP port")),
        pcdata(eff_tcp),
        pcdata(_("UDP port")),
        pcdata(eff_udp),
        pcdata(_("There are unsaved changes. Leave without saving?"))
      )
      return "<div class='col'>" .. right .. "</div></div>"
    end
  end

  -- Modes
  do
    local dv = main_s:option(DummyValue, "_modes"); dv.rawhtml = true
    function dv.cfgvalue()
      local pm = pick_form_or_uci(fval("tpx_port_mode"), getu("port_mode"))
      local sm = pick_form_or_uci(fval("tpx_src_mode"),  getu("src_mode"))
      local function opt(val, cur, title)
        return string.format('<option value="%s"%s>%s</option>', val, (val==cur) and " selected" or "", title)
      end
      return ([[<div class="box">
        <div class="inline-row"><label>%s:</label>
          <select name="tpx_port_mode">%s%s</select>
        </div>
        <div class="inline-row" style="margin-top:.25rem"><label>%s:</label>
          <select id="tpx_src_mode" name="tpx_src_mode">%s%s%s</select>
        </div>
        <script>
        (function(){
          function qs(s){ return document.querySelector(s) }
          function buildUrl(){
            var base = ']].. pcdata(disp.build_url("admin","network","tproxy_manager").."?tab=tproxy") ..[[';
            var pm = (qs('select[name="tpx_port_mode"]')||{}).value || '';
            var sm = (qs('#tpx_src_mode')||{}).value || '';
            var lf = (qs('#unified-editor select[name="list_file"]')||{}).value || '';
            var jf = (qs('#json-editor select[name="json_file"]')||{}).value || '';
            var cf = (qs('#clash-editor select[name="clash_file"]')||{}).value || '';
            var url = base + '&tpx_port_mode=' + encodeURIComponent(pm) + '&tpx_src_mode=' + encodeURIComponent(sm);
            if (lf) url += '&list_file=' + encodeURIComponent(lf);
            if (jf) url += '&json_file=' + encodeURIComponent(jf);
            if (cf) url += '&clash_file=' + encodeURIComponent(cf);
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
        pcdata(_("Port mode")),
        opt("bypass",pm,"bypass"),
        opt("only",pm,"only"),
        pcdata(_("Source mode")),
        opt("off",sm,"off"),
        opt("only",sm,"only"),
        opt("bypass",sm,"bypass")
      )
    end
  end

  -- Unified editor and DHCP picker.
  do
    local se = m:section(SimpleSection, "")
    local dv = se:option(DummyValue, "_uniedit"); dv.rawhtml = true
    function dv.cfgvalue()
      local pmode_form = fval("tpx_port_mode")
      local smode      = pick_form_or_uci(fval("tpx_src_mode"),  getu("src_mode"))
      local pmode      = pick_form_or_uci(pmode_form, getu("port_mode"))

      local ports = getu("ports_file")
      local bv4   = getu("bypass_v4_file")
      local bv6   = getu("bypass_v6_file")
      local so4   = getu("src_only_v4_file")
      local so6   = getu("src_only_v6_file")
      local sb4   = getu("src_bypass_v4_file")
      local sb6   = getu("src_bypass_v6_file")

      local options = {}
      if ports ~= "" then options[#options+1] = {ports, _("Ports").." ("..((pmode and pmode~="") and pmode or "?")..")", "none"} end
      if bv4   ~= "" then options[#options+1] = {bv4,   "bypass IPv4", "none"} end
      if bv6   ~= "" then options[#options+1] = {bv6,   "bypass IPv6", "none"} end
      if so4   ~= "" then options[#options+1] = {so4,   "src only IPv4", "only"} end
      if so6   ~= "" then options[#options+1] = {so6,   "src only IPv6", "only"} end
      if sb4   ~= "" then options[#options+1] = {sb4,   "src bypass IPv4", "bypass"} end
      if sb6   ~= "" then options[#options+1] = {sb6,   "src bypass IPv6", "bypass"} end

      if #options == 0 then
        return "<div class='box editor-wrap' style='color:var(--tpm-muted)'>" .. _("No list file paths are configured in UCI. Set paths in Additional settings.") .. "</div>"
      end

      local chosen = fval("list_file")
      local found=false; for __,o in ipairs(options) do if o[1]==chosen then found=true end end
      if not found then chosen = options[1][1] end

      local function visible_for_mode(kind, sm)
        if kind=="none" then return true end
        if sm=="only"  and kind=="only"  then return true end
        if sm=="bypass" and kind=="bypass" then return true end
        return false
      end
      local chosen_kind = "none"
      for __,o in ipairs(options) do if o[1]==chosen then chosen_kind=o[3] end end
      if not visible_for_mode(chosen_kind, smode) then
        for __,o in ipairs(options) do if visible_for_mode(o[3], smode) then chosen = o[1]; break end end
      end

      local content = read_file(chosen)

      local desc = ""
      if chosen == ports then
        if     pmode == "bypass" then desc = _("Traffic to listed ports goes directly; all other traffic goes through proxy.")
        elseif pmode == "only"   then desc = _("Traffic to listed ports goes through proxy; all other traffic goes directly.")
        else desc = _("Ports file; current port mode is not set in UCI.") end
      elseif chosen == bv4 then desc = _("IPv4 addresses/networks that will not be proxied.")
      elseif chosen == bv6 then desc = _("IPv6 addresses/networks that will not be proxied.")
      elseif chosen == so4 then desc = _("IPv4 sources that will go through proxy.")
      elseif chosen == so6 then desc = _("IPv6 sources that will go through proxy.")
      elseif chosen == sb4 then desc = _("IPv4 sources that will go directly.")
      elseif chosen == sb6 then desc = _("IPv6 sources that will go directly.") end

      local sel = {}
      sel[#sel+1] = "<div id='unified-editor' class='editor-wrap'>"
      sel[#sel+1] = "<div class='inline-row'><label>" .. _("File to edit") .. ":</label><select name='list_file' class='tpm-filesel'>"
      for __,o in ipairs(options) do
        local path, label, kind = o[1], o[2], o[3]
        local selattr = (path == chosen) and " selected" or ""
        local show = (kind=='none') or (smode=='only' and kind=='only') or (smode=='bypass' and kind=='bypass')
        local style = show and "" or " style=\"display:none\""
        sel[#sel+1] = string.format("<option value=\"%s\" data-src-kind=\"%s\"%s%s>%s — %s</option>",
          pcdata(path), pcdata(kind), selattr, style, pcdata(path), pcdata(label))
      end
      sel[#sel+1] = "</select><button class=\"cbi-button cbi-button-apply small-btn\" name=\"_uniedit_save\" value=\"1\">" .. _("Save file") .. "</button></div>"
      sel[#sel+1] = "<div style='margin:.2rem 0 .5rem 0; color:var(--tpm-muted)'>" .. pcdata(desc) .. "</div>"

      sel[#sel+1] = string.format("<textarea name='uniedit_text' rows='16' spellcheck='false' class='tpm-editor'>%s</textarea>", pcdata(content))

      sel[#sel+1] = string.format([[
<div id="uniedit_hint" style="margin-top:.35rem; color:var(--tpm-muted)"></div>
<script>
(function(){
  function qs(s){ return document.querySelector(s) }
  var ta = qs('textarea[name="uniedit_text"]');
  var fileSel = qs('#unified-editor select[name="list_file"]');
  var hint = qs('#uniedit_hint');
  var key = 'uniedit:' + (fileSel ? fileSel.value : '');
  var portsPath = %q; // UCI: main.ports_file

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

  function isPortLine(ln){
    var m = ln.match(/^(?:(tcp|udp|both):)?(\d{1,5})(?:-(\d{1,5}))?$/i);
    if(!m) return false;
    var from = +m[2], to = m[3] ? +m[3] : from;
    if(!(from >= 1 && from <= 65535)) return false;
    if(!(to   >= 1 && to   <= 65535)) return false;
    if(from > to) return false;
    return true;
  }

  function validate(){
    if(!ta||!hint) return;
    var bad = [], portsMode = (fileSel && fileSel.value === portsPath);
    var lines = ta.value.split(/\r?\n/);
    for(var i=0;i<lines.length;i++){
      var ln = (lines[i]||'').trim();
      if(!ln || ln[0]=='#' || ln[0]==';') continue;
      var ok = portsMode ? isPortLine(ln) : (isIPv4(ln) || isIPv4CIDR(ln) || isIPv6(ln) || isIPv6CIDR(ln));
      if(!ok) bad.push((i+1)+': '+ln);
    }
    if(bad.length){
      hint.style.color = 'var(--tpm-warn)';
      hint.innerHTML = (portsMode
        ? ']] .. pcdata(_("Suspicious lines in ports file")) .. [[ ('+bad.length+'):<br><code style="white-space:pre-wrap">'+bad.slice(0,10).join('\\n')+(bad.length>10?'\\n…':'')+'</code><br>]] .. pcdata(_("Expected")) .. [[: <code>80</code>, <code>tcp:443</code>, <code>udp:53</code>, <code>both:123</code>, <code>1000-2000</code>, <code>udp:6000-7000</code>.'
        : ']] .. pcdata(_("Suspicious lines")) .. [[ ('+bad.length+'):<br><code style="white-space:pre-wrap">'+bad.slice(0,10).join('\\n')+(bad.length>10?'\\n…':'')+'</code>');
      ta.style.outline = '2px solid var(--tpm-warn)';
    }else{
      hint.style.color = 'var(--tpm-muted)';
      hint.textContent = portsMode
        ? ']] .. pcdata(_("Ports format is valid: port/range, optionally prefixed with tcp:/udp:/both:.")) .. [['
        : ']] .. pcdata(_("Looks valid: IPv4/IPv6, optionally CIDR. Lines starting with # or ; are ignored.")) .. [[';
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
    var base = ']] .. pcdata(disp.build_url("admin","network","tproxy_manager").."?tab=tproxy") .. [[';
    var pm = (document.querySelector('select[name="tpx_port_mode"]')||{}).value || '';
    var sm = (document.querySelector('#tpx_src_mode')||{}).value || '';
    var jf = (document.querySelector('#json-editor select[name="json_file"]')||{}).value || '';
    var cf = (document.querySelector('#clash-editor select[name="clash_file"]')||{}).value || '';
    var url = base + '&tpx_port_mode=' + encodeURIComponent(pm) + '&tpx_src_mode=' + encodeURIComponent(sm);
    if (jf) url += '&json_file=' + encodeURIComponent(jf);
    if (cf) url += '&clash_file=' + encodeURIComponent(cf);
    url += '&list_file=' + encodeURIComponent(sel.value);
    location.href = url;
  });
  sel.setAttribute('data-prev', sel.value);

  (function(){
    var saveBtn = document.querySelector('button[name="_save_tproxy_main"]');
    if(!saveBtn) return;
    saveBtn.addEventListener('click', function(){
      var form = this.form || document.querySelector('form'); if(!form) return;
      var a = form.querySelector('input[name="_save_tproxy_main"]');
      if(!a){ a = document.createElement('input'); a.type='hidden'; a.name='_save_tproxy_main'; form.appendChild(a); }
      a.value = '1';
      var b = form.querySelector('input[name="_uniedit_save"]');
      if(!b){ b = document.createElement('input'); b.type='hidden'; b.name='_uniedit_save'; form.appendChild(b); }
      b.value = '1';
    }, {passive:true});
  })();

})();
</script>]], ports)

      -- DHCP leases picker
      local leases = {}
      for line in (read_file("/tmp/dhcp.leases").."\n"):gmatch("([^\n]*)\n") do
        local ts, mac, ip, host = line:match("^(%d+)%s+(%S+)%s+(%S+)%s+(%S+)")
        if ip and ip:match("^%d+%.%d+%.%d+%.%d+$") then
          leases[#leases+1] = { ip = ip, mac = mac, host = (host and host ~= "*" and host) or "" }
        end
      end
      sel[#sel+1] = "<details style='margin-top:.6rem'><summary style='cursor:pointer;font-weight:600'>" .. _("DHCP leases (quick add to src only/bypass v4)") .. "</summary>"
      sel[#sel+1] = "<div class='box' style='margin-top:.4rem'>"
      if #leases == 0 then
        sel[#sel+1] = "<div style='color:var(--tpm-muted)'>" .. _("No active leases.") .. "</div>"
      else
        sel[#sel+1] = "<div class='tpm-tablewrap'><table class='leases-table tpm-cards'><colgroup><col class='col-ip'><col class='col-host'><col class='col-mac'><col class='col-act'></colgroup><thead><tr><th>IP</th><th>" .. _("Name") .. "</th><th>MAC</th><th>" .. _("Actions") .. "</th></tr></thead><tbody>"
        for __, r in ipairs(leases) do
          sel[#sel+1] = string.format(
            "<tr><td data-th='IP'><code>%s</code></td><td data-th='" .. _("Name") .. "'>%s</td><td data-th='MAC'><code>%s</code></td>" ..
            "<td>" ..
            "<button class='cbi-button cbi-button-apply small-btn' name='_dhcp_add_only' value='%s' onclick='return window.__xray_guard?window.__xray_guard():true'>+ only</button> " ..
            "<button class='cbi-button cbi-button-action small-btn' name='_dhcp_add_bypass' value='%s' onclick='return window.__xray_guard?window.__xray_guard():true'>+ bypass</button>" ..
            "</td></tr>",
            pcdata(r.ip), pcdata(r.host or ""), pcdata(r.mac or ""), pcdata(r.ip), pcdata(r.ip)
          )
        end
        sel[#sel+1] = "</tbody></table></div>"
      end
      sel[#sel+1] = "</div></details>"

      sel[#sel+1] = "</div>"
      return table.concat(sel, "\n")
    end
  end

  -- Advanced
  do
    local dv = m:section(SimpleSection, _("Additional settings (collapsed panel)")):option(DummyValue, "_advanced")
    dv.rawhtml = true
    function dv.cfgvalue()
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
        <summary><strong>%s</strong></summary>
        <div style="display:grid;grid-template-columns:minmax(220px, 360px) 1fr;gap:.35rem .6rem;align-items:center">
          <label>%s</label><input type="checkbox" name="tpx_log_enabled" value="1" %s>

          <label>nft_table</label><input type="text" name="tpx_nft_table" value="%s">
          <label>fwmark_tcp</label><input type="text" name="tpx_fwmark_tcp" value="%s">
          <label>fwmark_udp</label><input type="text" name="tpx_fwmark_udp" value="%s">
          <label>rttab_tcp</label><input type="text" name="tpx_rttab_tcp" value="%s">
          <label>rttab_udp</label><input type="text" name="tpx_rttab_udp" value="%s">

          <label>ports_file</label><input type="text" name="tpx_ports_file" value="%s" title="%s">
          <label>bypass_v4_file</label><input type="text" name="tpx_bypass_v4_file" value="%s" title="%s">
          <label>bypass_v6_file</label><input type="text" name="tpx_bypass_v6_file" value="%s" title="%s">

          <label>src_only_v4_file</label><input type="text" name="tpx_src_only_v4_file" value="%s" title="%s">
          <label>src_only_v6_file</label><input type="text" name="tpx_src_only_v6_file" value="%s" title="%s">
          <label>src_bypass_v4_file</label><input type="text" name="tpx_src_bypass_v4_file" value="%s" title="%s">
          <label>src_bypass_v6_file</label><input type="text" name="tpx_src_bypass_v6_file" value="%s" title="%s">
        </div>
      </details></div]]):format(
        pcdata(_("Expand/collapse advanced parameters")),
        pcdata(_("Logging")),
        (loge=="1") and "checked" or "",
        pcdata(nft), pcdata(fwt), pcdata(fwu), pcdata(rtt), pcdata(rtu),
        pcdata(ports_file), pcdata(ports_file), pcdata(bypass_v4), pcdata(bypass_v4), pcdata(bypass_v6), pcdata(bypass_v6),
        pcdata(src_o4), pcdata(src_o4), pcdata(src_o6), pcdata(src_o6), pcdata(src_b4), pcdata(src_b4), pcdata(src_b6), pcdata(src_b6)
      )
    end
  end

  -- Backup / Restore handlers (apply/cancel act on an already-uploaded
  -- pending import; the upload itself happens on a separate controller
  -- action - see luci/controller/tproxy_manager.lua - because it needs to
  -- register its own setfilehandler before this page's very first
  -- http.formvalue() call, which already happens in manage.lua before this
  -- module even runs.)
  -- CSRF gate for the two handlers that actually mutate /etc. LuCI's own
  -- test_post_security() does not run for this page (its form() target only
  -- arms it when cbi.submit is present), so a cross-site POST carrying just
  -- _backup_apply=1 + a guessed backup_token would otherwise bypass the
  -- whole review-before-apply step. Checked against the same
  -- disp.context.authtoken the upload form embeds.
  -- formvalue() returns a TABLE when a field arrives more than once. Comparing
  -- that against a string is always false, so a duplicated token would read as
  -- a forged one; accept it when every submitted copy matches.
  local function backup_csrf_ok()
    local expected = tostring((disp.context and disp.context.authtoken) or "")
    if expected == "" then return false end
    local given = http.formvalue("token")
    if type(given) == "table" then
      if #given == 0 then return false end
      for __, v in ipairs(given) do
        if v ~= expected then return false end
      end
      return true
    end
    return given == expected
  end

  -- Recovery from a transaction that was interrupted mid-apply. The snapshot
  -- store survives (it lives on persistent storage and carries a KEEP marker),
  -- but until now nothing could act on it from the UI: the files stayed
  -- half-written and the only record sat in a directory nobody looks at.
  if http.formvalue("_rollback_recover") ~= nil then
    if not backup_csrf_ok() then
      set_info(nil); set_err(_("Request was rejected: invalid or missing CSRF token."))
    else
      local dir = trim(http.formvalue("_rollback_recover"))
      local ok_r, failed = utils.rollback_recover(dir)
      if ok_r then
        set_err(nil)
        set_info(_("The interrupted change was rolled back; the previous state is restored."))
      else
        set_info(nil)
        set_err(string.format(
          _("Could not restore the previous state of: %s. The snapshot is kept at %s."),
          table.concat(failed or {}, ", "), dir))
      end
    end
    redirect_here("tproxy"); return m
  end

  if http.formvalue("_rollback_discard") ~= nil then
    if not backup_csrf_ok() then
      set_info(nil); set_err(_("Request was rejected: invalid or missing CSRF token."))
    elseif utils.rollback_discard(trim(http.formvalue("_rollback_discard"))) then
      set_err(nil); set_info(_("The kept snapshot was discarded; the current state is left as it is."))
    else
      set_info(nil); set_err(_("Failed to save settings."))
    end
    redirect_here("tproxy"); return m
  end

  if http.formvalue("_backup_apply") == "1" then
    if not backup_csrf_ok() then
      set_info(nil)
      set_err(_("Session validation failed, please reload this page and try again."))
      redirect_here("tproxy")
      return m
    end
    local token = trim(http.formvalue("backup_token") or "")
    local ok, touched_or_err, perm_warning = backup.apply(token)
    if ok then
      -- Report only services that actually came back up, and surface the
      -- ones that failed separately: a restored config paired with a dead
      -- engine is exactly the state the admin must not mistake for success.
      local restarted, failed = {}, {}
      local function restart_service(flag, script, label)
        if not flag then return end
        if sys.call(string.format("[ -x %s ] && %s restart >/dev/null 2>&1", script, script)) == 0 then
          restarted[#restarted + 1] = label
        else
          failed[#failed + 1] = label
        end
      end
      restart_service(touched_or_err.core, "/etc/init.d/tproxy-manager", "TPROXY")
      restart_service(touched_or_err.watchdog, "/etc/init.d/tproxy-manager-watchdog", "Watchdog")
      restart_service(touched_or_err.xray, "/etc/init.d/xray", "Xray")
      restart_service(touched_or_err.mihomo, "/etc/init.d/tproxy-manager-mihomo", "Mihomo")
      restart_service(touched_or_err.singbox, "/etc/init.d/tproxy-manager-sing-box", "sing-box")
      restart_service(touched_or_err.geo, "/etc/init.d/cron", "cron")

      local msg = string.format(
        _("Backup restored. Restarted: %s"),
        #restarted > 0 and table.concat(restarted, ", ") or _("nothing (no service-affecting changes)")
      )
      -- The permissions warning is a real, actionable outcome of the
      -- restore: files were written but could not be locked down. It used
      -- to be returned and then dropped on the floor here.
      if perm_warning and perm_warning ~= "" then
        msg = msg .. "\n" .. string.format(_("Warning: %s"), perm_warning)
      end
      if #failed > 0 then
        set_info(nil)
        set_err(msg .. "\n" .. string.format(_("Failed to restart: %s"), table.concat(failed, ", ")))
      elseif perm_warning and perm_warning ~= "" then
        set_info(nil)
        set_err(msg)
      else
        set_err(nil)
        set_info(msg)
      end
    else
      set_info(nil)
      set_err(touched_or_err or _("Failed to restore backup."))
    end
    redirect_here("tproxy")
    return m
  end
  if http.formvalue("_backup_cancel") == "1" then
    if not backup_csrf_ok() then
      set_info(nil)
      set_err(_("Session validation failed, please reload this page and try again."))
      redirect_here("tproxy")
      return m
    end
    backup.cancel(trim(http.formvalue("backup_token") or ""))
    set_err(nil)
    set_info(_("Backup restore cancelled."))
    redirect_here("tproxy")
    return m
  end

  -- Backup / Restore UI
  do
    local function render_uci_diff(u)
      local rows = {}
      for __, e in ipairs(u.changed) do
        rows[#rows + 1] = string.format(
          "<div class='bkdiff-kv'><code>%s</code>: <span class='bkdiff-del'>%s</span> &rarr; <span class='bkdiff-add'>%s</span></div>",
          pcdata(e.key), pcdata(e.old), pcdata(e.new))
      end
      for __, e in ipairs(u.added) do
        rows[#rows + 1] = string.format(
          "<div class='bkdiff-kv'><code>%s</code>: <span class='bkdiff-add'>%s</span> (%s)</div>",
          pcdata(e.key), pcdata(e.new), pcdata(_("new")))
      end
      for __, e in ipairs(u.removed) do
        -- UCI is restored as an exact snapshot (unlike files, which are
        -- never deleted just for being absent from the backup) - an option
        -- missing from the backup really will be removed by Apply.
        rows[#rows + 1] = string.format(
          "<div class='bkdiff-kv'><code>%s</code>: %s (%s)</div>",
          pcdata(e.key), pcdata(e.old), pcdata(_("will be removed")))
      end
      return table.concat(rows)
    end

    local function render_file_diff(f)
      if f.status == "added" then
        return "<div class='bkdiff-file'><code>" .. pcdata(f.path) .. "</code> &mdash; " ..
          pcdata(_("new file, will be created")) .. "</div>"
      end
      if f.status == "removed" then
        return "<div class='bkdiff-file'><code>" .. pcdata(f.path) .. "</code> &mdash; " ..
          pcdata(_("not part of this backup, will be left untouched")) .. "</div>"
      end
      if not f.diff then
        return "<div class='bkdiff-file'><code>" .. pcdata(f.path) .. "</code> &mdash; " ..
          pcdata(string.format(_("changed (%d -> %d lines, too large to show inline)"), f.old_lines or 0, f.new_lines or 0)) ..
          "</div>"
      end
      local rows = {}
      for __, tok in ipairs(f.diff) do
        if tok.tag ~= "same" then
          rows[#rows + 1] = "<div class='" .. backup_diff_line_class(tok.tag) .. "'>" ..
            (tok.tag == "add" and "+ " or "- ") .. pcdata(tok.text) .. "</div>"
        end
      end
      if #rows == 0 then return "" end
      return "<div class='bkdiff-file'><code>" .. pcdata(f.path) .. "</code><div class='bkdiff-lines'>" ..
        table.concat(rows) .. "</div></div>"
    end

    local function render_backup_diff(diff, token)
      local total = 0
      local sections = {}
      for __, id in ipairs(diff.order) do
        local mod = diff.modules[id]
        local uci_html = render_uci_diff(mod.uci)
        local file_parts = {}
        -- "removed" files are shown but not counted: Apply leaves them exactly
        -- as they are, so counting them would advertise changes that this
        -- restore never makes.
        local applied_files = 0
        for __, f in ipairs(mod.files) do
          local html = render_file_diff(f)
          if html ~= "" then
            file_parts[#file_parts + 1] = html
            if f.status ~= "removed" then applied_files = applied_files + 1 end
          end
        end
        local n = #mod.uci.changed + #mod.uci.added + #mod.uci.removed + applied_files
        if n > 0 then
          total = total + n
          sections[#sections + 1] = string.format(
            "<details class='bkdiff-mod' open><summary>%s (%d)</summary>%s%s</details>",
            pcdata(BACKUP_MODULE_LABELS[id] or id), n, uci_html, table.concat(file_parts)
          )
        end
      end

      -- ONLY the pending-import id. The CSRF token is already emitted by the
      -- enclosing CBI form, and adding a second field with the same name made
      -- the browser submit `token` twice: http.formvalue("token") then returns a
      -- table, LuCI's own check compares it against a string, and every click
      -- died with "the submitted security token is invalid or already expired".
      -- curl tests sent a single value and never reproduced it.
      local hidden_token = string.format(
        "<input type='hidden' name='backup_token' value='%s'>", pcdata(token))

      if total == 0 then
        return string.format(
          "<div class='msg info' style='margin-top:.5rem'>%s<div style='margin-top:.4rem'>%s" ..
          "<button class='cbi-button' name='_backup_cancel' value='1'>%s</button></div></div>",
          pcdata(_("No differences found - current settings already match this backup.")),
          hidden_token, pcdata(_("Close"))
        )
      end

      return string.format([[<div class='box editor-wrap' style='margin-top:.5rem'>
        <p><strong>%s</strong></p>
        %s
        <div style="margin-top:.6rem">
          %s
          <button class="cbi-button cbi-button-apply" name="_backup_apply" value="1"
            onclick="return confirm('%s')">%s</button>
          <button class="cbi-button cbi-button-reset" name="_backup_cancel" value="1">%s</button>
        </div>
      </div>]],
        pcdata(string.format(_("%d change(s) will be applied:"), total)),
        table.concat(sections),
        hidden_token,
        pcdata(_("Apply this backup? Current settings shown above will be overwritten.")),
        pcdata(_("Apply")),
        pcdata(_("Cancel"))
      )
    end

    local sec = m:section(SimpleSection)
    local dv = sec:option(DummyValue, "_backup"); dv.rawhtml = true
    function dv.cfgvalue()
      backup.cleanup_stale()

      -- Interrupted transactions are surfaced here, with their manifest and the
      -- two actions that resolve them. Detection is also logged, so an operator
      -- who never opens this page still finds out.
      local orphan_html = ""
      do
        local orphans = utils.rollback_orphans()
        if #orphans > 0 then
          local parts = {}
          for _idx, o in ipairs(orphans) do
            local files = {}
            for _fi, f in ipairs(o.files) do
              files[#files + 1] = "<div class='bkdiff-file'><code>" .. pcdata(f.path) .. "</code>" ..
                (f.exists and "" or (" &mdash; " .. pcdata(_("was absent")))) .. "</div>"
            end
            parts[#parts + 1] = string.format(
              "<div class='box' style='margin:.4rem 0'><div><strong>%s</strong></div>" ..
              "<div style='font-size:.85em;margin:.2rem 0'><code>%s</code></div>" ..
              "<div style='font-size:.9em;margin:.2rem 0'>%s</div>%s" ..
              "<div class='inline-row' style='margin-top:.4rem'>" ..
              "<button class='cbi-button cbi-button-apply' name='_rollback_recover' value='%s'>%s</button>" ..
              "<button class='cbi-button cbi-button-remove' name='_rollback_discard' value='%s'" ..
              " onclick=\"return confirm('%s')\">%s</button></div></div>",
              pcdata(_("An earlier change was interrupted before it finished")),
              pcdata(o.dir), pcdata(o.reason or ""), table.concat(files),
              pcdata(o.dir), pcdata(_("Restore the previous state")),
              pcdata(o.dir), pcdata(_("Discard the kept snapshot and keep the current state?")),
              pcdata(_("Discard")))
          end
          orphan_html = "<div class='msg err' style='margin-top:.5rem'>" ..
            pcdata(_("These files may be half-written. Restore the previous state, or discard the snapshot to keep what is on disk now.")) ..
            "</div>" .. table.concat(parts)
        end
      end

      local token = trim(fval("backup_token") or "")
      local export_url = disp.build_url("admin", "network", "tproxy_manager_backup_export")
      local upload_url = disp.build_url("admin", "network", "tproxy_manager_backup_upload")

      local diff_html = ""
      if token ~= "" then
        local diff, err = backup.diff(token)
        diff_html = diff and render_backup_diff(diff, token)
          or ("<div class='msg err' style='margin-top:.5rem'>" ..
              pcdata(err or _("Pending import not found or expired.")) .. "</div>")
      end

      -- The interrupted-transaction warning is emitted OUTSIDE the collapsed
      -- <details>: it describes files that may be half-written right now, and a
      -- warning nobody sees until they expand a section is not a warning.
      return orphan_html .. string.format([[<div id="backup-wrap"><details>
        <summary><strong>%s</strong></summary>
        <style>
          .bkdiff-mod{margin:var(--tpm-1) 0;padding:var(--tpm-1) var(--tpm-3);border:1px solid var(--tpm-line);border-radius:.4rem}
          .bkdiff-mod summary{cursor:pointer;font-weight:600}
          .bkdiff-kv{font-family:var(--tpm-mono);font-size:var(--tpm-fs-code);margin:.15rem 0}
          .bkdiff-file{margin:var(--tpm-2) 0}
          .bkdiff-file code{font-size:var(--tpm-fs-code)}
          .bkdiff-lines{font-family:var(--tpm-mono);font-size:var(--tpm-fs-meta);white-space:pre-wrap;background:var(--tpm-neutral-tint);border-radius:.3rem;padding:var(--tpm-1) var(--tpm-2);margin-top:var(--tpm-1)}
          .bkdiff-add{color:var(--tpm-ok);background:var(--tpm-ok-tint)}
          .bkdiff-del{color:var(--tpm-bad);background:var(--tpm-bad-tint)}
        </style>
        <div style="padding:.4rem 0">
          <p class="cbi-value-description">%s</p>
          <a class="cbi-button cbi-button-action" href="%s">%s</a>
          <a class="cbi-button cbi-button-action" href="%s"
             onclick="return (window.__xray_guard?window.__xray_guard():true)">%s</a>
          %s
        </div>
      </details></div>]],
        pcdata(_("Backup / Restore")),
        pcdata(_("Export a full backup of TPROXY, engine configs, GEO sources and Watchdog data, or restore one after reviewing exactly what would change.")),
        pcdata(export_url), pcdata(_("Export backup")),
        pcdata(upload_url), pcdata(_("Import backup...")),
        diff_html
      )
    end
  end

  -- report_quick_add: turns append_line_unique's outcome into a banner. The
  -- four cases are genuinely different to the user — a duplicate is not an
  -- error, but it is also not "added", and a failed write must never read as
  -- either.
  local function report_quick_add(state, ip, path, added_msg)
    if state == "added" then
      set_err(nil); set_info(added_msg)
    elseif state == "exists" then
      set_err(nil)
      set_info(string.format(_("%s is already listed in %s"), ip, path))
    elseif state == "permissions" then
      set_info(nil)
      set_err(added_msg .. "\n" ..
        _("Settings saved, but the configuration file permissions could not be secured."))
    else
      set_info(nil)
      set_err(string.format(_("Failed to add %s to %s"), ip, path))
    end
  end

  -- Save handlers (TPROXY) + DHCP quick add + restart
  local function save_tproxy_main()
    -- "Cancel changes" must be handled here, next to the other buttons that are
    -- emitted as raw markup. Routing it through the CBI Button option below
    -- never worked: that option's render() is disabled, so no `cbid.*` field is
    -- submitted, CBI's parse never calls its write(), and the POST fell through
    -- to a plain re-render — which repopulates every input from the request
    -- body, leaving the edits the user just asked to drop still on screen.
    -- Redirecting turns the POST into a clean GET that reads UCI again.
    if http.formvalue("_cancel_tproxy_main") == "1" then
      set_err(nil); set_info(nil)
      redirect_here("tproxy"); return
    end

    -- DHCP quick add
    local ip_only  = http.formvalue("_dhcp_add_only")
    local ip_bypass= http.formvalue("_dhcp_add_bypass")
    if ip_only and ip_only ~= "" then
      if not is_ipv4(ip_only) then
        set_err(_("DHCP quick-add: invalid IPv4 address."))
        redirect_here("tproxy"); return
      end
      local path = getu("src_only_v4_file")
      if path ~= "" then
        report_quick_add(append_line_unique(path, ip_only), ip_only, path,
          string.format(_("Added %s to src_only_v4_file: %s"), ip_only, path))
      end
      redirect_here("tproxy"); return
    end
    if ip_bypass and ip_bypass ~= "" then
      if not is_ipv4(ip_bypass) then
        set_err(_("DHCP quick-add: invalid IPv4 address."))
        redirect_here("tproxy"); return
      end
      local path = getu("src_bypass_v4_file")
      if path ~= "" then
        report_quick_add(append_line_unique(path, ip_bypass), ip_bypass, path,
          string.format(_("Added %s to src_bypass_v4_file: %s"), ip_bypass, path))
      end
      redirect_here("tproxy"); return
    end

    local want_save    = http.formvalue("_save_tproxy_main") == "1"
    local want_file    = (http.formvalue("_uniedit_save") == "1") or (http.formvalue("_save_tproxy_main") == "1")
    local want_restart = http.formvalue("_tproxy_restart") == "1"

    if want_save then
      local nft_table = trim(http.formvalue("tpx_nft_table"))
      local fwmark_tcp = trim(http.formvalue("tpx_fwmark_tcp"))
      local fwmark_udp = trim(http.formvalue("tpx_fwmark_udp"))
      local rttab_tcp = trim(http.formvalue("tpx_rttab_tcp"))
      local rttab_udp = trim(http.formvalue("tpx_rttab_udp"))
      local path_fields = {
        ports_file = trim(http.formvalue("tpx_ports_file")),
        bypass_v4_file = trim(http.formvalue("tpx_bypass_v4_file")),
        bypass_v6_file = trim(http.formvalue("tpx_bypass_v6_file")),
        src_only_v4_file = trim(http.formvalue("tpx_src_only_v4_file")),
        src_only_v6_file = trim(http.formvalue("tpx_src_only_v6_file")),
        src_bypass_v4_file = trim(http.formvalue("tpx_src_bypass_v4_file")),
        src_bypass_v6_file = trim(http.formvalue("tpx_src_bypass_v6_file")),
      }
      local split = http.formvalue("tpx_split") ~= nil
      if split then
        local pt = http.formvalue("tpx_port_tcp") or ""
        local pu = http.formvalue("tpx_port_udp") or ""
        if not (is_port(pt) and is_port(pu)) then
          set_err(_("TCP/UDP split is enabled: both ports must be set in range 1..65535."))
          return
        end
      else
        local p = http.formvalue("tpx_port") or ""
        if not is_port(p) then
          set_err(_("Common port is required (1..65535)."))
          return
        end
      end

      if not is_nft_table_name(nft_table) then
        set_err(_("Invalid nft_table name. Use a safe name, for example tp_mgr."))
        return
      end
      if not is_fwmark(fwmark_tcp) or not is_fwmark(fwmark_udp) then
        set_err(_("fwmark_tcp/fwmark_udp must be decimal numbers or hex values like 0x1."))
        return
      end
      if not is_uint(rttab_tcp, 1) or not is_uint(rttab_udp, 1) then
        set_err(_("rttab_tcp/rttab_udp must be positive integers."))
        return
      end
      for key, path in pairs(path_fields) do
        if not is_abs_path(path) then
          set_err(_("Invalid path for").." " .. key .. _(". Expected an absolute path without extra whitespace."))
          return
        end
      end

      set_err(nil)

      -- Every staged change is recorded from the FIRST one on. Previously the
      -- accounting started only at the block below, so a failure in the
      -- interface, port or mode fields was committed as a half-formed
      -- configuration and still reported as saved.
      local stage_ok = true
      local function S(k,v)
        if not utils.uci_stage(uci, PKG, "main", k, v) then stage_ok = false end
      end
      local function D(k)
        if not utils.uci_unset(uci, PKG, "main", k) then stage_ok = false end
      end

      if not uci:section(PKG,"main","main",{}) then stage_ok = false end
      S("log_enabled", http.formvalue("tpx_log_enabled") and "1" or "0")

      local selected = {}
      for __,d in ipairs((sys.net and sys.net.devices and sys.net.devices()) or {}) do
        if d ~= "lo" and not d:match("^wwan") and http.formvalue("tpx_if_"..d) then selected[#selected+1]=d end
      end
      for __, iface in ipairs(selected) do
        if not is_iface_name(iface) then
          set_err(_("Invalid interface name:").." " .. tostring(iface))
          return
        end
      end
      S("ifaces", #selected > 0 and table.concat(selected," ") or nil)
      S("ipv6_enabled", http.formvalue("tpx_ipv6_enabled") and "1" or "0")

      if split then
        S("tproxy_port_tcp", http.formvalue("tpx_port_tcp"))
        S("tproxy_port_udp", http.formvalue("tpx_port_udp"))
        local p = http.formvalue("tpx_port")
        if p and p~="" then S("tproxy_port", p) end
      else
        S("tproxy_port", http.formvalue("tpx_port"))
        D("tproxy_port_tcp")
        D("tproxy_port_udp")
      end

      local pm = fval("tpx_port_mode")
      S("port_mode", (pm == "bypass" or pm == "only") and pm or nil)

      local sm = fval("tpx_src_mode")
      S("src_mode", (sm == "off" or sm == "only" or sm == "bypass") and sm or nil)

      S("nft_table", nft_table)
      S("fwmark_tcp", fwmark_tcp)
      S("fwmark_udp", fwmark_udp)
      S("rttab_tcp",  rttab_tcp)
      S("rttab_udp",  rttab_udp)
      S("ports_file", path_fields.ports_file)
      S("bypass_v4_file", path_fields.bypass_v4_file)
      S("bypass_v6_file", path_fields.bypass_v6_file)
      S("src_only_v4_file", path_fields.src_only_v4_file)
      S("src_only_v6_file", path_fields.src_only_v6_file)
      S("src_bypass_v4_file", path_fields.src_bypass_v4_file)
      S("src_bypass_v6_file", path_fields.src_bypass_v6_file)
      if engines then
        -- The engine profile is part of the same save: staging it silently
        -- meant a failure here was committed together with everything else.
        if not engines.save_legacy_to_profile(uci, PKG, proxy_engine) then
          stage_ok = false
        end
      end

      if not stage_ok then
        uci:revert(PKG)
        set_info(nil)
        set_err(_("Failed to save settings."))
        redirect_here("tproxy")
        return
      end
      local ok_commit, why = utils.commit_uci(uci, PKG)
      if ok_commit then
        set_info(_("TPROXY settings saved"))
      elseif why == "permissions" then
        set_info(nil)
        set_err(_("Settings saved, but the configuration file permissions could not be secured."))
      else
        -- Not committed: do not claim success and do not let the caller go
        -- on to restart services with a config that was never written.
        set_info(nil)
        set_err(_("Failed to save settings."))
        redirect_here("tproxy")
        return
      end
    end

    if want_file then
      local path = http.formvalue("list_file") or fval_last("list_file")
      -- Only allow saving to one of the paths that are actually configured
      -- in UCI for this module (the same set shown in the editor's dropdown)
      -- — otherwise a direct POST request with an arbitrary list_file could
      -- write to any file on the router.
      local allowed_list_files = {
        getu("ports_file"),
        getu("bypass_v4_file"),
        getu("bypass_v6_file"),
        getu("src_only_v4_file"),
        getu("src_only_v6_file"),
        getu("src_bypass_v4_file"),
        getu("src_bypass_v6_file"),
      }
      local is_allowed = false
      if path and path ~= "" then
        for __, p in ipairs(allowed_list_files) do
          if p ~= "" and p == path then is_allowed = true; break end
        end
      end
      if is_allowed then
        local text = http.formvalue("uniedit_text") or ""
        -- Result is checked instead of assumed: "permissions" means the
        -- file IS saved and only its mode could not be set, so it must not
        -- be reported as a failed save.
        local wrote, wwhy = write_file(path, text)
        if wrote then
          set_err(nil)
          set_info(_("List file saved:").." " .. path)
        elseif wwhy == "permissions" then
          set_info(nil)
          set_err(_("Settings saved, but the configuration file permissions could not be secured."))
        else
          set_info(nil)
          set_err(_("Failed to save settings."))
        end
        -- No unconditional set_err(nil) here: it used to run right after
        -- the branch above and wiped the write/permission error that had
        -- just been set, so a failed save still looked clean to the user.
      elseif path and path ~= "" then
        set_err(_("Invalid list_file: not one of the configured list paths."))
      end
    end

    if want_restart then
      -- Both results were discarded, so a configuration that fails validation
      -- or a start that cannot bind still reported "service restarted" while
      -- nothing had been applied. `start` is the one that matters: it validates
      -- the lists, builds the nft ruleset and installs the policy rules, and its
      -- output carries the reason it refused.
      sys.call("/etc/init.d/tproxy-manager stop >/dev/null 2>&1")
      local marker = "__TPM_RC__:"
      local out = sys.exec(string.format(
        "(/etc/init.d/tproxy-manager start) 2>&1; printf '\\n%s%%s' \"$?\"", marker)) or ""
      local rc = tonumber(out:match(marker .. "([%-%d]+)%s*$")) or 1
      out = trim((out:gsub("\n?" .. marker .. "[%-%d]+%s*$", "")))
      if rc == 0 then
        set_err(nil)
        set_info(_("TPROXY: service restarted"))
      else
        -- The service's own diagnostics are shown verbatim: they name the file
        -- and line of an invalid list entry, which no generic message could.
        set_info(nil)
        set_err(_("TPROXY: the service did not start; the saved configuration is not applied.") ..
          (out ~= "" and ("\n" .. out) or ""))
      end
      redirect_here("tproxy"); return
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
  <button class="cbi-button cbi-button-apply" name="_save_tproxy_main" value="1">]] .. pcdata(_("Save TPROXY settings")) .. [[</button>
  <button class="cbi-button cbi-button-reset" name="_cancel_tproxy_main" value="1">]] .. pcdata(_("Cancel changes")) .. [[</button>
</div>]]
    end
    -- Both buttons are the raw markup above and are handled by
    -- save_tproxy_main(). There used to be CBI Button options here whose write()
    -- was supposed to do the redirect, but with render() disabled no `cbid.*`
    -- field reaches the request, so CBI never called them.
  end

  -- The shared err/info banner is already rendered by manage.lua at the
  -- bottom of the page (single render point for all tabs, see "Messages are
  -- rendered at the bottom to keep module layout stable") — rendering it
  -- again here only duplicated the same message twice on screen.
end

return { render = render }
