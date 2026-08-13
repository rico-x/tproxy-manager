local cbi = require "luci.cbi"
local SimpleSection, DummyValue, Button = cbi.SimpleSection, cbi.DummyValue, cbi.Button

-- Local Mihomo-specific helpers.
local fs   = require "nixio.fs"
local sys  = require "luci.sys"
local http = require "luci.http"
local disp = require "luci.dispatcher"
local xml  = require "luci.xml"
local utils = require "luci.model.cbi.tproxy_manager.utils"
local _ = require "luci.model.cbi.tproxy_manager.i18n"
local pcdata = xml.pcdata

local MIHOMO_DIR      = "/etc/mihomo"
local MIHOMO_TEST_LOG = "/tmp/tproxy_manager_mihomo_test.log"
local MIHOMO_VERSION_SCRIPT = "/usr/bin/tproxy-manager-mihomo-version.lua"

local function get_mihomo_bin()
  if fs.access("/usr/bin/mihomo") then return "/usr/bin/mihomo"
  elseif fs.access("/usr/sbin/mihomo") then return "/usr/sbin/mihomo"
  else return "mihomo" end
end
local MIHOMO_BIN = get_mihomo_bin()

local read_file = utils.read_file
local write_file = utils.write_file

local function run_cmd_capture(cmd)
  local marker = "__TPM_MIHOMO_RC__:"
  local wrapped = string.format("(%s) 2>&1; printf '\\n%s%%s' \"$?\"", cmd, marker)
  local out = sys.exec(wrapped) or ""
  local rc = tonumber(out:match(marker .. "([%-%d]+)%s*$")) or 1
  out = out:gsub("\n?" .. marker .. "[%-%d]+%s*$", "")
  return rc, utils.trim(out)
end

local function run_mihomo_version(args)
  local parts = { utils.shellescape(MIHOMO_VERSION_SCRIPT) }
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

local function validate_mihomo_text(text, edit_dir, filename)
  if edit_dir ~= MIHOMO_DIR then
    local shadow = utils.private_dir("/tmp", "tpm-mihomo-check")
    if not shadow then return false end
    local copied = sys.call(string.format("cp -a %s/. %s/ >/dev/null 2>&1",
      utils.shellescape(edit_dir), utils.shellescape(shadow))) == 0
    local wrote = copied and write_file(shadow .. "/" .. filename, text or "")
    local assembled = shadow .. "/assembled.yaml"
    local cmd = string.format(
      "TPM_CONFIG_DIR_OVERRIDE=%s TPM_ASSEMBLED_OVERRIDE=%s TPM_MIHOMO_WORKDIR_OVERRIDE=%s %s mihomo --check >%s 2>&1",
      utils.shellescape(shadow), utils.shellescape(assembled), utils.shellescape(MIHOMO_DIR),
      utils.shellescape("/usr/libexec/tproxy-manager/assemble-config"), utils.shellescape(MIHOMO_TEST_LOG))
    local ok = wrote and sys.call(cmd) == 0
    sys.call("rm -rf " .. utils.shellescape(shadow) .. " >/dev/null 2>&1")
    return ok
  end
  local tmp = string.format("/tmp/tproxy-manager-mihomo-check.%d.yaml", math.random(1, 10^9))
  if not write_file(tmp, text or "") then return false end
  local cmd = string.format(
    "SAFE_PATHS=%q %s -d %q -t -f %q >%s 2>&1",
    MIHOMO_DIR,
    MIHOMO_BIN,
    MIHOMO_DIR,
    tmp,
    MIHOMO_TEST_LOG
  )
  local ok = sys.call(cmd) == 0
  fs.remove(tmp)
  return ok
end

-- Only *.yaml files are supported, not *.yml.
local function list_yaml(dir)
  local t, it = {}, fs.dir(dir)
  if it then
    for name in it do
      if name:match("%.yaml$") then t[#t+1] = name end
    end
  end
  table.sort(t)
  return t
end

local function ensure_parent(path)
  local dir = tostring(path or ""):match("^(.*)/[^/]+$")
  if dir and dir ~= "" then utils.ensure_dir(dir) end
end

local function build_managed_config(ctx)
  local links_file = ctx.uci:get(ctx.PKG, "main", "watchdog_links_file") or "/etc/tproxy-manager/watchdog.links"
  -- This is the package's only writable Mihomo file. Older releases replaced
  -- the whole profile and could destroy a hand-written configuration; role
  -- fragments keep every user-owned file outside this write path.
  local managed_file = ctx.uci:get(ctx.PKG, "main", "mihomo_profile_managed_file")
    or ctx.uci:get(ctx.PKG, "main", "mihomo_profile_managed_provider_file")
    or "/etc/mihomo/tproxy-manager-proxies.yaml"
  ensure_parent(managed_file)
  local managed_tmp = managed_file .. ".tmp." .. tostring(os.time())
  local vless_template = ctx.uci:get(ctx.PKG, "main", "watchdog_mihomo_vless_outbound_template_file")
    or "/etc/tproxy-manager/watchdog-mihomo-vless-outbound.template.yaml"
  local hy2_template = ctx.uci:get(ctx.PKG, "main", "watchdog_mihomo_hysteria_outbound_template_file")
    or "/etc/tproxy-manager/watchdog-mihomo-hysteria-outbound.template.yaml"

  local rc, out = run_cmd_capture(string.format(
    "%s -r %s --provider --vless-template %s --hy2-template %s > %s",
    utils.shellescape("/usr/bin/proxy2mihomo.lua"),
    utils.shellescape(links_file),
    utils.shellescape(vless_template),
    utils.shellescape(hy2_template),
    utils.shellescape(managed_tmp)))
  if rc ~= 0 then
    fs.remove(managed_tmp)
    return false, out ~= "" and out or "Mihomo managed config build failed."
  end

  local assembler = "/usr/libexec/tproxy-manager/assemble-config"
  if not fs.access(assembler) then
    fs.remove(managed_tmp)
    return false, _("Could not assemble the Mihomo config directory.")
  end
  rc, out = run_cmd_capture(string.format(
    "TPM_MIHOMO_MANAGED_CANDIDATE=%s %s mihomo --check",
    utils.shellescape(managed_tmp), utils.shellescape(assembler)))
  if rc ~= 0 then
    fs.remove(managed_tmp)
    return false, out ~= "" and out or _("Generated Mihomo config failed validation.")
  end

  local rollback = managed_file .. ".rollback." .. tostring(os.time())
  local existed = fs.access(managed_file)
  if existed then
    local copy_rc = run_cmd_capture(string.format("cp -p %s %s",
      utils.shellescape(managed_file), utils.shellescape(rollback)))
    if copy_rc ~= 0 then
      fs.remove(managed_tmp)
      return false, _("Could not preserve the current Mihomo managed config.")
    end
  end
  rc, out = run_cmd_capture(string.format("mv %s %s",
    utils.shellescape(managed_tmp), utils.shellescape(managed_file)))
  if rc == 0 then
    rc, out = run_cmd_capture(utils.shellescape(assembler) .. " mihomo")
  end
  if rc ~= 0 then
    if existed then fs.rename(rollback, managed_file) else fs.remove(managed_file) end
    run_cmd_capture(utils.shellescape(assembler) .. " mihomo")
    fs.remove(managed_tmp); fs.remove(rollback)
    return false, out ~= "" and out or _("Could not put the generated Mihomo config in place.")
  end
  fs.remove(rollback)
  return true, managed_file
end

-- ensure Mihomo dir exists
do
  utils.ensure_dir(MIHOMO_DIR)
end
-- End of local Mihomo-specific helpers.

local function render(ctx)
  local m = ctx.m
  local fval, fval_last = ctx.fval, ctx.fval_last
  local self_url, redirect_here = ctx.self_url, ctx.redirect_here
  local combined_log, set_err, get_err, set_info, get_info =
    ctx.combined_log, ctx.set_err, ctx.get_err, ctx.set_info, ctx.get_info
  local service_block = ctx.service_block
  local profile_dir = ctx.uci:get(ctx.PKG, "main", "mihomo_profile_config_dir")
    or "/etc/mihomo/tproxy-manager.d"
  local profile_stat = fs.stat(profile_dir)
  local edit_dir = profile_stat and (profile_stat.type == "dir" or profile_stat.type == "directory")
    and profile_dir or MIHOMO_DIR

  -- Toolbar handlers
  if http.formvalue("_refreshlog_mihomo") then set_err(nil); redirect_here("mihomo"); return m end
  if http.formvalue("_clearlog_mihomo") then
    -- Restarting `log` is what actually drops the ring buffer. Clearing
    -- the banner regardless read as success even when it failed.
    if sys.call("/etc/init.d/log restart >/dev/null 2>&1") == 0 then
      set_err(nil)
    else
      set_info(nil); set_err(_("Failed to clear the log."))
    end
    redirect_here("mihomo"); return m
  end
  if http.formvalue("_test_mihomo") then
    if edit_dir ~= MIHOMO_DIR then
      sys.call(string.format("%s mihomo --check >%s 2>&1",
        utils.shellescape("/usr/libexec/tproxy-manager/assemble-config"), utils.shellescape(MIHOMO_TEST_LOG)))
    else
      local default_config = basename(ctx.uci:get(ctx.PKG, "main", "mihomo_profile_config_file"), "tproxy-manager.yaml")
      local config_file = fval_last("mihomo_file_selected")
      if config_file == "" then config_file = fval_last("mihomo_file") end
      if config_file == "" or config_file:find("[/\\]") then config_file = default_config end
      sys.call(string.format(
        "SAFE_PATHS=%q %s -d %q -t -f %q >%s 2>&1",
        MIHOMO_DIR, MIHOMO_BIN, MIHOMO_DIR, MIHOMO_DIR.."/"..config_file, MIHOMO_TEST_LOG))
    end
    set_err(nil); redirect_here("mihomo"); return m
  end
  if http.formvalue("_clearlog_mihomo_config") then
    local ok, why = write_file(MIHOMO_TEST_LOG, "")
    if ok then
      set_err(nil)
    elseif why == "permissions" then
      set_info(nil)
      set_err(_("Settings saved, but the configuration file permissions could not be secured."))
    else
      set_info(nil); set_err(_("Failed to clear the log."))
    end
    redirect_here("mihomo"); return m
  end
  if http.formvalue("_mihomo_version_refresh") == "1" then
    local rc, out = run_mihomo_version({ "status", "--refresh" })
    if rc == 0 then set_info(_("Mihomo version information refreshed.")) else set_err(out ~= "" and out or _("Failed to refresh Mihomo version information.")) end
    redirect_here("mihomo"); return m
  end
  if http.formvalue("_mihomo_update_latest") == "1" then
    local rc, out = run_mihomo_version({ "status", "--refresh" })
    local status = utils.parse_kv_text(out)
    local tag = utils.trim(status.LATEST_TAG or "")
    if rc ~= 0 or tag == "" then
      set_err(out ~= "" and out or _("Latest Mihomo version is not available."))
    else
      local install_rc, install_out = run_mihomo_version({ "install", tag })
      if install_rc == 0 then set_info(install_out ~= "" and install_out or _("Mihomo updated.")) else set_err(install_out ~= "" and install_out or _("Mihomo update failed.")) end
    end
    redirect_here("mihomo"); return m
  end
  if http.formvalue("_mihomo_install_version") == "1" then
    local tag = utils.trim(http.formvalue("mihomo_install_tag"))
    if tag == "" then
      set_err(_("Select Mihomo version to install."))
    else
      local rc, out = run_mihomo_version({ "install", tag })
      if rc == 0 then set_info(out ~= "" and out or _("Mihomo version installed.")) else set_err(out ~= "" and out or _("Mihomo install failed.")) end
    end
    redirect_here("mihomo"); return m
  end
  if http.formvalue("_mihomo_rollback") == "1" then
    local rc, out = run_mihomo_version({ "rollback" })
    if rc == 0 then set_info(out ~= "" and out or _("Mihomo rollback completed.")) else set_err(out ~= "" and out or _("Mihomo rollback failed.")) end
    redirect_here("mihomo"); return m
  end
  if http.formvalue("_mihomo_build_managed") == "1" then
    local ok, msg = build_managed_config(ctx)
    if ok then set_err(nil); set_info(_("Mihomo managed config generated:").." " .. msg) else set_info(nil); set_err(msg) end
    redirect_here("mihomo"); return m
  end

  -- Mihomo status
  do
    local ss = m:section(SimpleSection, _("Mihomo service status and controls"))
    service_block(ss, "tproxy-manager-mihomo", "Mihomo", "mihomo")
  end

  do
    local sec = m:section(SimpleSection)
    local dv = sec:option(DummyValue, "_mihomo_version")
    dv.rawhtml = true
    function dv.cfgvalue()
      local status_rc, status_out = run_mihomo_version({ "status" })
      local status = utils.parse_kv_text(status_out)
      local list_rc, list_out = run_mihomo_version({ "list" })
      local versions = list_rc == 0 and parse_tsv_versions(list_out) or {}
      local color = status.STATUS_COLOR or "gray"
      local css_color = color == "green" and "var(--tpm-ok)" or color == "blue" and "var(--primary-color-medium,#2563eb)" or color == "orange" and "var(--tpm-warn)" or "var(--tpm-muted)"
      local rows = {}
      rows[#rows + 1] = "<details><summary><strong>" .. _("Mihomo version") .. "</strong></summary>"
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
        pcdata(status.BIN or MIHOMO_BIN),
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
        rows[#rows + 1] = "<div style='margin-top:.5rem;color:var(--tpm-bad)'>" .. pcdata(status.ERROR) .. "</div>"
      end
      rows[#rows + 1] = "<div style='margin-top:.6rem'>"
      rows[#rows + 1] = "<button class='cbi-button cbi-button-action' name='_mihomo_version_refresh' value='1'>" .. _("Refresh versions") .. "</button> "
      rows[#rows + 1] = "<button class='cbi-button cbi-button-apply' name='_mihomo_update_latest' value='1' onclick=\"return confirm('" .. pcdata(_("Update Mihomo to latest stable version?")) .. "')\">" .. _("Update to latest") .. "</button> "
      rows[#rows + 1] = "<button class='cbi-button cbi-button-reset' name='_mihomo_rollback' value='1' onclick=\"return confirm('" .. pcdata(_("Rollback Mihomo to previous binary?")) .. "')\"" .. ((status.BACKUP_FILE or "") == "" and " disabled" or "") .. ">" .. _("Rollback previous binary") .. "</button>"
      rows[#rows + 1] = "</div>"
      rows[#rows + 1] = "<div style='margin-top:.7rem'>"
      rows[#rows + 1] = "<select name='mihomo_install_tag' style='max-width:18rem'>"
      for __, item in ipairs(versions) do
        local suffix = item.prerelease and " prerelease" or ""
        rows[#rows + 1] = string.format("<option value='%s'>%s%s · %s</option>", pcdata(item.tag), pcdata(item.tag), pcdata(suffix), pcdata(item.published))
      end
      if #versions == 0 then rows[#rows + 1] = "<option value=''>" .. pcdata(_("No repository versions available")) .. "</option>" end
      rows[#rows + 1] = "</select> "
      rows[#rows + 1] = "<button class='cbi-button cbi-button-apply' name='_mihomo_install_version' value='1' onclick=\"return confirm('" .. pcdata(_("Install selected Mihomo version?")) .. "')\">" .. _("Install selected version") .. "</button>"
      rows[#rows + 1] = "</div>"
      rows[#rows + 1] = "<div style='margin-top:.7rem'>"
      rows[#rows + 1] = "<button class='cbi-button cbi-button-action' name='_mihomo_build_managed' value='1'>" .. _("Generate managed Mihomo config from Watchdog links") .. "</button>"
      rows[#rows + 1] = "</div>"
      if status_rc ~= 0 then rows[#rows + 1] = "<pre style='white-space:pre-wrap;color:var(--tpm-bad)'>" .. pcdata(status_out) .. "</pre>" end
      rows[#rows + 1] = "</div></details>"
      return table.concat(rows, "\n")
    end
  end

  -- Combined log
  do
    local sl = m:section(SimpleSection)
    local log = sl:option(DummyValue, "_log_mihomo"); log.rawhtml = true
    function log.cfgvalue()
      return "<details><summary><strong>" .. _("System log (logread)") .. "</strong></summary>" ..
             "<div class='box editor-wrap'><pre style='white-space:pre-wrap;max-height:30rem;overflow:auto'>" ..
             pcdata(combined_log()) .. "</pre>" ..
             "<div style='margin-top:.5rem'><button class='cbi-button cbi-button-action small-btn' style='margin-right:4px; padding:0; border:0' name='_refreshlog_mihomo' value='1'>" .. _("Refresh") .. "</button> " ..
             "<button class='cbi-button cbi-button-remove small-btn' style='padding:0; border:0' name='_clearlog_mihomo' value='1'>" .. _("Clear") .. "</button></div>" ..
             "</div></details>"
    end
  end

  -- Mihomo config editor
  do
    local sx = m:section(SimpleSection, _("Mihomo configuration files") .. " (" .. edit_dir .. ")")

    local config_files = list_yaml(edit_dir)
    local default_config
    if edit_dir ~= MIHOMO_DIR then
      default_config = basename(ctx.uci:get(ctx.PKG, "main", "mihomo_profile_user_file"), "03-proxies-user.yaml")
    else
      default_config = basename(ctx.uci:get(ctx.PKG, "main", "mihomo_profile_config_file"), "tproxy-manager.yaml")
    end
    local chosen = fval("mihomo_file")
    if chosen == "" then chosen = default_config end
    local found=false; for __,f in ipairs(config_files) do if f==chosen then found=true; break end end
    if not found then
      for __, f in ipairs(config_files) do if f == default_config then chosen = f; found = true; break end end
    end
    if not found then chosen = config_files[1] end

    local function is_known_yaml_file(name)
      if not name or name == "" or name:find("[/\\]") then return false end
      for __, f in ipairs(config_files) do if f == name then return true end end
      return false
    end

    -- create/delete
    if http.formvalue("_mihomo_create") == "1" then
      local name = (http.formvalue("new_mihomo_name") or ""):gsub("^%s+",""):gsub("%s+$","")
      if name ~= "" and not name:find("[/\\]") and name:match("%.yaml$") then
        local path = edit_dir .. "/" .. name
        if not fs.access(path) then
          -- Creation is checked: redirecting to an editor for a file that
          -- was never created (and clearing the error on the way) left the
          -- user staring at an empty page with no indication of failure.
          local made, mwhy = write_file(path, "# Mihomo configuration\n\n")
          if not made and mwhy ~= "permissions" then
            set_info(nil)
            set_err(_("Failed to save settings."))
            redirect_here("mihomo")
            return m
          end
          if not made then
            set_info(nil)
            set_err(_("Settings saved, but the configuration file permissions could not be secured."))
            redirect_here("mihomo")
            return m
          end
        end
        set_err(nil)
        http.redirect(self_url({ tab="mihomo", mihomo_file=name }))
      else
        set_err(_("Invalid file name. Expected *.yaml without slashes."))
        redirect_here("mihomo")
      end
      return m
    end

    if http.formvalue("_mihomo_delete") == "1" then
      local cf = fval_last("mihomo_file") or ""
      if is_known_yaml_file(cf) then
        fs.remove(edit_dir .. "/" .. cf)
        set_err(nil)
      else
        set_err(_("Invalid file name. Expected *.yaml without slashes."))
      end
      redirect_here("mihomo"); return m
    end

    -- selector box
    do
      local url = disp.build_url("admin","network","tproxy_manager")
      local buf = {}
      buf[#buf+1] = "<div class='box editor-wrap editor-680' id='mihomo-editor'>"
      buf[#buf+1] = string.format([[
    <div class="inline-row" style="margin:.3rem 0;">
        <span>%s:</span>
        <input type="text" name="new_mihomo_name" placeholder="config.yaml" style="width:200px">
        <button class="cbi-button cbi-button-apply" name="_mihomo_create" value="1" onclick="return window.__xray_guard?window.__xray_guard():true">%s</button>
    </div>
    <div style="color:var(--tpm-muted);margin-top:.2rem">%s <code>*.yaml</code>, %s.</div>
    <hr style="border:none;border-top:1px solid var(--tpm-line);margin:.5rem 0"/>]],
        pcdata(_("New file")),
        pcdata(_("Create")),
        pcdata(_("The name must match")),
        pcdata(_("without slashes"))
      )
      buf[#buf+1] = "<label>" .. _("File to edit") .. "</label>"
      buf[#buf+1] = "<select name='mihomo_file'>"
      for __, f in ipairs(config_files) do
        local sel = (f==chosen) and " selected" or ""
        buf[#buf+1] = string.format("<option value=\"%s\"%s>%s</option>", pcdata(f), sel, pcdata(f))
      end
      buf[#buf+1] = "</select>"
      buf[#buf+1] = string.format("<input type=\"hidden\" name=\"mihomo_file_selected\" value=\"%s\">", pcdata(chosen or ""))
      buf[#buf+1] = [[
<script>
(function(){
    var sel = document.querySelector('#mihomo-editor select[name="mihomo_file"]');
    var hidden = document.querySelector('#mihomo-editor input[name="mihomo_file_selected"]');
    if (!sel) return;
    function remember(){ if(hidden) hidden.value = sel.value || ''; }
    remember();
    sel.addEventListener('change', function(){
        if (window.__xray_guard && !window.__xray_guard()) {
          this.value = this.getAttribute('data-prev') || this.value; return;
        }
        remember();
        var base = ']] .. pcdata(url) .. [[';
        var target = base + "?tab=mihomo&mihomo_file="+encodeURIComponent(sel.value);
        location.href = target;
    });
    var form = sel.closest && sel.closest('form');
    if(form) form.addEventListener('submit', remember, true);
    sel.setAttribute('data-prev', sel.value);

    // Name the file in the delete confirmation: the other buttons redirect and
    // the selector returns on the first file, so a bare "Delete selected file?"
    // can be confirmed for a file the user never had open.
    document.addEventListener('DOMContentLoaded', function(){
      var del = document.querySelector('#mihomo-editor button[name="_mihomo_delete"]');
      if (!del) return;
      var ask = del.getAttribute('data-confirm') || '';
      del.onclick = function(){
        if (window.__xray_guard && !window.__xray_guard()) return false;
        return confirm(ask + '\n\n' + (sel.value || ''));
      };
    });
})();
</script>]]
      buf[#buf+1] = string.format([[
<button class="cbi-button cbi-button-remove" name="_mihomo_delete" value="1"
    data-confirm="%s"
    onclick="return (window.__xray_guard?window.__xray_guard():true) && confirm('%s')">%s</button>]],
        pcdata(_("Delete selected file?")),
        pcdata(_("Delete selected file?")),
        pcdata(_("Delete"))
      )
      buf[#buf+1] = "</div><div style='height:5px'></div>"
      local dvsel = sx:option(DummyValue, "_selector_mihomo"); dvsel.rawhtml=true
      function dvsel.cfgvalue() return table.concat(buf) end
    end

    if chosen then
      local cedit = sx:option(DummyValue, "_mihomo_area"); cedit.rawhtml = true
      function cedit.cfgvalue()
        local content = read_file(edit_dir .. "/" .. chosen)
        -- Same editor chrome as the Xray and sing-box tabs: a dark code panel is
        -- deliberately single-scheme (it is a window into a config file), and it
        -- was the only engine tab without one. No syntax overlay here: the
        -- highlighter on those tabs parses JSON, and this file is YAML.
        return [[
<div class="tpm-codeblock">
  <div class="tpm-codebox">
    <textarea name="mihomo_text" rows="22" spellcheck="false">]] .. pcdata(content) .. [[</textarea>
  </div>
</div>
<div style="height:5px"></div>]]
      end

      local bsave = sx:option(Button, "_savemihomo"); bsave.title = ""; bsave.inputtitle = _("Save")
      bsave.inputstyle = "apply"
      function bsave.write(self, section)
        if not self.map:formvalue(self:cbid(section)) then return end
        local new = http.formvalue("mihomo_text") or ""
        local cf = fval_last("mihomo_file_selected")
        if cf == "" then cf = fval_last("mihomo_file") end
        if cf == "" then cf = chosen end
        if not is_known_yaml_file(cf) then
          set_err(_("Invalid file name. Expected *.yaml without slashes."))
          set_info(nil)
          http.redirect(self_url({ tab = "mihomo" }))
          return
        end
        if not validate_mihomo_text(new, edit_dir, cf) then
          set_err(_("Invalid Mihomo configuration. File was not saved."))
          set_info(nil)
          http.redirect(self_url({ tab = "mihomo", mihomo_file = cf }))
          return
        end
        local wrote, wwhy = write_file(edit_dir .. "/" .. cf, new)
        if wrote then
          if edit_dir ~= MIHOMO_DIR then
            local arc, aout = run_cmd_capture(utils.shellescape("/usr/libexec/tproxy-manager/assemble-config") .. " mihomo")
            if arc ~= 0 then
              set_info(nil); set_err(aout ~= "" and aout or _("Could not assemble the Mihomo config directory."))
            else
              set_err(nil); set_info(_("Mihomo config saved:").." "..cf)
            end
          else
            set_err(nil); set_info(_("Mihomo config saved:").." "..cf)
          end
        elseif wwhy == "permissions" then
          set_info(nil); set_err(_("Settings saved, but the configuration file permissions could not be secured."))
        else
          set_info(nil); set_err(_("Failed to save settings."))
        end
        http.redirect(self_url({ tab = "mihomo", mihomo_file = cf }))
      end
    end

    local dout = sx:option(DummyValue, "_testout_mihomo"); dout.rawhtml = true; dout.title = ""
    function dout.cfgvalue()
      local out = read_file(MIHOMO_TEST_LOG)
      return "<details><summary>" .. _("Last validation result") .. "</summary>" ..
             "<div class='box editor-wrap editor-680'><pre style='white-space:pre-wrap'>" ..
             pcdata(out ~= "" and out or _("(not run yet)")) .. "</pre>" ..
             "<div style='margin-top:.5rem'><button class='cbi-button cbi-button-action small-btn' style='margin-right:4px; padding:0; border:0' name='_test_mihomo' value='1'>" .. _("Validate configuration") .. "</button> " ..
             "<button class='cbi-button cbi-button-remove small-btn' style='padding:0; border:0' name='_clearlog_mihomo_config' value='1'>" .. _("Clear") .. "</button></div>" ..
             "</div></details>"
    end

    local msg = sx:option(DummyValue, "_mihomo_msgs"); msg.rawhtml = true; msg.title = ""
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
