local cbi = require "luci.cbi"
local SimpleSection, DummyValue, Button = cbi.SimpleSection, cbi.DummyValue, cbi.Button

-- Local self-contained implementation of the updates module.
local fs    = require "nixio.fs"
local sys   = require "luci.sys"
local http  = require "luci.http"
local disp  = require "luci.dispatcher"
local xml   = require "luci.xml"
local jsonc = require "luci.jsonc"
local utils = require "luci.model.cbi.tproxy_manager.utils"
local _ = require "luci.model.cbi.tproxy_manager.i18n"

local pcdata = xml.pcdata

-- Internal paths/constants for this module.
local BASE_DIR     = "/etc/tproxy-manager"
local GEO_CFG      = BASE_DIR .. "/geo-sources.conf"
local GEO_SCRIPT   = "/usr/bin/tproxy-manager-geo-update.sh"
local CRON_FILE    = "/etc/crontabs/root"
local CRON_TAG     = "# tproxy-manager-geo-update"
local SYSLOG_TAG   = "tproxy-manager-geoip-update"

-- ---------- File helpers ----------
local read_file = utils.read_file
local write_file = utils.write_file

local function parse_jsonc_or_error(raw)
  local data, err = utils.parse_jsonc_or_error(raw, {})
  if data == nil then
    return nil, err or _("Invalid JSON/JSONC")
  end
  if type(data) ~= "table" then
    return nil, _("JSON root must be an array or object")
  end
  return data
end

-- Returns the writer's tri-state instead of an unconditional true: the GEO
-- source list is what every later update run reads, so a silently failed
-- write used to leave the UI claiming a list that was never stored.
local function write_json_file(path, tbl)
  local text = jsonc.stringify(tbl or {}, true)
  local wrote, wwhy = write_file(path, text)
  if wrote then return true end
  if wwhy == "permissions" then return true, "permissions" end
  return false
end

-- ---------- Utilities ----------
local function mtime_str(path)
  local st = fs.stat(path)
  if not st or not st.mtime then return _("(not found)") end
  local size = st.size or 0
  return os.date("%Y-%m-%d %H:%M:%S", st.mtime) .. string.format(" · %d bytes", size)
end

local function shellescape(s)
  return utils.shellescape(s)
end

local function log_sys(msg)
  sys.exec(string.format("logger -t %s %s", SYSLOG_TAG, shellescape(msg or "")))
end

-- is_safe_geo_url: only allow http(s), reject schemes like file://
-- (otherwise fetch_to could be made to copy an arbitrary local file —
-- SSRF/LFI via curl/wget). Also reject whitespace/quotes/shell special
-- characters as defense-in-depth (shellescape() already makes this safe,
-- this is just a second line of defense).
local function is_safe_geo_url(url)
  url = tostring(url or "")
  return url:match("^https?://[^%s\"'`$]+$") ~= nil
end

-- is_safe_geo_dest: an absolute path without directory traversal ("..").
local function is_safe_geo_dest(dest)
  return utils.is_abs_path(dest)
end

-- dq_escape: escaping for substitution inside DOUBLE quotes in the
-- generated shell script (used only for log message text — the actual
-- command arguments go through shellescape()/single quotes).
local function dq_escape(s)
  return (tostring(s or ""):gsub('([\\"$`])', '\\%1'))
end

local function fetch_to(url, dest)
  if not is_safe_geo_url(url) then
    log_sys(string.format("FAIL: unsafe url rejected: %s", url or ""))
    return false
  end
  if not is_safe_geo_dest(dest) then
    log_sys(string.format("FAIL: unsafe dest rejected: %s", dest or ""))
    return false
  end
  local tmp = dest .. ".tmp"
  local cmd = string.format("(command -v curl >/dev/null && curl -L --fail --silent --show-error -o %s %s) " ..
                            "|| (command -v wget >/dev/null && wget -O %s %s)",
                            shellescape(tmp), shellescape(url),
                            shellescape(tmp), shellescape(url))
  local ok = (sys.call(cmd .. " >/dev/null 2>&1") == 0)
  if ok then
    local dir = dest:match("^(.*)/[^/]+$")
    if dir and not fs.access(dir) then sys.call("mkdir -p '"..dir:gsub("'", "'\\''").."'") end
    -- utils.promote_file() falls back to copy+remove if a bare rename fails
    -- (observed: ESTALE from nixio.fs.rename on some flash filesystems) —
    -- without it, the download succeeds but only the ".tmp" file is left
    -- behind while this still reported "OK".
    ok = utils.promote_file(tmp, dest)
    if ok then
      log_sys(string.format("OK: %s -> %s", url or "", dest or ""))
    else
      fs.remove(tmp)
      log_sys(string.format("FAIL: unable to move downloaded file into place: %s", dest or ""))
    end
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

-- Both cron helpers now report whether the crontab was actually written:
-- restarting cron and returning true after a failed write meant the UI
-- showed a schedule that does not exist.
-- Both report the permissions case separately: the crontab IS in place, so
-- it is not a failure, but announcing a plain success would hide that the
-- file is left world-readable.
local function cron_write(body)
  local wrote, wwhy = write_file(CRON_FILE, body)
  if not wrote and wwhy ~= "permissions" then return false end
  -- Only a restarted cron actually picks the schedule up; reporting an
  -- installed schedule that cron has not read yet is the same false success.
  if sys.call("/etc/init.d/cron restart >/dev/null 2>&1") ~= 0 then return false end
  if wrote then return true end
  return true, "permissions"
end

local function cron_install(spec)
  local new_body = cron_body_without_tag()
  new_body = (new_body ~= "" and (new_body .. "\n") or "") .. string.format("%s %s %s\n", spec, GEO_SCRIPT, CRON_TAG)
  return cron_write(new_body)
end

local function cron_remove()
  local body = cron_body_without_tag()
  return cron_write(body ~= "" and (body .. "\n") or "")
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

local function cron_named_value(token, field_type)
  local names = nil
  if field_type == "month" then
    names = { jan = 1, feb = 2, mar = 3, apr = 4, may = 5, jun = 6, jul = 7, aug = 8, sep = 9, oct = 10, nov = 11, dec = 12 }
  elseif field_type == "dow" then
    names = { sun = 0, mon = 1, tue = 2, wed = 3, thu = 4, fri = 5, sat = 6 }
  end
  if not names then return tonumber(token) end
  local lower = tostring(token or ""):lower()
  return names[lower] or tonumber(lower)
end

local function cron_validate_atom(atom, min_value, max_value, field_type)
  local value = cron_named_value(atom, field_type)
  return value ~= nil and value >= min_value and value <= max_value
end

local function cron_validate_base(base, min_value, max_value, field_type)
  if base == "*" then return true end
  if base:match("^[^%-]+%-.+$") then
    local left, right = base:match("^([^%-]+)%-(.+)$")
    local lv = cron_named_value(left, field_type)
    local rv = cron_named_value(right, field_type)
    return lv ~= nil and rv ~= nil and lv >= min_value and rv <= max_value and lv <= rv
  end
  return cron_validate_atom(base, min_value, max_value, field_type)
end

local function cron_validate_field(value, min_value, max_value, field_type)
  value = tostring(value or "")
  if value == "" or not value:match("^[%w%*/,%-]+$") then return false end
  for token in (value .. ","):gmatch("([^,]+),") do
    local base, step = token, nil
    if token:find("/", 1, true) then
      base, step = token:match("^(.-)/(%d+)$")
      if not base or not step or tonumber(step) < 1 then return false end
    end
    if not cron_validate_base(base, min_value, max_value, field_type) then
      return false
    end
  end
  return true
end

local function validate_cron_spec(spec)
  spec = utils.trim(spec):gsub("%s+", " ")
  local fields = {}
  for part in spec:gmatch("%S+") do fields[#fields + 1] = part end
  if #fields ~= 5 then
    return nil, _("Invalid cron expression: 5 fields are required (min hour dom month dow).")
  end
  local validators = {
    { min = 0, max = 59,  field = "min",   label = _("minutes") },
    { min = 0, max = 23,  field = "hour",  label = _("hours") },
    { min = 1, max = 31,  field = "dom",   label = _("day of month") },
    { min = 1, max = 12,  field = "month", label = _("month") },
    { min = 0, max = 7,   field = "dow",   label = _("day of week") },
  }
  for i, meta in ipairs(validators) do
    if not cron_validate_field(fields[i], meta.min, meta.max, meta.field) then
      return nil, _("Invalid cron field:").." " .. meta.label .. " (" .. tostring(fields[i]) .. ")"
    end
  end
  return table.concat(fields, " ")
end

local function cron_spec_human(spec)
  spec = (spec or ""):gsub("^%s+",""):gsub("%s+$","")
  if spec == "" then return "" end
  local parts = {}
  for w in (spec.." "):gmatch("([^%s]+)") do parts[#parts+1] = w end
  if #parts < 5 then return _("schedule:").." "..spec end
  local min, hr, dom, mon, dow = parts[1], parts[2], parts[3], parts[4], parts[5]
  local min_num, hr_num = tonumber(min), tonumber(hr)
  local time_str = (min_num and hr_num) and string.format("%d:%02d", hr_num, min_num) or (hr..":"..min)
  local names = { ["0"]=_("Sundays"),["7"]=_("Sundays"),["1"]=_("Mondays"),["2"]=_("Tuesdays"),["3"]=_("Wednesdays"),["4"]=_("Thursdays"),["5"]=_("Fridays"),["6"]=_("Saturdays") }

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
    for __, d in ipairs(days) do local k=tostring(d); if not seen[k] and names[k] then seen[k]=true; labels[#labels+1]=names[k] end end
    table.sort(labels)
    local text = (#labels==0) and (_("on days").." "..dow) or (#labels==1 and (_("on").." "..labels[1]) or (_("on").." "..table.concat(labels, ", ", 1, #labels-1).." ".._("and").." "..labels[#labels]))
    return time_str ~= "" and (text.." ".._("at").." "..time_str) or text
  end

  if dow == "*" and mon == "*" and dom == "*" then
    return _("every day at").." "..time_str
  end

  if dow == "*" and mon == "*" and dom ~= "*" then
    local ords = {}
    for token in (dom..","):gmatch("([^,]+),") do
      local dnum = tonumber(token); ords[#ords+1] = dnum and (tostring(dnum) .. _("th")) or (token.._("th"))
    end
    local text = (#ords==0 and _("monthly")) or (#ords==1 and (_("monthly on day").." "..ords[1]) or (_("monthly on days").." "..table.concat(ords, " ".._("and").." ")))
    return text.." ".._("at").." "..time_str
  end

  return _("schedule:").." "..spec
end

-- ---------- GEO config ----------
local function normalize_rows(data)
  local out = {}
  for __, it in ipairs(data) do
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
  local data, err = parse_jsonc_or_error(raw)
  if not data then return {}, err end
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
    -- The lock used to sit at a fixed path in world-writable /tmp, where any
    -- local user could pre-create it (denying the updater its lock forever) or
    -- point it at another file for this root script to open. It now lives in a
    -- root-only 0700 directory that the script creates and validates itself.
    "LOCK_ROOT=\"/var/lock/tproxy-manager\"",
    "mkdir -m 0700 \"$LOCK_ROOT\" 2>/dev/null || :",
    "case \"$(ls -ldn \"$LOCK_ROOT\" 2>/dev/null | awk '{print $1\" \"$3}')\" in",
    "  \"drwx------ 0\") : ;;",
    "  *) logger -t " .. SYSLOG_TAG .. " \"ABORT: unsafe lock directory $LOCK_ROOT\"; exit 1 ;;",
    "esac",
    "LOCK=\"$LOCK_ROOT/geo-update.lock\"",
    "if command -v flock >/dev/null 2>&1; then",
    "  exec 9>\"$LOCK\"",
    "  if ! flock -n 9; then logger -t " .. SYSLOG_TAG .. " \"SKIP: already running\"; exit 0; fi",
    "else",
    "  ( set -o noclobber; : >\"$LOCK\" ) 2>/dev/null || { logger -t " .. SYSLOG_TAG .. " \"SKIP: already running\"; exit 0; }",
    "  trap 'rm -f \"$LOCK\"' EXIT INT TERM",
    "fi",
    "logger -t " .. SYSLOG_TAG .. " \"starting update\""
  }
  for __, r in ipairs(rows or {}) do
    if r.url and r.url ~= "" and r.dest and r.dest ~= "" then
      -- Skip entries with an invalid url/dest (in case they ended up in
      -- geo-sources.conf bypassing UI validation, e.g. via the "raw JSON"
      -- editor) — never embed them into the executable script at all.
      if not is_safe_geo_url(r.url) then
        log_sys(string.format("SKIP (write_geo_script): unsafe url: %s", r.url))
      elseif not is_safe_geo_dest(r.dest) then
        log_sys(string.format("SKIP (write_geo_script): unsafe dest: %s", r.dest))
      else
        -- shellescape() wraps the value in single quotes and correctly
        -- escapes embedded single quotes/backticks/$()/newlines — unlike the
        -- previous manual gsub('"','\\"'), which did not protect against
        -- command substitution inside double quotes.
        local q_url   = shellescape(r.url)
        local q_dest  = shellescape(r.dest)
        local q_name  = shellescape(r.name or "")
        local dq_url  = dq_escape(r.url)
        local dq_dest = dq_escape(r.dest)
        lines[#lines+1] = string.format([[
: %s
if command -v curl >/dev/null; then
  tmp=%s.tmp
  mkdir -p "$(dirname %s)"
  if curl -L --fail --silent --show-error -o "$tmp" %s; then
    mv "$tmp" %s
    logger -t %s "OK: %s -> %s"
  else
    rm -f "$tmp"
    logger -t %s "FAIL: %s"
  fi
elif command -v wget >/dev/null; then
  tmp=%s.tmp
  mkdir -p "$(dirname %s)"
  if wget -q -O "$tmp" %s; then
    mv "$tmp" %s
    logger -t %s "OK: %s -> %s"
  else
    rm -f "$tmp"
    logger -t %s "FAIL: %s"
  fi
else
  logger -t %s "FAIL: no curl/wget"
fi
]], q_name,
        q_dest, q_dest, q_url, q_dest, SYSLOG_TAG, dq_url, dq_dest,
        SYSLOG_TAG, dq_url,
        q_dest, q_dest, q_url, q_dest, SYSLOG_TAG, dq_url, dq_dest,
        SYSLOG_TAG, dq_url,
        SYSLOG_TAG)
      end
    end
  end
  local wrote, wwhy = write_file(GEO_SCRIPT, table.concat(lines, "\n") .. "\n")
  if not wrote and wwhy ~= "permissions" then return false end
  -- The updater must stay executable; it is invoked by cron, not sourced.
  if sys.call(string.format("chmod +x %s", shellescape(GEO_SCRIPT))) ~= 0 then return false end
  if wrote then return true end
  return true, "permissions"
end

-- geo_persist: the source list and the generated updater are one unit — the
-- script is what cron actually runs, so a saved list with a stale script
-- keeps downloading the old sources. Both are written here, and the caller is
-- told the truth about the result instead of the previous unconditional
-- "Source added"/"Source deleted".
--
-- Returns:
--   true                  - list and script both written
--   true, "permissions"   - both written, but 0600 could not be applied
--   false                 - nothing may be reported as saved
local function geo_persist(rows)
  -- Both halves are copied into a private 0700 directory BEFORE the first
  -- write. The list can land while the script write fails, and then the page
  -- shows one set of sources while cron keeps downloading another — a
  -- mismatch nobody would notice until the wrong file is in place. Holding
  -- the "before" state on disk rather than in this process means it survives
  -- even if the request dies between the two writes.
  local store, serr = utils.snapshot_begin("geo")
  if store then
    for __, path in ipairs({ GEO_CFG, GEO_SCRIPT }) do
      if not store then break end
      local ok, aerr = utils.snapshot_add(store, path)
      if not ok then serr = aerr; utils.snapshot_discard(store); store = nil end
    end
  end
  if not store then
    -- No verified way back means the transaction must not start at all —
    -- refusing before the first write is strictly better than writing one
    -- file and discovering the other cannot be undone.
    return false, "nosnapshot", tostring(serr or "unknown error")
  end

  -- Armed before the first live write: a crash from here on must leave the
  -- snapshot behind rather than have it swept as untouched.
  local armed, aerr = utils.snapshot_arm(store)
  if not armed then
    utils.snapshot_discard(store)
    return false, "nosnapshot", tostring(aerr or "")
  end

  local saved, swhy = save_geo_cfg(rows)
  if not saved then
    utils.snapshot_discard(store)
    return false
  end

  local wrote, wwhy = write_geo_script(rows)
  if not wrote then
    -- The rollback is verified, not assumed: each file is written back from
    -- its on-disk copy and re-read to confirm content and mode. An
    -- unverified rollback that silently failed would leave the new list live
    -- under a "not saved" banner — the worst of both states.
    local failed = utils.snapshot_restore(store)
    if #failed > 0 then
      local names = {}
      for __, f in ipairs(failed) do
        names[#names + 1] = f.path .. (f.state == "permissions" and " (mode)" or "")
      end
      -- The directory is KEPT and marked so the sweeper leaves it alone: it
      -- now holds the only copy of the previous contents, and its path goes
      -- to the user.
      return false, "rollback", table.concat(names, ", "), utils.snapshot_keep(store)
    end
    utils.snapshot_discard(store)
    return false
  end

  utils.snapshot_discard(store)
  if swhy == "permissions" or wwhy == "permissions" then return true, "permissions" end
  return true
end

-- report_geo: single place that turns a geo_persist result into a banner, so
-- no handler can drift back into announcing success it did not verify.
local function report_geo(ctx, ok, why, success_msg, detail, store_dir)
  if not ok then
    ctx.set_info(nil)
    if why == "rollback" then
      -- Naming the paths is the point: this is the one state the user cannot
      -- diagnose from the UI, and the kept snapshot directory holds the only
      -- remaining copy of the previous contents.
      local msg = _("Failed to save settings.") .. "\n" ..
        string.format(_("ROLLBACK INCOMPLETE: the previous state of these files could not be restored: %s"),
          detail or "")
      if store_dir then
        msg = msg .. "\n" .. string.format(_("The previous contents are kept here: %s"), store_dir)
      end
      ctx.set_err(msg)
    elseif why == "nosnapshot" then
      -- Refusing up front is deliberate: without a verified way back, a
      -- half-applied change could not be undone at all.
      ctx.set_err(_("Failed to save settings.") .. "\n" ..
        string.format(_("Could not create a rollback snapshot: %s"), detail or ""))
    else
      ctx.set_err(_("Failed to save settings."))
    end
    return false
  end
  if why == "permissions" then
    ctx.set_info(nil)
    ctx.set_err(success_msg .. "\n" ..
      _("Settings saved, but the configuration file permissions could not be secured."))
    return true
  end
  ctx.set_err(nil)
  ctx.set_info(success_msg)
  return true
end

-- ===== UI / handlers =====
local function render(ctx)
  -- Use only common message/redirect helpers from ctx.
  local m = ctx.m
  local set_err, get_err, set_info, get_info = ctx.set_err, ctx.get_err, ctx.set_info, ctx.get_info
  local redirect_here = ctx.redirect_here

  -- Local styles.
  do
    local sec = m:section(SimpleSection)
    local css = sec:option(DummyValue, "_css_updates"); css.rawhtml = true
    function css.cfgvalue()
      return [[
<style>
/* Only what is specific to this tab. The shared box, editor, message and
   inline-row rules live in the token layer in manage.lua; they used to be
   declared here as well, with their own hardcoded colours, so the two copies
   could drift apart. (Do not write an editor-* wildcard here: the star-slash
   would close this comment early and swallow the first rule below.) */
.small-btn{padding:var(--tpm-1) .55rem}
.inline-edit{display:flex;gap:var(--tpm-3);align-items:center;flex-wrap:wrap;margin:var(--tpm-3) 0}
.inline-edit input[type="text"]{width:28%;min-width:180px}
.btn-green{background:var(--tpm-ok)!important;border-color:var(--tpm-ok)!important;color:var(--background-color-high,#fff)!important;font-weight:700!important}
/* GEO source table */
table.geo-table{width:100%;border-collapse:collapse; table-layout:fixed; word-break:break-all}
table.geo-table th, table.geo-table td{border:1px solid var(--tpm-line);padding:.35rem;text-align:left;vertical-align:top}
table.geo-table th{background:var(--tpm-surface); color:inherit}
table.geo-table.geo-upd{ table-layout:auto }
table.geo-table.geo-upd col.col-idx{ width:auto }
table.geo-table.geo-upd th:first-child, table.geo-table.geo-upd td:first-child{ white-space:nowrap }
</style>]]
    end
  end

  -- Source table data.
  local cfg, cfg_err = load_geo_cfg()
  local edit_idx = tonumber(http.formvalue("_geo_edit_idx") or http.formvalue("_geo_edit") or "")

  -- Source table and cron controls.
  do
    local sec = m:section(SimpleSection, _("Update management"))
    local list = sec:option(DummyValue, "_geo_list"); list.rawhtml = true
    function list.cfgvalue()
      local rows = {}
      rows[#rows+1] = "<div class='tpm-tablewrap'><table class='geo-table geo-upd tpm-cards'><colgroup><col class='col-idx'><col><col><col><col><col></colgroup><thead><tr><th>#</th><th>" .. _("Name") .. "</th><th>URL</th><th>" .. _("Path") .. "</th><th>" .. _("Updated at") .. "</th><th>" .. _("Actions") .. "</th></tr></thead><tbody>"
      for i, r in ipairs(cfg) do
        rows[#rows+1] = string.format(
          "<tr><td data-th='#' class='tpm-num'>%s</td><td data-th='" .. _("Name") .. "'>%s</td>" ..
          "<td data-th='URL'><code>%s</code></td><td data-th='" .. _("Path") .. "'><code>%s</code></td>" ..
          "<td data-th='" .. _("Updated at") .. "'>%s</td>" ..
          "<td>" ..
          "<button class='cbi-button cbi-button-apply btn-green small-btn' name='_geo_update_one' value='%s'>" .. _("Update") .. "</button> " ..
          "<button class='cbi-button cbi-button-action small-btn' name='_geo_edit' value='%s'>" .. _("Edit") .. "</button> " ..
          "<button class='cbi-button cbi-button-remove small-btn' name='_geo_delete' value='%s' onclick=\"return confirm('" .. _("Delete source #") .. "%s?')\">" .. _("Delete") .. "</button>" ..
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
        rows[#rows+1] = "<tr><td colspan='6' style='color:var(--tpm-muted)'>" .. _("List is empty") .. "</td></tr>"
      end

      local spec = current_cron_spec() or ""
      local placeholder = "*/30 * * * *"
      local human = (spec ~= "" and cron_spec_human(spec)) or _("Automatic updates are disabled")

      rows[#rows+1] = string.format([[
<tr>
  <td><em>%s: %s</em></td>
  <td colspan="4">
    <div class="inline-row"><span><em>%s:</em></span>
      <input type="text" id="geo_cron" name="geo_cron" style="width:24%%" value="%s" placeholder="%s" title="%s">
      <select id="geo_cron_presets" style="max-width:220px">
        <option value="">%s</option>
        <option value="0 5 * * *">%s</option>
        <option value="*/30 * * * *">%s</option>
        <option value="30 4 * * 0">%s</option>
        <option value="0 3 1 * *">%s</option>
      </select>
      <button class="cbi-button cbi-button-apply small-btn" name="_geo_install_cron" value="1">%s</button>
      <button class="cbi-button cbi-button-remove small-btn" name="_geo_remove_cron" value="1">%s</button>
    </div>
    <div style='margin-top:.2rem; color:var(--tpm-muted)'>%s</div>
    <div style='margin-top:.1rem; color:var(--tpm-muted)'>%s: <code>min hour dom month dow</code>, %s: <code>0 5 * * *</code> (%s), <code>30 4 * * 0</code> (%s)</div>
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
    <button class="cbi-button cbi-button-apply btn-green" name="_geo_update_all" value="1">%s</button>
  </td>
</tr>]],
        pcdata(_("Total")), tostring(#cfg),
        pcdata(_("Schedule")),
        pcdata(spec), pcdata(placeholder), pcdata(_("minutes hours day_of_month month day_of_week (example: 30 4 * * 0)")),
        pcdata(_("preset")),
        pcdata(_("Every day 05:00")),
        pcdata(_("Every 30 minutes")),
        pcdata(_("Sundays 04:30")),
        pcdata(_("1st day 03:00")),
        pcdata(_("Create/update autostart")),
        pcdata(_("Remove autostart")),
        pcdata(human),
        pcdata(_("Format")),
        pcdata(_("examples")),
        pcdata(_("every day at 5:00")),
        pcdata(_("Sundays at 4:30")),
        pcdata(_("Update all"))
      )

      rows[#rows+1] = "</tbody></table></div>"
      return table.concat(rows, "\n")
    end
  end

  -- Edit selected source.
  if edit_idx then
    local sec = m:section(SimpleSection, _("Edit source #") .. edit_idx)
    local dv = sec:option(DummyValue, "_geo_edit_form"); dv.rawhtml = true
    function dv.cfgvalue()
      local r = cfg[edit_idx]
      if not r then return _("(invalid index)") end
      return string.format([[
<div class="box editor-wrap inline-edit">
  <div>%s: <input type="text" name="edit_name" style="width:20%%" value="%s"></div>
  <div>URL: <input type="text" name="edit_url" style="width:35%%" value="%s"></div>
  <div>%s: <input type="text" name="edit_dest" style="width:35%%" value="%s"></div>
  <div>
    <button class="cbi-button cbi-button-apply" name="_geo_apply_edit" value="1">%s</button>
    <button class="cbi-button cbi-button-reset" name="_geo_cancel_edit" value="1">%s</button>
  </div>
</div>
<input type="hidden" name="_geo_edit_idx" value="%s">]],
        pcdata(_("Name")), pcdata(r.name or ""),
        pcdata(r.url or ""),
        pcdata(_("Path")), pcdata(r.dest or ""),
        pcdata(_("Save")), pcdata(_("Cancel")),
        tostring(edit_idx))
    end
  end

  -- Add new source.
  if not edit_idx then
    local sec = m:section(SimpleSection, _("Add source"))
    local dv = sec:option(DummyValue, "_geo_add"); dv.rawhtml = true
    function dv.cfgvalue()
      return [[
<div class="box editor-wrap inline-edit">
  <div>]] .. pcdata(_("Name")) .. [[: <input type="text" name="add_name" style="width:20%%" placeholder="geoip"></div>
  <div>URL: <input type="text" name="add_url" style="width:35%%" placeholder="https://.../file.dat"></div>
  <div>]] .. pcdata(_("Path")) .. [[: <input type="text" name="add_dest" style="width:35%%" placeholder="/usr/share/xray/geoip.dat"></div>
  <div><button class="cbi-button cbi-button-apply" name="_geo_add" value="1">]] .. pcdata(_("Add")) .. [[</button></div>
</div>]]
    end
  end

  -- Full JSON source editor.
  do
    local sec = m:section(SimpleSection)
    local dv = sec:option(DummyValue, "_geo_edit_json"); dv.rawhtml = true
    local raw = read_file(GEO_CFG); if raw == "" then raw = "[]" end
    function dv.cfgvalue()
      local content = read_file(GEO_CFG); if content == "" then content = "[]" end
      return [[
<details>
  <summary style="cursor:pointer;font-weight:600">]] .. pcdata(_("Full source list (JSON) - expand/collapse")) .. [[</summary>
  <div class="box editor-wrap editor-wide" style="margin-top:.5rem">
    <textarea name="geo_sources" rows="12" spellcheck="false">]] .. pcdata(content) .. [[</textarea>
    <div class="inline-row" style="margin-top:.4rem">
      <button class="cbi-button cbi-button-apply"  name="_geo_save" value="1">]] .. pcdata(_("Save list")) .. [[</button>
      <button class="cbi-button cbi-button-action" name="_geo_write_script" value="1">]] .. pcdata(_("Recreate script")) .. [[</button>
      <span style="color:var(--tpm-muted)">]] .. pcdata(_("Source list")) .. [[: <code>]] .. pcdata(GEO_CFG) .. [[</code> · ]] .. pcdata(_("Script")) .. [[: <code>]] .. pcdata(GEO_SCRIPT) .. [[</code></span>
    </div>
  </div>
</details>
]]
    end
  end

  -- ---------- Action handlers ----------
  do
    local function load_rows_again()
      local rows, err = load_geo_cfg()
      return rows, err
    end

    if http.formvalue("_geo_add") == "1" then
      local rows, err = load_rows_again()
      if err then
        set_err(_("GEO list was not parsed:").." " .. err); set_info(nil)
        redirect_here("updates"); return m
      end
      local name = (http.formvalue("add_name") or ""):gsub("^%s+",""):gsub("%s+$","")
      local url  = (http.formvalue("add_url")  or ""):gsub("^%s+",""):gsub("%s+$","")
      local dest = (http.formvalue("add_dest") or ""):gsub("^%s+",""):gsub("%s+$","")
      if dest == "" then
        set_err(_("Destination path (dest) is required.")); set_info(nil)
      elseif not is_safe_geo_dest(dest) then
        set_err(_("Destination path (dest) must be an absolute path without \"..\".")); set_info(nil)
      elseif url ~= "" and not is_safe_geo_url(url) then
        set_err(_("Source URL must start with http:// or https://.")); set_info(nil)
      else
        rows[#rows+1] = { name = name, url = url, dest = dest }
        local ok, why, detail, sdir = geo_persist(rows)
        report_geo(ctx, ok, why, _("Source added:").." "..(name ~= "" and name or dest), detail, sdir)
      end
      redirect_here("updates"); return m
    end

    if http.formvalue("_geo_update_one") then
      local idx = tonumber(http.formvalue("_geo_update_one"))
      local rows = load_rows_again()
      local r = (idx and rows[idx]) and rows[idx] or nil
      -- A failed download has to reach the user as an error. It used to go
      -- through set_info together with the success case, which renders in the
      -- green box that fades out after five seconds — so a download that never
      -- happened looked exactly like one that did. The same went for a row with
      -- no URL or destination: that branch reported nothing at all and the click
      -- looked like a no-op.
      if not r or (r.url or "") == "" then
        set_info(nil)
        set_err(_("Source URL must start with http:// or https://."))
      elseif (r.dest or "") == "" then
        set_info(nil)
        set_err(_("Destination path (dest) is required."))
      elseif fetch_to(r.url, r.dest) then
        set_err(nil)
        set_info(_("Updated:").." "..(r.name or r.dest))
      else
        set_info(nil)
        set_err(_("Update failed:").." "..(r.name or r.dest))
      end
      redirect_here("updates"); return m
    end

    if http.formvalue("_geo_update_all") == "1" then
      local rows = load_rows_again()
      local ok_count, total = 0, 0
      for __, r in ipairs(rows) do
        if r.url and r.url ~= "" and r.dest and r.dest ~= "" then
          total = total + 1
          if fetch_to(r.url, r.dest) then ok_count = ok_count + 1 end
        end
      end
      -- "Updated 0 of 3 sources" in the green fading box read as success. Any
      -- source that did not update makes this an error the user has to see.
      local summary = string.format(_("Updated %d of %d sources"), ok_count, total)
      if ok_count < total then
        set_info(nil); set_err(summary)
      else
        set_err(nil); set_info(summary)
      end
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
      local rows, err = load_rows_again()
      if err then
        set_err(_("GEO list was not parsed:").." " .. err); set_info(nil)
        redirect_here("updates"); return m
      end
      if idx and rows[idx] then
        local dest = (http.formvalue("edit_dest") or ""):gsub("^%s+",""):gsub("%s+$","")
        local url  = (http.formvalue("edit_url") or ""):gsub("^%s+",""):gsub("%s+$","")
        local edit_err = nil
        if dest == "" then
          edit_err = _("Destination path (dest) is required.")
        elseif not is_safe_geo_dest(dest) then
          edit_err = _("Destination path (dest) must be an absolute path without \"..\".")
        elseif url ~= "" and not is_safe_geo_url(url) then
          edit_err = _("Source URL must start with http:// or https://.")
        end
        if edit_err then
          set_err(edit_err); set_info(nil)
          http.redirect(disp.build_url("admin","network","tproxy_manager") .. "?tab=updates&_geo_edit_idx=" .. tostring(idx))
          return m
        end
        rows[idx].name = (http.formvalue("edit_name") or "")
        rows[idx].url  = url
        rows[idx].dest = dest
        local ok, why, detail, sdir = geo_persist(rows)
        report_geo(ctx, ok, why, _("Source updated:").." "..(rows[idx].name or rows[idx].dest), detail, sdir)
      end
      redirect_here("updates"); return m
    end

    if http.formvalue("_geo_cancel_edit") == "1" then
      -- Drop any banner from the previous action: a cancel that leaves the
      -- earlier "saved" message on screen reads as if it had saved something.
      set_err(nil); set_info(nil)
      redirect_here("updates"); return m
    end

    if http.formvalue("_geo_delete") then
      local idx = tonumber(http.formvalue("_geo_delete"))
      local rows, err = load_rows_again()
      if err then
        set_err(_("GEO list was not parsed:").." " .. err); set_info(nil)
        redirect_here("updates"); return m
      end
      if idx and rows[idx] then
        local name = rows[idx].name or rows[idx].dest
        table.remove(rows, idx)
        local ok, why, detail, sdir = geo_persist(rows)
        report_geo(ctx, ok, why, _("Source deleted:").." "..(name or ("#"..tostring(idx))), detail, sdir)
      end
      redirect_here("updates"); return m
    end

    if http.formvalue("_geo_save") == "1" then
      local raw = http.formvalue("geo_sources") or "[]"
      local data, err = parse_jsonc_or_error(raw)
      if not data then
        set_err(_("GEO list was not saved:").." " .. err)
        set_info(nil)
        redirect_here("updates"); return m
      end
      local rows = normalize_rows(data)
      local ok, why, detail, sdir = geo_persist(rows)
      report_geo(ctx, ok, why, _("Source list saved"), detail, sdir)
      redirect_here("updates"); return m
    end

    if http.formvalue("_geo_write_script") == "1" then
      local rows, err = load_rows_again()
      if err then
        set_err(_("GEO list was not parsed:").." " .. err); set_info(nil)
        redirect_here("updates"); return m
      end
      local wrote, wwhy = write_geo_script(rows)
      report_geo(ctx, wrote, wwhy, _("Update script recreated"))
      redirect_here("updates"); return m
    end

    if http.formvalue("_geo_install_cron") == "1" then
      local rows, err = load_rows_again()
      if err then
        set_err(_("GEO list was not parsed:").." " .. err); set_info(nil)
        redirect_here("updates"); return m
      end
      local spec = (http.formvalue("geo_cron") or ""):gsub("%s+"," ")
      if spec == "" then spec = "0 5 * * *" end
      local normalized, cron_err = validate_cron_spec(spec)
      if not normalized then
        set_err(cron_err); set_info(nil)
      else
        -- The script has to exist before the schedule points at it: a cron
        -- entry installed alongside a failed script write is a job that fails
        -- silently every night.
        local wrote, wwhy = write_geo_script(rows)
        if not wrote then
          set_info(nil); set_err(_("Failed to save settings."))
        else
          local ok, why = cron_install(normalized)
          if ok and wwhy == "permissions" then why = "permissions" end
          report_geo(ctx, ok, why, _("Cron installed:").." "..normalized)
        end
      end
      redirect_here("updates"); return m
    end

    if http.formvalue("_geo_remove_cron") == "1" then
      local ok, why = cron_remove()
      report_geo(ctx, ok, why, _("Cron removed"))
      redirect_here("updates"); return m
    end

    -- The shared err/info banner is already rendered by manage.lua at the
    -- bottom of the page (single render point for all tabs) — here we only
    -- show the GEO-tab-specific geo-sources.conf parse error, without
    -- re-rendering get_err()/get_info(), which used to duplicate the same
    -- message twice on screen.
    if cfg_err and cfg_err ~= "" then
      local sec = m:section(SimpleSection)
      local dv = sec:option(DummyValue, "_geo_cfg_err"); dv.rawhtml = true; dv.title = ""
      function dv.cfgvalue()
        return "<div class='msg err'>" .. _("Invalid JSON/JSONC in").." " .. pcdata(GEO_CFG) .. ": " .. pcdata(cfg_err) .. "</div>"
      end
    end
  end
end

return { render = render }
