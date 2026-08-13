local sys = require "luci.sys"
local fs = require "nixio.fs"
local utils = require "luci.model.cbi.tproxy_manager.utils"

local M = {}

M.ORDER = { "xray", "mihomo", "singbox" }

-- Everything the watchdog needs in order to probe a link with a given engine
-- lives here, next to the rest of that engine's definition. The shell side asks
-- for it through /usr/libexec/tproxy-manager/engine-probe-info instead of
-- carrying a second copy of this table, which is how the probe used to end up
-- running Xray no matter which engine was active.
--
--   probe_kind      which renderer builds the probe config
--   probe_log       name of the test instance's log file
--   probe_ext       extension the engine expects for that config
--   protocols       link protocols this engine can actually run
--   probe_batch     whether one process can probe many links at once
--
-- And the config layout, which is the same model for all three: a directory of
-- fragments by role, of which the package rewrites exactly one.
--
--   config_dir      the directory the engine's configuration lives in
--   managed_file    the ONLY file the package rewrites -- the applied link
--   user_file       the fragment that belongs to the user and is never written
--   assembled_file  set only when the engine cannot read a directory itself
M.DEFS = {
  xray = {
    id = "xray",
    label = "Xray",
    tab = "xray",
    binary = "xray",
    binary_paths = { "/usr/bin/xray", "/usr/sbin/xray" },
    service_name = "xray",
    service_path = "/etc/init.d/xray",
    test_command = "/usr/bin/xray -c {config}",
    outbound_file = "/etc/xray/04_outbounds.json",
    tproxy_port = "61219",
    proxy_url = "socks5h://127.0.0.1:10808",
    version_script = "/usr/bin/tproxy-manager-xray-version.lua",
    probe_kind = "template",
    probe_log = "xray-test.log",
    probe_ext = "json",
    -- Xray carries Hysteria 2 as a stream transport rather than an outbound
    -- protocol, so it needs its own pair of templates for it. The other two
    -- engines take it as a first-class outbound.
    protocols = { "vless", "hy2" },
    probe_batch = true,
    -- Xray reads the directory itself with -confdir and concatenates arrays
    -- across files, so nothing has to be assembled.
    config_dir = "/etc/xray",
    managed_file = "/etc/xray/04_outbounds.json",
    user_file = "/etc/xray/03_outbounds_user.json"
  },
  mihomo = {
    id = "mihomo",
    label = "Mihomo",
    tab = "mihomo",
    binary = "mihomo",
    binary_paths = { "/usr/bin/mihomo", "/usr/sbin/mihomo" },
    service_name = "tproxy-manager-mihomo",
    service_path = "/etc/init.d/tproxy-manager-mihomo",
    native_service_name = "mihomo",
    native_service_path = "/etc/init.d/mihomo",
    test_command = "/usr/bin/mihomo -f {config}",
    outbound_file = "/etc/mihomo/tproxy-manager-proxies.yaml",
    config_file = "/etc/mihomo/tproxy-manager.yaml",
    managed_provider_file = "/etc/mihomo/tproxy-manager-proxies.yaml",
    controller = "http://127.0.0.1:9090",
    tproxy_port = "61219",
    proxy_url = "socks5h://127.0.0.1:10808",
    version_script = "/usr/bin/tproxy-manager-mihomo-version.lua",
    probe_kind = "mihomo",
    probe_log = "mihomo-test.log",
    probe_ext = "yaml",
    protocols = { "vless", "hy2" },
    probe_batch = true,
    -- Mihomo has no directory mode, so the fragments are concatenated into
    -- assembled_file before it starts. The managed part is deliberately OUTSIDE
    -- the directory: it is pulled in by a file provider, which keeps it off the
    -- `proxies:` key the user's own fragment uses -- concatenating two fragments
    -- under one key would silently keep only the last.
    config_dir = "/etc/mihomo/tproxy-manager.d",
    assembled_file = "/etc/mihomo/tproxy-manager.yaml",
    managed_file = "/etc/mihomo/tproxy-manager-proxies.yaml",
    user_file = "/etc/mihomo/tproxy-manager.d/03-proxies-user.yaml"
  },
  singbox = {
    id = "singbox",
    label = "sing-box",
    tab = "singbox",
    binary = "sing-box",
    binary_paths = { "/usr/bin/sing-box", "/usr/sbin/sing-box" },
    service_name = "tproxy-manager-sing-box",
    service_path = "/etc/init.d/tproxy-manager-sing-box",
    native_service_name = "sing-box",
    native_service_path = "/etc/init.d/sing-box",
    test_command = "/usr/bin/sing-box run -c {config}",
    outbound_file = "/etc/sing-box/tproxy-manager-outbounds.json",
    config_file = "/etc/sing-box/tproxy-manager.json",
    base_config_file = "/etc/sing-box/config.json",
    managed_outbounds_file = "/etc/sing-box/tproxy-manager-outbounds.json",
    controller = "http://127.0.0.1:9091",
    tproxy_port = "61219",
    proxy_url = "socks5h://127.0.0.1:10808",
    version_script = "/usr/bin/tproxy-manager-singbox-version.lua",
    probe_kind = "singbox",
    probe_log = "singbox-test.log",
    probe_ext = "json",
    protocols = { "vless", "hy2" },
    probe_batch = true,
    -- sing-box reads the directory with -C and concatenates arrays across
    -- fragments, verified on a router: nothing has to be assembled.
    config_dir = "/etc/sing-box/tproxy-manager.d",
    managed_file = "/etc/sing-box/tproxy-manager.d/04-outbounds-managed.json",
    user_file = "/etc/sing-box/tproxy-manager.d/03-outbounds-user.json"
  }
}

local function trim(value)
  -- Assigning first truncates gsub's second return value (the replacement
  -- count). Returning it straight through made every caller receive two
  -- values, and `tonumber(trim(x))` then read that count as the numeric
  -- base -- an outright error for a count of 0 or 1.
  local text = tostring(value or ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
  return text
end

local function shellescape(value)
  value = tostring(value or "")
  if value == "" then return "''" end
  return "'" .. value:gsub("'", "'\\''") .. "'"
end

function M.normalize(id)
  id = trim(id):lower()
  if id == "sing-box" or id == "sing_box" then id = "singbox" end
  if M.DEFS[id] then return id end
  return "xray"
end

function M.def(id)
  return M.DEFS[M.normalize(id)]
end

function M.command_path(command, candidates)
  for _, path in ipairs(candidates or {}) do
    if sys.call("[ -x " .. shellescape(path) .. " ]") == 0 then
      return path
    end
  end
  local out = trim(sys.exec("command -v " .. shellescape(command) .. " 2>/dev/null") or "")
  return out ~= "" and out or ""
end

function M.binary_path(id)
  local def = M.def(id)
  return M.command_path(def.binary, def.binary_paths)
end

local function init_status(service_path)
  service_path = trim(service_path)
  if service_path == "" or sys.call("[ -x " .. shellescape(service_path) .. " ]") ~= 0 then
    return "missing"
  end
  return trim(sys.exec(shellescape(service_path) .. " status 2>&1") or "")
end

-- service_state: ask the init script itself, matching how the UI decides.
--
--   missing       no executable init script at that path
--   no_instances  procd took the service but started nothing. Its own config has
--                 the service disabled -- seen on a router whose sing-box profile
--                 pointed at the NATIVE /etc/init.d/sing-box, which is shipped
--                 disabled: start returned 0 and nothing ran.
--   running       up
--   stopped       everything else
function M.service_state(path)
  path = trim(path)
  if path == "" then return "missing" end
  -- Existence is checked on its own. Folded into the status call as
  -- `[ -x p ] && p status || echo missing`, the fallback also fires when the
  -- script EXISTS and its status merely exits non-zero -- which is what procd
  -- does for "active with no instances", so a present-but-disabled service was
  -- reported to the user as a missing init script.
  if sys.call("[ -x " .. shellescape(path) .. " ]") ~= 0 then return "missing" end
  local txt = (sys.exec(shellescape(path) .. " status 2>&1") or ""):lower()
  if txt:find("no instances", 1, true) then return "no_instances" end
  if txt:match("not[%s%-_]*running") or txt:match("stopped") then return "stopped" end
  if txt:find("%f[%a]running%f[%A]") ~= nil then return "running" end
  return "stopped"
end

-- One predicate, deliberately. There used to be two implementations of "is it
-- running", and the wait added for slow-starting engines polled the other one --
-- so the wait could disagree with the check it existed to serve.
function M.service_running(path)
  return M.service_state(path) == "running"
end

function M.service_enabled(service_path)
  service_path = trim(service_path)
  if service_path == "" or sys.call("[ -x " .. shellescape(service_path) .. " ]") ~= 0 then return false end
  return sys.call(shellescape(service_path) .. " enabled >/dev/null 2>&1") == 0
end

local function uci_get(uci, pkg, key, fallback)
  local v = uci:get(pkg, "main", key)
  if v ~= nil and v ~= false and v ~= "" then return v end
  return fallback
end

function M.profile_value(uci, pkg, id, name)
  id = M.normalize(id)
  local def = M.def(id)
  local key = id .. "_profile_" .. name
  return uci_get(uci, pkg, key, def[name] or "")
end

function M.current(uci, pkg)
  return M.normalize(uci_get(uci, pkg, "proxy_engine", "xray"))
end

function M.status(uci, pkg, id)
  id = M.normalize(id)
  local def = M.def(id)
  local binary = M.binary_path(id)
  local service_path = M.profile_value(uci, pkg, id, "service_path")
  return {
    id = id,
    label = def.label,
    binary = binary,
    installed = binary ~= "",
    service_path = service_path,
    service_status = init_status(service_path),
    running = M.service_running(service_path),
    enabled = M.service_enabled(service_path)
  }
end

-- True when the live (legacy) keys really describe engine `id`. The switch saves
-- the live keys into the current engine's profile, so if the two ever disagree --
-- proxy_engine says one engine while watchdog_service_path points at another --
-- that save writes the WRONG engine's values into the profile. After that the UI
-- reports a foreign service's state for that engine and an activation "succeeds"
-- while starting the other engine's service. Observed for real after an external
-- script set proxy_engine without updating the rest.
local function legacy_describes(uci, pkg, id)
  local live = uci:get(pkg, "main", "watchdog_service_path")
  if live == nil or live == false or live == "" then return true end
  local def = M.def(id)
  if not def then return true end
  -- A user may legitimately point an engine at their own init script, so the
  -- check accepts the profile's own stored path as well as the built-in ones.
  local allowed = {
    def.service_path, def.native_service_path,
    M.profile_value(uci, pkg, id, "service_path"),
  }
  for __, candidate in ipairs(allowed) do
    if candidate ~= nil and candidate ~= "" and candidate == live then return true end
  end
  -- If it matches ANOTHER engine's definition, the live keys are definitely not
  -- this engine's.
  for __, other in ipairs(M.ORDER) do
    if other ~= id then
      local odef = M.def(other)
      if odef and (odef.service_path == live or odef.native_service_path == live) then
        return false
      end
    end
  end
  return true
end

-- True when a live check command plainly belongs to a DIFFERENT engine: it either
-- is another engine's built-in command, or it names another engine's binary. The
-- live key can hold such a value after a restored backup, a hand edit, or a form
-- that re-submitted whatever its input happened to show, and copying it into the
-- active engine's profile destroys the one correct copy of that command.
-- The program a check command runs, by name. The executable is the first token and
-- everything after it is flags, so this recognises "/usr/bin/xray -c ...",
-- "/usr/sbin/xray ..." and a bare "xray ..." alike.
local function command_binary(value)
  local token = trim(value):match("^%S+") or ""
  token = token:gsub("^[\"']", ""):gsub("[\"']$", "")
  return token:match("([^/]+)$") or token
end

local function command_describes_other(value, id)
  value = trim(value)
  if value == "" then return false end
  local def = M.DEFS[id]
  local bin = command_binary(value)
  -- The active engine's own program settles it. Matching another engine's name
  -- ANYWHERE in the string would have called "/usr/bin/mihomo -f /etc/xray/x.yaml"
  -- foreign and quietly dropped a perfectly good command.
  if def and bin ~= "" and bin == def.binary then return false end
  for _, other in ipairs(M.ORDER) do
    if other ~= id then
      local odef = M.DEFS[other]
      if odef then
        if trim(odef.test_command) == value then return true end
        if bin ~= "" and bin == odef.binary then return true end
      end
    end
  end
  return false
end

-- opts.edited states, per live key, whether the user changed it in this request.
-- For watchdog_test_command the three possible answers mean three different things:
--
--   true   an explicit edit. Copied as asked -- the user's decision, even when the
--          value looks like another engine's.
--   false  the field was not touched. NOT copied at all. The profile is the
--          authority, and nothing about the live key's text can prove it belongs to
--          this engine: a stale value may be a wrapper, a rename, or a command that
--          was correct two switches ago. Guessing is what let
--          "/opt/bin/xray-wrapper -c {config}" through and overwrite the correct
--          mihomo_profile_test_command.
--   nil    no answer, which is the older callers. The text-based heuristic below is
--          the best available guess and stays for them.
--
-- Every other field syncs regardless.
function M.save_legacy_to_profile(uci, pkg, id, opts)
  id = M.normalize(id)
  if not legacy_describes(uci, pkg, id) then
    -- Keep the existing profile rather than overwriting it with another engine's
    -- values. Reported as success: there is nothing new worth saving, and failing
    -- here would block a switch that is otherwise fine.
    return true
  end
  local map = {
    watchdog_service_path = "service_path",
    watchdog_test_command = "test_command",
    watchdog_outbound_file = "outbound_file",
    watchdog_proxy_url = "proxy_url",
    tproxy_port = "tproxy_port"
  }
  local edited = (opts and opts.edited) or {}
  -- Report whether the profile was staged in full. A partially written
  -- profile is worse than none: the missing fields silently fall back to the
  -- other engine's values on the next switch.
  local ok = true
  for legacy, profile in pairs(map) do
    local value = uci:get(pkg, "main", legacy)
    if value ~= nil and value ~= false and value ~= "" then
      local skip = false
      if legacy == "watchdog_test_command" then
        local was_edited = edited[legacy]
        if was_edited == false then
          -- Stated as untouched: skip outright. Reaching for the heuristic here was
          -- the bug -- it can only recognise a command that NAMES a known engine,
          -- so any wrapper script sailed past it.
          skip = true
        elseif was_edited == nil then
          skip = command_describes_other(value, id)
        end
      end
      if not skip then
        if not uci:set(pkg, "main", id .. "_profile_" .. profile, value) then ok = false end
      end
    end
  end
  return ok
end

function M.apply_profile_to_legacy(uci, pkg, id)
  id = M.normalize(id)
  local def = M.def(id)
  local service_path = M.profile_value(uci, pkg, id, "service_path")
  local test_command = M.profile_value(uci, pkg, id, "test_command")
  local outbound_file = M.profile_value(uci, pkg, id, "outbound_file")
  local tproxy_port = M.profile_value(uci, pkg, id, "tproxy_port")
  local proxy_url = M.profile_value(uci, pkg, id, "proxy_url")

  -- Staged as a set: half of this applied means the watchdog probes one
  -- engine while TPROXY forwards to another, so the caller has to be able to
  -- tell that the switch was never fully described.
  local ok = true
  local function S(k, v)
    if not uci:set(pkg, "main", k, v) then ok = false end
  end
  S("proxy_engine", id)
  S("watchdog_service_path", service_path)
  S("watchdog_test_command", test_command)
  S("watchdog_outbound_file", outbound_file)
  S("watchdog_proxy_url", proxy_url ~= "" and proxy_url or def.proxy_url)
  if tproxy_port ~= "" then
    S("tproxy_port", tproxy_port)
    -- uci:delete answers false when the option is simply not there, which is
    -- the normal case in non-split mode. Only the RESULT counts, or every
    -- switch would be refused as a staging failure.
    if not utils.uci_unset(uci, pkg, "main", "tproxy_port_tcp") then ok = false end
    if not utils.uci_unset(uci, pkg, "main", "tproxy_port_udp") then ok = false end
  end
  return ok
end

-- Returns the REAL exit status of the init script. It used to return true
-- unconditionally, so a failed start was indistinguishable from a
-- successful one and activation reported success while TPROXY pointed at a
-- dead engine.
local function service_op(path, op)
  path = trim(path)
  if path == "" or sys.call("[ -x " .. shellescape(path) .. " ]") ~= 0 then return false end
  return sys.call(shellescape(path) .. " " .. op .. " >/dev/null 2>&1") == 0
end


-- An init script returns as soon as it has spawned the process, but the engine is
-- not up yet: these load 20 MB of GeoIP/GeoSite at start, and on this router Xray
-- needed more than three seconds before it answered through the proxy. The engine
-- being replaced may also still hold the SOCKS and TPROXY ports, in which case the
-- target dies on bind within the first moment.
--
-- Asking once, immediately after "start", turned both into "the engine refused to
-- start" and rolled back a switch that was fine. Observed in the UI: sing-box
-- reported as not starting while the very same config ran for as long as it was
-- given a second to bind.
local START_GRACE = 12

local function wait_service_running(path, seconds)
  if M.service_running(path) then return true end
  for _ = 1, (seconds or START_GRACE) do
    -- sleep, not a busy loop: this runs inside a LuCI request.
    sys.call("sleep 1")
    if M.service_running(path) then return true end
  end
  return false
end


local function service_exists(path)
  path = trim(path)
  return path ~= "" and sys.call("[ -x " .. shellescape(path) .. " ]") == 0
end

-- The services that must follow the engine switch: TPROXY has to be rebuilt
-- against the new port, and the watchdog has to probe the new engine.
-- Public for the same reason DEFS is: the activation test points it at stub
-- init scripts so a suite run cannot restart the live stack.
M.STACK_SERVICES = {
  { path = "/etc/init.d/tproxy-manager",          label = "tproxy-manager" },
  { path = "/etc/init.d/tproxy-manager-watchdog", label = "tproxy-manager-watchdog" },
}

-- restart_stack: returns a comma-separated list of units that exist but
-- refused to restart. A unit that is not installed is not a failure, but a
-- unit that failed must never be swallowed: it leaves TPROXY pointing at the
-- old port while the UI claims the switch is complete.
local function restart_stack()
  local failed = {}
  for _, svc in ipairs(M.STACK_SERVICES) do
    if service_exists(svc.path) and not service_op(svc.path, "restart") then
      failed[#failed + 1] = svc.label
    end
  end
  return table.concat(failed, ", ")
end

-- stop_service_verified: a stop is judged by whether the service is actually
-- down afterwards, not by the init script's exit code. Two engines bound to
-- the same TPROXY port is the failure this guards against: the survivor keeps
-- the port and the engine the user selected never gets it.
local function stop_service_verified(path)
  path = trim(path)
  if path == "" or not service_exists(path) then return true end
  service_op(path, "stop")
  -- The init script returns once it has signalled the process, which may still be
  -- alive and holding the TPROXY and SOCKS ports for a moment. Reported stopped
  -- straight away, the engine taking over could die on bind -- so the state has to
  -- settle before this answers, and the answer stays honest if it never does.
  for _ = 1, 6 do
    if not M.service_running(path) then return true end
    sys.call("sleep 1")
  end
  return not M.service_running(path)
end

-- Returns the list of engine labels that would not stop, so the caller can
-- report a switch that only half happened.
function M.stop_inactive_services(uci, pkg, active_id)
  active_id = M.normalize(active_id)
  local stuck = {}
  for _, id in ipairs(M.ORDER) do
    local def = M.def(id)
    if id ~= active_id then
      local ok = true
      for _, path in ipairs({
        M.profile_value(uci, pkg, id, "service_path"),
        def.service_path,
        def.native_service_path,
      }) do
        if not stop_service_verified(path) then ok = false end
      end
      if not ok then stuck[#stuck + 1] = def.label end
    end
  end
  return table.concat(stuck, ", ")
end

-- Exactly one engine may start at boot. Activation stopped the other engines but
-- left their rc.d links in place, so after a reboot two engines raced for the
-- TPROXY port and whichever won decided how traffic was routed. Autostart is
-- therefore part of the switch: on for the active engine, off for the rest.
--
-- Every candidate path is disabled, not just the profile one: an engine may have
-- both a package init script and a native one, and either could carry the link.
function M.align_autostart(uci, pkg, active_id)
  active_id = M.normalize(active_id)
  local failed = {}
  for _, id in ipairs(M.ORDER) do
    local def = M.def(id)
    local seen = {}
    local paths = {}
    for _, path in ipairs({
      M.profile_value(uci, pkg, id, "service_path"),
      def.service_path,
      def.native_service_path,
    }) do
      if path ~= nil and path ~= "" and not seen[path] then
        seen[path] = true
        paths[#paths + 1] = path
      end
    end
    if id == active_id then
      -- Only the profile/definition path is enabled: enabling a native script as
      -- well would start a second instance of the same engine.
      local target = paths[1]
      if target and service_exists(target) then
        service_op(target, "enable")
        if not M.service_enabled(target) then failed[#failed + 1] = def.label end
      end
    else
      for _, path in ipairs(paths) do
        if service_exists(path) and M.service_enabled(path) then
          service_op(path, "disable")
          if M.service_enabled(path) then failed[#failed + 1] = def.label .. " (" .. path .. ")" end
        end
      end
    end
  end
  return table.concat(failed, ", ")
end

-- Engines whose autostart is on. Used by the UI to report the conflict when the
-- state predates this check or was changed by hand.
-- Link probe results are per-engine, and only the "unsupported" ones are: alive
-- and dead were measured against a real server and stay meaningful. Removing the
-- state file entirely leaves the link as "not checked", which is what it is.
M.LINK_STATE_DIR = "/tmp/tproxy-manager-watchdog-links"

function M.clear_unsupported_link_states(dir)
  dir = dir or M.LINK_STATE_DIR
  local it = fs.dir(dir)
  if not it then return 0 end
  local names = {}
  for name in it do
    if name:match("%.state$") then names[#names + 1] = name end
  end
  local cleared = 0
  for _, name in ipairs(names) do
    local path = dir .. "/" .. name
    local text = fs.readfile(path) or ""
    -- Anchored to a line start so a reason text that happens to contain the word
    -- cannot be mistaken for the status field.
    if text:match("\nLAST_STATUS=unsupported\n") or text:match("^LAST_STATUS=unsupported\n") then
      if fs.remove(path) then cleared = cleared + 1 end
    end
  end
  return cleared
end

function M.autostart_conflicts(uci, pkg)
  local on = {}
  for _, id in ipairs(M.ORDER) do
    local def = M.def(id)
    local seen = {}
    for _, path in ipairs({
      M.profile_value(uci, pkg, id, "service_path"),
      def.service_path,
      def.native_service_path,
    }) do
      if path ~= nil and path ~= "" and not seen[path] then
        seen[path] = true
        if service_exists(path) and M.service_enabled(path) then
          on[#on + 1] = { id = id, label = def.label, path = path }
          break
        end
      end
    end
  end
  return on
end

-- run_version_script: shells out to a version-manager helper (same helpers
-- used by the per-engine "Update to latest"/"Install selected version"
-- buttons, e.g. tproxy-manager-mihomo-version.lua) and captures rc+output,
-- same convention as run_cmd_capture() in the xray/mihomo/singbox CBI modules.
local function run_version_script(script, args)
  script = trim(script)
  if script == "" then return 1, "version manager script is not configured" end
  local parts = { shellescape(script) }
  for _, a in ipairs(args or {}) do
    parts[#parts + 1] = shellescape(a)
  end
  local marker = "__TPM_ENGINE_RC__:"
  local wrapped = string.format("(%s) 2>&1; printf '\\n%s%%s' \"$?\"", table.concat(parts, " "), marker)
  local out = trim(sys.exec(wrapped) or "")
  local rc = tonumber(out:match(marker .. "([%-%d]+)%s*$")) or 1
  out = out:gsub("\n?" .. marker .. "[%-%d]+%s*$", "")
  return rc, trim(out)
end

local function parse_kv(text)
  local data = {}
  for line in ((text or "") .. "\n"):gmatch("([^\n]*)\n") do
    local k, v = line:match("^([A-Za-z0-9_]+)=(.*)$")
    if k then data[k] = v end
  end
  return data
end

-- install_latest: resolve the engine's latest stable release tag via its
-- version-manager script and install it — the exact same two-step sequence
-- ("status --refresh" to learn LATEST_TAG, then "install <tag>") already used
-- by each engine's own "Update to latest" button, just callable without
-- needing to be on that engine's own tab.
function M.install_latest(id)
  id = M.normalize(id)
  local def = M.def(id)
  local script = def.version_script
  if not script or trim(script) == "" then
    return false, "no_version_manager", { engine = def.label }
  end
  local rc, out = run_version_script(script, { "status", "--refresh" })
  local status = parse_kv(out)
  local tag = trim(status.LATEST_TAG or "")
  if rc ~= 0 or tag == "" then
    return false, "latest_unavailable", { engine = def.label, out = out }
  end
  local install_rc, install_out = run_version_script(script, { "install", tag })
  if install_rc ~= 0 then
    return false, "install_failed", { engine = def.label, out = install_out }
  end
  return true, "installed", { engine = def.label, out = install_out }
end

-- rollback_activation: undo a switch whose target engine refused to start,
-- and report what actually happened. Every step used to be fire-and-forget,
-- so the UI could print "reverted to Xray" while the config still described
-- the dead engine and nothing was running. Reporting a rollback that did not
-- happen is worse than reporting the original failure: the next boot would
-- start the broken engine again with nobody expecting it.
local function rollback_activation(uci, pkg, current, target_id, target_svc)
  local problems = {}

  if not M.apply_profile_to_legacy(uci, pkg, current) then
    uci:revert(pkg)
    problems[#problems + 1] = { code = "restore_failed" }
  else
    local restored, why = utils.commit_uci(uci, pkg)
    if not restored and why == "commit" then
      uci:revert(pkg)
      problems[#problems + 1] = { code = "restore_failed" }
    elseif not restored then
      -- The rollback IS on disk, only chmod failed. Silently dropping this
      -- left /etc/config/tproxy-manager world-readable with the proxy
      -- credentials in it, right after an operation the user already knows
      -- went wrong.
      problems[#problems + 1] = { code = "restore_permissions" }
    end
  end

  -- The failed engine must be down before the previous one is brought back:
  -- both bind the same TPROXY port, and a target that ignored "stop" would
  -- keep it and make the recovery look like a second failure.
  if not stop_service_verified(target_svc) then
    problems[#problems + 1] = { code = "target_not_stopped", engine = M.def(target_id).label }
  end

  local prev_svc = M.profile_value(uci, pkg, current, "service_path")
  service_op(prev_svc, "start")
  if not wait_service_running(prev_svc) then
    problems[#problems + 1] = { code = "previous_not_up", engine = M.def(current).label }
  end

  -- Boot must follow the engine that is actually running again. This is belt and
  -- braces: activate() now aligns autostart only after a verified start, but any
  -- other path into a rollback must not leave the failed engine set to start.
  local autostart_failed = M.align_autostart(uci, pkg, current)
  if autostart_failed ~= "" then
    problems[#problems + 1] = { code = "autostart_not_restored", services = autostart_failed }
  end

  local failed = restart_stack()
  if failed ~= "" then
    problems[#problems + 1] = { code = "stack_not_restarted", services = failed }
  end

  if #problems == 0 then
    return "did_not_start_reverted",
      { target = M.def(target_id).label, previous = M.def(current).label }
  end
  return "rollback_incomplete",
    { target = M.def(target_id).label, problems = problems }
end

function M.activate(uci, pkg, target_id)
  target_id = M.normalize(target_id)
  local current = M.current(uci, pkg)
  local st = M.status(uci, pkg, target_id)
  if not st.installed then
    return false, "not_installed", { binary = M.def(target_id).binary }
  end
  -- Both halves must be staged in full before anything is committed: saving
  -- the outgoing engine's profile is what makes the switch reversible, and
  -- committing a partial one would lose the settings we are about to
  -- overwrite.
  local staged = M.save_legacy_to_profile(uci, pkg, current)
  if not M.apply_profile_to_legacy(uci, pkg, target_id) then staged = false end
  if not staged then
    uci:revert(pkg)
    return false, "stage_failed", {}
  end

  -- Commit BEFORE touching any service. If the config was not written, the
  -- services must not be switched: otherwise the router would be running
  -- the new engine while UCI still describes the old one, and the next
  -- start would silently revert the switch.
  local committed, why = utils.commit_uci(uci, pkg)
  if not committed and why == "commit" then
    uci:revert(pkg)
    return false, "commit_failed", {}
  end

  -- A previous engine that refuses to stop keeps the TPROXY port, so the new
  -- one cannot bind it. Reported rather than swallowed.
  local stuck = M.stop_inactive_services(uci, pkg, target_id)

  -- The engine must actually come up. Previously the start result was
  -- ignored, so a broken binary or config left TPROXY pointing at a dead
  -- engine while the UI said "activated".
  local target_svc = M.profile_value(uci, pkg, target_id, "service_path")
  local started = service_op(target_svc, "start")
  if not wait_service_running(target_svc) then
    -- One more attempt before the switch is called off: a start that died on a
    -- port the previous engine had not finished releasing will succeed now that
    -- the grace period above has passed.
    started = service_op(target_svc, "start")
    if not wait_service_running(target_svc, 6) then
      -- Why it did not come up, in the words of the init script -- captured BEFORE
      -- the rollback, which stops the target and leaves it reporting plain
      -- "inactive". Asked afterwards, the diagnosis was always lost.
      --
      -- Without it the message blamed the engine even when the script we were told
      -- to run does not exist, or ran and deliberately started nothing.
      local reason
      local state = M.service_state(target_svc)
      if state == "missing" then
        reason = "no_init_script"
      elseif state == "no_instances" then
        reason = "no_instances"
      elseif not started then
        reason = "start_failed"
      end

      local code, params = rollback_activation(uci, pkg, current, target_id, target_svc)
      params.stuck = (stuck ~= "" and stuck or nil)
      params.service_path = target_svc
      params.reason = reason
      return false, code, params
    end
  end

  -- Autostart follows the switch, and only once the target is verified up: doing
  -- it before the start check meant a failed switch rolled back UCI and the
  -- running process but left the boot pointing at the engine that just refused
  -- to start, so the next reboot came up on the broken one.
  local autostart_failed = M.align_autostart(uci, pkg, target_id)

  -- "Unsupported" is a statement about the engine that was active when the link
  -- was last checked, not about the link. Carried across a switch it would keep
  -- claiming a link is unusable when the engine now running handles it fine, so
  -- those results are dropped and the next scan measures them again.
  M.clear_unsupported_link_states()

  -- The engine is up, but the switch is only complete once TPROXY and the
  -- watchdog follow it. A failure here is not a reason to roll back a working
  -- engine, yet it must reach the user: silently ignoring it left TPROXY
  -- forwarding to the previous engine's port.
  local stack_failed = restart_stack()
  -- An engine left running alongside the new one belongs in the same warning:
  -- from the user's side both symptoms are "traffic still goes somewhere else".
  if stuck ~= "" then
    stack_failed = (stack_failed ~= "" and (stack_failed .. ", ") or "") .. stuck .. " (still running)"
  end
  -- An engine left in autostart is the same class of problem, just deferred to
  -- the next boot, so it travels in the same warning rather than staying silent.
  if autostart_failed ~= "" then
    stack_failed = (stack_failed ~= "" and (stack_failed .. ", ") or "") .. autostart_failed .. " (autostart)"
  end

  local warns = {}
  -- Permissions are reported separately from an outright failure: the switch
  -- DID happen, so this is not a refusal, but it must not read as clean
  -- success either.
  if not committed then warns[#warns + 1] = "permissions" end
  if stack_failed ~= "" then warns[#warns + 1] = "services" end
  if #warns > 0 then
    return true, M.def(target_id).label, table.concat(warns, "+"), stack_failed
  end
  return true, M.def(target_id).label
end

M.trim = trim
M.shellescape = shellescape

return M
