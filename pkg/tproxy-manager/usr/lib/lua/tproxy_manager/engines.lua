local sys = require "luci.sys"
local utils = require "luci.model.cbi.tproxy_manager.utils"

local M = {}

M.ORDER = { "xray", "mihomo", "singbox" }

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
    version_script = "/usr/bin/tproxy-manager-xray-version.lua"
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
    version_script = "/usr/bin/tproxy-manager-mihomo-version.lua"
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
    version_script = "/usr/bin/tproxy-manager-singbox-version.lua"
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

function M.service_running(service_path)
  local txt = init_status(service_path)
  local s = txt:lower()
  if txt == "missing" or s:match("not[%s%-_]*running") or s:match("stopped") then return false end
  return s:find("%f[%a]running%f[%A]") ~= nil
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

function M.save_legacy_to_profile(uci, pkg, id)
  id = M.normalize(id)
  local map = {
    watchdog_service_path = "service_path",
    watchdog_test_command = "test_command",
    watchdog_outbound_file = "outbound_file",
    watchdog_proxy_url = "proxy_url",
    tproxy_port = "tproxy_port"
  }
  -- Report whether the profile was staged in full. A partially written
  -- profile is worse than none: the missing fields silently fall back to the
  -- other engine's values on the next switch.
  local ok = true
  for legacy, profile in pairs(map) do
    local value = uci:get(pkg, "main", legacy)
    if value ~= nil and value ~= false and value ~= "" then
      if not uci:set(pkg, "main", id .. "_profile_" .. profile, value) then ok = false end
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

-- service_running: ask the init script itself, matching how the UI decides.
local function service_running(path)
  path = trim(path)
  if path == "" then return false end
  local txt = sys.exec(string.format("[ -x %s ] && %s status 2>&1 || echo N/A",
    shellescape(path), shellescape(path))) or ""
  txt = txt:lower()
  if txt:match("not[%s%-_]*running") or txt:match("stopped") then return false end
  return txt:find("%f[%a]running%f[%A]") ~= nil
end

local function service_exists(path)
  path = trim(path)
  return path ~= "" and sys.call("[ -x " .. shellescape(path) .. " ]") == 0
end

-- The services that must follow the engine switch: TPROXY has to be rebuilt
-- against the new port, and the watchdog has to probe the new engine.
local STACK_SERVICES = {
  { path = "/etc/init.d/tproxy-manager",          label = "tproxy-manager" },
  { path = "/etc/init.d/tproxy-manager-watchdog", label = "tproxy-manager-watchdog" },
}

-- restart_stack: returns a comma-separated list of units that exist but
-- refused to restart. A unit that is not installed is not a failure, but a
-- unit that failed must never be swallowed: it leaves TPROXY pointing at the
-- old port while the UI claims the switch is complete.
local function restart_stack()
  local failed = {}
  for _, svc in ipairs(STACK_SERVICES) do
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
  return not service_running(path)
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
  if not service_running(prev_svc) then
    problems[#problems + 1] = { code = "previous_not_up", engine = M.def(current).label }
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
  service_op(target_svc, "start")
  if not service_running(target_svc) then
    local code, params = rollback_activation(uci, pkg, current, target_id, target_svc)
    params.stuck = (stuck ~= "" and stuck or nil)
    return false, code, params
  end

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
