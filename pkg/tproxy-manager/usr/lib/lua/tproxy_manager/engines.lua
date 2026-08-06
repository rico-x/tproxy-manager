local sys = require "luci.sys"

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
    proxy_url = "socks5h://127.0.0.1:10808"
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
    proxy_url = "socks5h://127.0.0.1:10808"
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
    proxy_url = "socks5h://127.0.0.1:10808"
  }
}

local function trim(value)
  return tostring(value or ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
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
  for legacy, profile in pairs(map) do
    local value = uci:get(pkg, "main", legacy)
    if value ~= nil and value ~= false and value ~= "" then
      uci:set(pkg, "main", id .. "_profile_" .. profile, value)
    end
  end
end

function M.apply_profile_to_legacy(uci, pkg, id)
  id = M.normalize(id)
  local def = M.def(id)
  local service_path = M.profile_value(uci, pkg, id, "service_path")
  local test_command = M.profile_value(uci, pkg, id, "test_command")
  local outbound_file = M.profile_value(uci, pkg, id, "outbound_file")
  local tproxy_port = M.profile_value(uci, pkg, id, "tproxy_port")
  local proxy_url = M.profile_value(uci, pkg, id, "proxy_url")

  uci:set(pkg, "main", "proxy_engine", id)
  uci:set(pkg, "main", "watchdog_service_path", service_path)
  uci:set(pkg, "main", "watchdog_test_command", test_command)
  uci:set(pkg, "main", "watchdog_outbound_file", outbound_file)
  uci:set(pkg, "main", "watchdog_proxy_url", proxy_url ~= "" and proxy_url or def.proxy_url)
  if tproxy_port ~= "" then
    uci:set(pkg, "main", "tproxy_port", tproxy_port)
    uci:delete(pkg, "main", "tproxy_port_tcp")
    uci:delete(pkg, "main", "tproxy_port_udp")
  end
end

local function service_op(path, op)
  path = trim(path)
  if path == "" or sys.call("[ -x " .. shellescape(path) .. " ]") ~= 0 then return false end
  sys.call(shellescape(path) .. " " .. op .. " >/dev/null 2>&1")
  return true
end

function M.stop_inactive_services(uci, pkg, active_id)
  active_id = M.normalize(active_id)
  for _, id in ipairs(M.ORDER) do
    local def = M.def(id)
    if id ~= active_id then
      service_op(M.profile_value(uci, pkg, id, "service_path"), "stop")
      service_op(def.service_path, "stop")
      service_op(def.native_service_path, "stop")
    end
  end
end

function M.activate(uci, pkg, target_id)
  target_id = M.normalize(target_id)
  local current = M.current(uci, pkg)
  local st = M.status(uci, pkg, target_id)
  if not st.installed then
    return false, "Binary is not installed: " .. M.def(target_id).binary
  end
  M.save_legacy_to_profile(uci, pkg, current)
  M.apply_profile_to_legacy(uci, pkg, target_id)
  uci:commit(pkg)

  M.stop_inactive_services(uci, pkg, target_id)
  service_op(M.profile_value(uci, pkg, target_id, "service_path"), "start")
  service_op("/etc/init.d/tproxy-manager", "restart")
  service_op("/etc/init.d/tproxy-manager-watchdog", "restart")
  return true, M.def(target_id).label
end

M.trim = trim
M.shellescape = shellescape

return M
