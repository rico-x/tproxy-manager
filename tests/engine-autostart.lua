#!/usr/bin/env lua
--
-- Regression suite for engine autostart during a switch.
--
-- Runs ON THE ROUTER: it needs the luci Lua tree. Use scripts/test-on-device.sh
-- to stage the working tree and execute this against it without touching the
-- installed package.
--
-- The invariant: exactly one engine may be armed for boot, and it must be the
-- one that is actually running. Two engines with an rc.d link raced for the
-- TPROXY port after a reboot, and whichever won decided how traffic was routed.
--
-- The subtle half is ORDERING. Autostart used to be aligned to the target
-- before the target was known to start, so a switch that failed rolled back UCI
-- and the running process but left boot pointing at the engine that had just
-- refused to start: `proxy_engine=xray` with `xray` disabled and the dead engine
-- enabled. The next reboot came up on the broken engine with nobody expecting
-- it. Cases below pin down both the end state and that ordering.
--
-- Safe on a live router. Every init script here is a stub in the suite's own
-- temp directory that records enable/start in marker files -- no rc.d link is
-- created, no engine is touched. DEFS, STACK_SERVICES and the profile paths are
-- all redirected, and UCI writes go to a throwaway package that is deleted at
-- the end.

local engines = require "tproxy_manager.engines"
local uci_mod = require "luci.model.uci"
local sys     = require "luci.sys"
local fs      = require "nixio.fs"

local BASE = os.getenv("TPM_TEST_BASE") or "/tmp/tpm-engine-autostart-test"
local PKG  = "tpm_autostart_test"
local CFG  = "/etc/config/" .. PKG

local pass, fail, failures = 0, 0, {}

local function check(name, got, want)
  local ok = (got == want)
  if ok then
    pass = pass + 1
  else
    fail = fail + 1
    failures[#failures + 1] = string.format("%s (got %s, want %s)", name, tostring(got), tostring(want))
  end
  print(string.format("  %-56s %s%s", name, ok and "PASS" or "FAIL",
    ok and "" or string.format("  <- got %s, want %s", tostring(got), tostring(want))))
end

local function group(name) print("\n== " .. name .. " ==") end

-- A stub init script speaking the subset of the rc.common interface engines.lua
-- uses. State lives beside the script, so "enabled" never means an rc.d link and
-- "running" never means a process. Refusals are injected by touching a marker,
-- which is how "the init script would not disable" is reproduced without a
-- broken system.
local STUB = [[#!/bin/sh
S="$0"
case "$1" in
  start)   [ -f "$S.refuse_start" ]   || : > "$S.running" ;;
  stop)    [ -f "$S.refuse_stop" ]    || rm -f "$S.running" ;;
  restart) "$S" stop; "$S" start ;;
  enable)  [ -f "$S.refuse_enable" ]  || : > "$S.enabled" ;;
  disable) [ -f "$S.refuse_disable" ] || rm -f "$S.enabled" ;;
  enabled) [ -f "$S.enabled" ] ;;
  status)  if [ -f "$S.running" ]; then echo "running"; else echo "inactive"; fi ;;
  *)       exit 1 ;;
esac
]]

local function stub(name)
  local path = BASE .. "/" .. name
  fs.writefile(path, STUB)
  fs.chmod(path, 755)
  return path
end

local SVC, NATIVE, BIN = {}, {}, {}

local function refuse(path, what, on)
  if on then fs.writefile(path .. ".refuse_" .. what, "") else fs.remove(path .. ".refuse_" .. what) end
end

local function enabled(path) return fs.access(path .. ".enabled") and true or false end
local function running(path) return fs.access(path .. ".running") and true or false end

local function set_enabled(path, on)
  if on then fs.writefile(path .. ".enabled", "") else fs.remove(path .. ".enabled") end
end
local function set_running(path, on)
  if on then fs.writefile(path .. ".running", "") else fs.remove(path .. ".running") end
end

-- Rebuild the whole world: stubs, DEFS redirected at them, a throwaway UCI
-- package describing `active` as the current engine.
local function reset(active)
  sys.call("rm -rf " .. BASE)
  sys.call("mkdir -p " .. BASE)
  fs.writefile(CFG, "config tproxy_manager 'main'\n")

  for _, id in ipairs(engines.ORDER) do
    SVC[id]    = stub(id .. "-init")
    NATIVE[id] = stub(id .. "-native-init")
    BIN[id]    = stub(id .. "-bin")
    local def = engines.DEFS[id]
    def.service_path        = SVC[id]
    def.native_service_path = NATIVE[id]
    def.binary_paths        = { BIN[id] }
  end
  -- Nothing may reach the real TPROXY or watchdog services.
  engines.STACK_SERVICES = {
    { path = stub("stack-tproxy"),  label = "tproxy-manager" },
    { path = stub("stack-watchdog"), label = "tproxy-manager-watchdog" },
  }

  local uci = uci_mod.cursor()
  uci:set(PKG, "main", "proxy_engine", active)
  uci:set(PKG, "main", "watchdog_service_path", SVC[active])
  uci:set(PKG, "main", "watchdog_test_command", active .. " -c {config}")
  uci:set(PKG, "main", "watchdog_outbound_file", BASE .. "/" .. active .. ".out")
  uci:set(PKG, "main", "watchdog_proxy_url", "socks5h://127.0.0.1:10808")
  uci:set(PKG, "main", "tproxy_port", "61219")
  for _, id in ipairs(engines.ORDER) do
    uci:set(PKG, "main", id .. "_profile_service_path", SVC[id])
    uci:set(PKG, "main", id .. "_profile_test_command", id .. " -c {config}")
    uci:set(PKG, "main", id .. "_profile_outbound_file", BASE .. "/" .. id .. ".out")
    uci:set(PKG, "main", id .. "_profile_tproxy_port", "61219")
  end
  uci:commit(PKG)
  -- The starting point of every case: the active engine armed and up, the others
  -- down and disarmed.
  for _, id in ipairs(engines.ORDER) do
    set_enabled(SVC[id], id == active)
    set_running(SVC[id], id == active)
    set_enabled(NATIVE[id], false)
    set_running(NATIVE[id], false)
  end
  return uci_mod.cursor()
end

local function armed()
  local on = {}
  for _, id in ipairs(engines.ORDER) do
    if enabled(SVC[id]) then on[#on + 1] = id end
    if enabled(NATIVE[id]) then on[#on + 1] = id .. "/native" end
  end
  return table.concat(on, ",")
end

local function live()
  local up = {}
  for _, id in ipairs(engines.ORDER) do
    if running(SVC[id]) then up[#up + 1] = id end
  end
  return table.concat(up, ",")
end

local function problem_codes(params)
  local codes = {}
  for _, p in ipairs((params or {}).problems or {}) do codes[#codes + 1] = p.code end
  table.sort(codes)
  return table.concat(codes, ",")
end

--------------------------------------------------------------------------------

group("ALIGN: exactly one engine armed, whichever is named active")
do
  local uci = reset("xray")
  check("baseline", armed(), "xray")
  check("align to xray reports no failure", engines.align_autostart(uci, PKG, "xray"), "")
  check("still only xray", armed(), "xray")
  check("align to mihomo reports no failure", engines.align_autostart(uci, PKG, "mihomo"), "")
  check("only mihomo armed", armed(), "mihomo")
  check("align to singbox", engines.align_autostart(uci, PKG, "singbox"), "")
  check("only singbox armed", armed(), "singbox")
end

group("ALIGN: a pre-existing conflict is collapsed to one engine")
do
  local uci = reset("xray")
  set_enabled(SVC.mihomo, true)
  set_enabled(SVC.singbox, true)
  check("three armed before", armed(), "xray,mihomo,singbox")
  check("align reports no failure", engines.align_autostart(uci, PKG, "xray"), "")
  check("one armed after", armed(), "xray")
end

group("ALIGN: a native init script carrying the link is disarmed too")
do
  local uci = reset("xray")
  -- An engine can have both a package init script and the distro's own; either
  -- could hold the boot link, so both are cleared for an inactive engine.
  set_enabled(NATIVE.mihomo, true)
  check("native link present", armed(), "xray,mihomo/native")
  check("align reports no failure", engines.align_autostart(uci, PKG, "xray"), "")
  check("native link cleared", armed(), "xray")
end

group("ALIGN: the active engine's native script is NOT armed as well")
do
  local uci = reset("xray")
  -- Arming both would start two instances of the same engine at boot, which is
  -- the very race this is meant to prevent.
  engines.align_autostart(uci, PKG, "mihomo")
  check("only the profile path armed", armed(), "mihomo")
  check("native stayed off", enabled(NATIVE.mihomo), false)
end

group("ALIGN: an init script that refuses is named, not swallowed")
do
  local uci = reset("xray")
  refuse(SVC.mihomo, "enable", true)
  check("enable refusal reported", engines.align_autostart(uci, PKG, "mihomo"), "Mihomo")
  check("nothing armed", armed(), "")

  uci = reset("xray")
  set_enabled(SVC.singbox, true)
  refuse(SVC.singbox, "disable", true)
  check("disable refusal names the path",
    engines.align_autostart(uci, PKG, "xray"), "sing-box (" .. SVC.singbox .. ")")
  check("the stuck link is still there", armed(), "xray,singbox")
end

group("CONFLICTS: report every engine armed for boot")
do
  local uci = reset("xray")
  local function ids()
    local out = {}
    for _, c in ipairs(engines.autostart_conflicts(uci, PKG)) do out[#out + 1] = c.id end
    return table.concat(out, ",")
  end
  check("clean state lists only the active engine", ids(), "xray")
  set_enabled(SVC.mihomo, true)
  check("conflict is visible", ids(), "xray,mihomo")
  set_enabled(NATIVE.singbox, true)
  check("a native link counts as armed", ids(), "xray,mihomo,singbox")
end

group("ACTIVATE: a successful switch moves both the process and the boot link")
do
  local uci = reset("xray")
  -- On success the second value is the engine label and the third is the warning
  -- set; a clean switch has none.
  local ok, label, warns = engines.activate(uci, PKG, "mihomo")
  check("activate succeeded", ok, true)
  check("label", label, "Mihomo")
  check("no warnings", warns, nil)
  check("only mihomo armed", armed(), "mihomo")
  check("only mihomo running", live(), "mihomo")
  check("proxy_engine", uci_mod.cursor():get(PKG, "main", "proxy_engine"), "mihomo")
end

group("ACTIVATE: a target that will not start leaves the boot link alone")
do
  -- The reported release blocker. Pre-fix this ended with proxy_engine=xray,
  -- xray disarmed and mihomo armed.
  local uci = reset("xray")
  refuse(SVC.mihomo, "start", true)
  local ok, code, params = engines.activate(uci, PKG, "mihomo")
  check("activate refused", ok, false)
  check("code", code, "did_not_start_reverted")
  check("no problems reported", problem_codes(params), "")
  check("boot link still xray", armed(), "xray")
  check("xray running again", live(), "xray")
  check("proxy_engine reverted", uci_mod.cursor():get(PKG, "main", "proxy_engine"), "xray")
end

group("ACTIVATE: a failed switch that had already armed the target is undone")
do
  -- Belt and braces: whatever armed the target -- this ordering or a future one
  -- -- the rollback re-arms the engine that is actually running.
  local uci = reset("xray")
  refuse(SVC.mihomo, "start", true)
  set_enabled(SVC.mihomo, true)
  set_enabled(SVC.xray, false)
  local ok, code = engines.activate(uci, PKG, "mihomo")
  check("activate refused", ok, false)
  check("code", code, "did_not_start_reverted")
  check("boot link back on xray", armed(), "xray")
end

group("ACTIVATE: autostart that cannot be restored is reported, not hidden")
do
  local uci = reset("xray")
  refuse(SVC.mihomo, "start", true)
  refuse(SVC.xray, "enable", true)
  set_enabled(SVC.xray, false)
  local ok, code, params = engines.activate(uci, PKG, "mihomo")
  check("activate refused", ok, false)
  check("rollback is not called clean", code, "rollback_incomplete")
  check("the autostart failure is in the problem list",
    problem_codes(params):find("autostart_not_restored", 1, true) ~= nil, true)
end

group("ACTIVATE: a target that is not installed changes nothing")
do
  local uci = reset("xray")
  fs.remove(BIN.mihomo)
  engines.DEFS.mihomo.binary_paths = { BASE .. "/absent-bin" }
  engines.DEFS.mihomo.binary = "tpm-absent-binary-" .. tostring(os.time())
  local ok, code = engines.activate(uci, PKG, "mihomo")
  check("activate refused", ok, false)
  check("code", code, "not_installed")
  check("boot link untouched", armed(), "xray")
  check("xray still running", live(), "xray")
end

--------------------------------------------------------------------------------

sys.call("rm -rf " .. BASE)
fs.remove(CFG)
sys.call("rm -rf /tmp/.uci/" .. PKG .. " >/dev/null 2>&1")

print(string.format("\n%d passed, %d failed", pass, fail))
if fail > 0 then
  print("\nfailures:")
  for _, f in ipairs(failures) do print("  - " .. f) end
  os.exit(1)
end
