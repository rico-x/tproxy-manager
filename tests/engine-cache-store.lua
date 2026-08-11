#!/usr/bin/env lua
--
-- Regression suite for the engine release-cache store.
--
-- Two things are being pinned down here, both of them consequences of the same
-- design decision: ensure_private_dir() DELETES a path it cannot trust, because
-- that is how an attacker-planted directory at a fixed /tmp name is disowned.
--
--   1. It must never be handed a shared root. /tmp is mode 1777 by definition, so
--      it can never pass the root-only test — pass it in and root runs
--      `rm -rf /tmp`. The candidate is therefore screened by owned_path_ok()
--      before anything is removed.
--
--   2. A cfg that names no cache_dir must not have one derived from the DIRNAME
--      of cache_file. The historical layout was
--      "/tmp/tproxy-manager-<engine>-releases.json", whose dirname is exactly
--      that shared root. The shipped Mihomo/sing-box configs pass a safe
--      cache_dir, so the bad branch was not reachable through them — but
--      core_version is a shared module and the next caller would have found it.
--
-- Runs ON THE ROUTER (needs luci.jsonc). Safe on a live router: nothing here
-- touches the engines, their binaries or their real stores. The one case that
-- deliberately provokes a delete does so inside the suite's own temp directory
-- and checks a sentinel afterwards, so if the guard ever regresses the damage is
-- confined to that directory and the failure is reported rather than silent.

local core = require "tproxy_manager.core_version"
local fs = require "nixio.fs"

local BASE = os.getenv("TPM_TEST_BASE") or "/tmp/tpm-cache-store-test"

local pass, fail = 0, 0
local function t(name, got, want)
  local ok = (got == want)
  if ok then pass = pass + 1 else fail = fail + 1 end
  print(string.format("  %-58s %s%s", name, ok and "PASS" or "FAIL",
    ok and "" or string.format("  <- got %s, want %s", tostring(got), tostring(want))))
end
local function group(name) print("\n== " .. name .. " ==") end

local function sh(cmd) return os.execute(cmd .. " >/dev/null 2>&1") end
local function exists(path) return fs.stat(path) ~= nil end

sh("rm -rf " .. BASE)
sh("mkdir -p " .. BASE)

-- The suite drives internals on purpose: these decide whether root deletes a
-- directory tree, and asserting the decision directly is stronger than inferring
-- it from what happens further up.
local owned_path_ok = core._owned_path_ok
local resolve_cache = core._resolve_cache
local ensure_private_dir = core._ensure_private_dir

if not (owned_path_ok and resolve_cache and ensure_private_dir) then
  print("core_version does not export the path guards this suite checks")
  os.exit(1)
end

group("PATH GUARD: what root may never delete")
-- Every one of these reached `rm -rf <path>` before the guard existed.
for _, path in ipairs({ "/", "/tmp", "/var", "/var/tmp", "/etc", "/usr", "/usr/bin",
                        "/root", "/overlay", "/dev", "/proc", "/sys", "/www" }) do
  t("refuses " .. path, owned_path_ok(path), false)
end
t("refuses an empty path", owned_path_ok(""), false)
t("refuses nil", owned_path_ok(nil), false)
t("refuses '.'", owned_path_ok("."), false)
t("refuses '..'", owned_path_ok(".."), false)
t("refuses a relative path", owned_path_ok("tmp/store"), false)
t("refuses a trailing slash", owned_path_ok("/tmp/store/"), false)
t("refuses a doubled slash", owned_path_ok("/tmp//store"), false)
t("refuses traversal in the middle", owned_path_ok("/tmp/store/../../etc"), false)
t("refuses traversal at the end", owned_path_ok("/tmp/store/.."), false)
t("refuses a single-component path", owned_path_ok("/store"), false)

group("PATH GUARD: what it must still allow")
t("accepts a named child of /tmp", owned_path_ok("/tmp/tproxy-manager-xray-cache"), true)
t("accepts a deeper path", owned_path_ok("/tmp/tproxy-manager-xray-cache/releases.json"), true)
t("accepts a path under /usr/bin", owned_path_ok("/usr/bin/xray"), true)

group("MISSING cache_dir: the store is derived, never taken from the dirname")
-- The exact shape that made this reachable: no cache_dir, and a cache_file in the
-- old flat layout whose dirname is /tmp.
local legacy = {
  name = "legacyengine",
  cache_file = "/tmp/tproxy-manager-legacyengine-releases.json",
}
local dir, file = resolve_cache(legacy)
t("a directory is resolved", type(dir) == "string" and dir ~= "", true)
t("  it is NOT the shared root", dir ~= "/tmp", true)
t("  it is a named child derived from cfg.name",
  dir, "/tmp/tproxy-manager-legacyengine-cache")
t("  the cache file sits inside it", file, dir .. "/releases.json")
t("  and the resolved directory passes the guard", owned_path_ok(dir), true)

-- A caller with neither a usable cache_dir nor a usable name gets nothing, and
-- fetch_releases then runs without a cache instead of touching anything.
local nameless = { cache_file = "/tmp/whatever.json" }
local nd = resolve_cache(nameless)
t("no cache_dir and no usable name yields no store", nd, nil)

local hostile = { name = "../../etc", cache_file = "/tmp/x.json" }
local hd = resolve_cache(hostile)
t("a traversal in cfg.name yields no store", hd, nil)

-- A cache_file pointing outside the named store is corrected rather than used:
-- the write must land in the one directory whose ownership was verified.
local mismatched = {
  name = "mismatch",
  cache_dir = "/tmp/tproxy-manager-mismatch-cache",
  cache_file = "/tmp/elsewhere/releases.json",
}
local md, mf = resolve_cache(mismatched)
t("a cache file outside the store is relocated into it",
  mf, md .. "/releases.json")

group("SHARED ROOT: handing one in deletes nothing")
-- The destructive case, kept inside the suite's own directory. A world-writable
-- directory with a sentinel stands in for /tmp: ensure_private_dir() would wipe
-- it if the caller resolved it as the store, which is what the dirname fallback
-- used to do. resolve_cache() must not name it, and the guard must refuse the
-- real shared roots outright (asserted above without side effects, so /tmp is
-- never passed to a function that deletes).
local fake_root = BASE .. "/shared-root"
sh("mkdir -p " .. fake_root)
sh("chmod 1777 " .. fake_root)
sh("touch " .. fake_root .. "/sentinel")
local sandbox_legacy = {
  name = "sandboxengine",
  cache_file = fake_root .. "/tproxy-manager-sandboxengine-releases.json",
}
local sdir = resolve_cache(sandbox_legacy)
t("the sandbox shared root is not chosen as the store", sdir ~= fake_root, true)
-- Deliberately unguarded: whatever the resolver named is handed to the function
-- that deletes, exactly as fetch_releases does it. That is what makes the two
-- checks below witnesses rather than tautologies — if the resolver ever names the
-- shared root again, the wipe really happens here and the sentinel says so. The
-- damage is bounded to this suite's own directory, which is the whole reason the
-- shared root is a stand-in instead of the real /tmp.
if sdir then ensure_private_dir(sdir) end
t("  its sentinel survived", exists(fake_root .. "/sentinel"), true)
-- Not "the directory still exists": a wipe is immediately followed by a
-- `mkdir -m 0700`, so the path is back either way. What distinguishes untouched
-- from destroyed-and-replaced is the mode — a shared root that nobody took over
-- is still 1777.
local root_st = fs.stat(fake_root)
t("  and it was not taken over as a private store",
  root_st and tostring(root_st.modedec), "1777")

group("DERIVED STORE: still usable after all that")
local derived = "/tmp/tproxy-manager-sandboxengine-cache"
t("the derived store was created", ensure_private_dir(derived), true)
local st = fs.stat(derived)
t("  it is a directory", st and st.type, "dir")
t("  owned by root", st and st.uid, 0)
t("  mode 0700", st and tostring(st.modedec), "700")
sh("rm -rf " .. derived)

sh("rm -rf " .. BASE)

print(string.format("\n%d passed, %d failed", pass, fail))
os.exit(fail == 0 and 0 or 1)
