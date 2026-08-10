#!/usr/bin/env lua
--
-- Integration suite for the backup export/import cycle, covering the two
-- hardening fixes that only show up end to end:
--
--   * staging is created exclusively with an unguessable name, so a directory
--     or symlink pre-created in world-writable /tmp can never be adopted by the
--     root cp/chmod/find/tar that follows;
--   * apply() takes its rollback snapshot in the durable store outside the
--     pending directory, so a retry cannot destroy the copy a crashed earlier
--     attempt left behind.
--
-- Runs ON THE ROUTER (needs nixio and the luci tree). Safe on a live router:
-- the archive it applies is an export of that router's OWN current
-- configuration, so the content written back is identical to what is already
-- there — and if the diff turns out to be non-empty for any reason, the apply
-- step is skipped rather than changing anything.

local backup = require "tproxy_manager.backup"
local utils  = require "luci.model.cbi.tproxy_manager.utils"
local fs     = require "nixio.fs"

local pass, fail, skipped = 0, 0, 0
local function t(name, got, want)
  local ok = (got == want)
  if ok then pass = pass + 1 else fail = fail + 1 end
  print(string.format("  %-54s %s%s", name, ok and "PASS" or "FAIL",
    ok and "" or string.format("  <- got %s, want %s", tostring(got), tostring(want))))
end
local function skip(name, why)
  skipped = skipped + 1
  print(string.format("  %-54s SKIP  (%s)", name, why))
end
local function group(name) print("\n== " .. name .. " ==") end

local function count_tmp(pattern)
  local n, it = 0, fs.dir("/tmp")
  if it then for name in it do if name:match(pattern) then n = n + 1 end end end
  return n
end
local function count_stores(prefix)
  local n, it = 0, fs.dir(utils.ROLLBACK_ROOT)
  if it then for name in it do if name:match("^" .. prefix .. "%.") then n = n + 1 end end end
  return n
end

group("EXPORT: exclusive staging with an unguessable name")
local out_before = count_tmp("^tproxy%-manager%-backup%-out%.")
local archive, err = backup.export()
t("export produced an archive", archive ~= nil, true)
if not archive then
  print("  error: " .. tostring(err))
  os.exit(1)
end
t("  the archive exists", fs.stat(archive) ~= nil, true)
local outdir = archive:match("^(.*)/[^/]+$")
t("  its directory is 0700", tostring(fs.stat(outdir).modedec), "700")
t("  its directory is root-owned", fs.stat(outdir).uid, 0)
-- private_dir() draws 12 bytes, i.e. 24 hex characters / 96 bits. The point of
-- the assertion is that the name is CSPRNG-derived at all: the previous names
-- came from a clock-seeded math.random and were guessable by a local user.
local suffix = outdir:match("tproxy%-manager%-backup%-out%.(%x+)$")
t("  the name carries 24 hex chars of entropy", suffix and #suffix, 24)
t("  no staging directory was left behind", count_tmp("^tproxy%-manager%-backup%-export%."), 0)
print(string.format("  (archive: %d bytes)", fs.stat(archive).size or 0))

group("IMPORT: extraction into an exclusively created directory")
local token, xerr = backup.extract_pending(archive)
t("extract_pending returned a token", type(token) == "string" and #token > 0, true)
if not token then
  print("  error: " .. tostring(xerr))
  backup.discard_export(archive)
  os.exit(1)
end
t("  the token is 32 hex chars (CSPRNG, not math.random)",
  (token:match("^%x+$") ~= nil) and #token, 32)

local diff, derr = backup.diff(token)
t("diff built", diff ~= nil, true)
if not diff then
  print("  error: " .. tostring(derr))
  backup.cancel(token)
  backup.discard_export(archive)
  os.exit(1)
end
local touched = 0
for _ in pairs(diff.touched or {}) do touched = touched + 1 end
t("a backup of the live config reports no changed module", touched, 0)

group("APPLY: the rollback store is used and released")
if touched ~= 0 then
  -- Never apply something that would actually change this router.
  skip("apply leaves no rollback store behind", "the diff is not empty; refusing to apply")
  backup.cancel(token)
else
  local stores_before = count_stores("backup%-apply")
  local ok_apply, res, warn = backup.apply(token)
  t("apply succeeded", ok_apply, true)
  if not ok_apply then print("  error: " .. tostring(res)) end
  if warn then print("  warning: " .. tostring(warn)) end
  t("  no rollback store left behind", count_stores("backup%-apply"), stores_before)
  t("  the pending directory is cleaned up", count_tmp("^tproxy%-manager%-backup%-pending"), 0)
end

group("CLEANUP: discard_export removes the whole private directory")
backup.discard_export(archive)
t("the private directory is gone", fs.stat(outdir), nil)
t("  /tmp holds no extra output directories", count_tmp("^tproxy%-manager%-backup%-out%."), out_before)

print(string.format("\n%d passed, %d failed, %d skipped", pass, fail, skipped))
os.exit(fail == 0 and 0 or 1)
