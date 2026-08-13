#!/usr/bin/env lua
--
-- Fault-injection suite for the rollback subsystem in
-- luci/model/cbi/tproxy_manager/utils.lua.
--
-- Runs ON THE ROUTER: it needs nixio and the luci Lua tree. Use
-- scripts/test-on-device.sh to stage the working tree and execute this
-- against it without touching the installed package.
--
-- Every case injects one concrete failure and asserts the subsystem reports
-- it instead of silently producing a snapshot that cannot be trusted. The
-- guarantees under test:
--
--   * a read that fails is never stored as empty content (that would make the
--     rollback truncate the file it was protecting);
--   * MANIFEST / KEEP / STAGE are written AND verified, because the sweeper
--     and the operator act on their content;
--   * a chmod failure means "written but not secured", never "not written";
--   * a rollback restores bytes and mode, and says so honestly when it cannot;
--   * a store whose owner died mid-apply is preserved, while one that died
--     before touching anything is reclaimed.
--
-- The suite operates inside its own temp directory and its own rollback root,
-- so it is safe to run on a live router: a genuinely preserved store belonging
-- to the real UI is never visible to it.

local utils = require "luci.model.cbi.tproxy_manager.utils"
local fs    = require "nixio.fs"
local sys   = require "luci.sys"

local BASE = os.getenv("TPM_TEST_BASE") or "/tmp/tpm-rollback-test"
local BIN  = BASE .. "/bin"
local REAL_PATH = os.getenv("PATH") or "/usr/sbin:/usr/bin:/sbin:/bin"

-- Isolated rollback root: never the one the live UI uses.
utils.ROLLBACK_ROOT = BASE .. "/rollback"

local pass, fail, failures = 0, 0, {}
-- Counted and printed: a check that quietly leaves the tally looks like coverage
-- that was never there. One of these skipped on a busy router and the total
-- dropped from 110 to 107 with nothing failing.
local skipped = 0

local function check(name, got, want)
  local ok = (got == want)
  if ok then
    pass = pass + 1
  else
    fail = fail + 1
    failures[#failures + 1] = string.format("%s (got %s, want %s)", name, tostring(got), tostring(want))
  end
  print(string.format("  %-54s %s%s", name, ok and "PASS" or "FAIL",
    ok and "" or string.format("  <- got %s", tostring(got))))
end

local function group(name) print("\n== " .. name .. " ==") end

local function reset()
  sys.call("rm -rf " .. BASE)
  sys.call("mkdir -p " .. BIN)
end

-- shadow_bin: put a deliberately broken command ahead of the real one on PATH.
-- This is how the chmod fault is injected: luci.sys.call() runs through /bin/sh,
-- which inherits our environment.
local function shadow_bin(name, body)
  local fh = io.open(BIN .. "/" .. name, "w")
  fh:write(body)
  fh:close()
  sys.call("/bin/chmod 0755 " .. BIN .. "/" .. name)
end

local function shadow(on)
  require("nixio").setenv("PATH", on and (BIN .. ":" .. REAL_PATH) or REAL_PATH)
end

-- Replace a path with a directory: the cheapest way to make a write or a read
-- of that exact path fail while everything around it still works.
local function block_path(path)
  sys.call("rm -rf " .. path .. " && mkdir " .. path)
end

local function lines_in(path)
  local data = utils.read_file(path)
  local n = 0
  for _ in data:gmatch("[^\n]+") do n = n + 1 end
  return n
end

reset()
local A, B = BASE .. "/a.txt", BASE .. "/b.txt"

--------------------------------------------------------------------------
group("READ FAULT: an unreadable source must not be snapshotted as empty")
--------------------------------------------------------------------------
utils.write_file(A, "AAA")
check("read_file_checked reads a regular file", utils.read_file_checked(A), "AAA")
check("read_file_checked on a missing path", utils.read_file_checked(BASE .. "/nope"), nil)
block_path(A)
check("read_file_checked on a directory", utils.read_file_checked(A), nil)

local st = utils.snapshot_begin("read")
check("snapshot_begin succeeded", type(st), "table")
local ok, err = utils.snapshot_add(st, A)
check("snapshot_add refuses the unreadable path", ok, nil)
check("  reports the reason", type(err) == "string" and err:find("not a regular file") ~= nil, true)
check("  wrote no copy", fs.stat(st.dir .. "/001.dat"), nil)
check("  recorded no item", #st.items, 0)
utils.snapshot_discard(st)
sys.call("rm -rf " .. A)

-- A read whose result cannot be reconciled with the file's own metadata must
-- be refused, not stored. /proc/self/stat is a deterministic stand-in: nixio
-- reports it as a regular file of size 0 while a read returns a couple of
-- hundred bytes — exactly the shape of a short or racing read on a real file.
-- This is the case that distinguishes the checked reader from the plain one:
-- with read_file() the snapshot would be taken from content the file does not
-- claim to have, and the rollback would later write that back.
local UNVERIFIABLE = "/proc/self/stat"
if fs.stat(UNVERIFIABLE) then
  check("read_file returns data for an unverifiable read", #utils.read_file(UNVERIFIABLE) > 0, true)
  check("read_file_checked refuses it", utils.read_file_checked(UNVERIFIABLE), nil)
  st = utils.snapshot_begin("unverifiable")
  ok, err = utils.snapshot_add(st, UNVERIFIABLE)
  check("snapshot_add refuses an unverifiable read", ok, nil)
  check("  reports the reason", type(err) == "string" and err:find("changed while being read") ~= nil, true)
  check("  recorded no item", #st.items, 0)
  utils.snapshot_discard(st)
end

--------------------------------------------------------------------------
group("MANIFEST WRITE FAULT: a store without a manifest is not usable evidence")
--------------------------------------------------------------------------
utils.write_file(A, "AAA")
st = utils.snapshot_begin("manifest")
block_path(st.dir .. "/MANIFEST")
ok, err = utils.snapshot_add(st, A)
check("snapshot_add fails when MANIFEST cannot be written", ok, nil)
check("  reports the reason", type(err) == "string" and err:find("manifest") ~= nil, true)
check("  the half-recorded item is rolled back", #st.items, 0)
sys.call("rm -rf " .. st.dir)

--------------------------------------------------------------------------
group("KEEP WRITE FAULT: never promise the user a store we could not mark")
--------------------------------------------------------------------------
st = utils.snapshot_begin("keep")
check("snapshot_add ok", utils.snapshot_add(st, A), true)
block_path(st.dir .. "/KEEP")
check("snapshot_keep returns nil when it cannot mark", utils.snapshot_keep(st), nil)
sys.call("rm -rf " .. st.dir)

--------------------------------------------------------------------------
group("STAGE WRITE FAULT: arming must fail loudly, never silently")
--------------------------------------------------------------------------
st = utils.snapshot_begin("stage")
utils.snapshot_add(st, A)
block_path(st.dir .. "/STAGE")
ok, err = utils.snapshot_arm(st)
check("snapshot_arm fails", ok, nil)
check("  reports the reason", type(err) == "string" and err:find("stage") ~= nil, true)
sys.call("rm -rf " .. st.dir)

--------------------------------------------------------------------------
group("CHMOD FAULT: 'written but not secured' is not 'not written'")
--------------------------------------------------------------------------
utils.write_file(A, "AAA")
sys.call("/bin/chmod 0644 " .. A)
st = utils.snapshot_begin("chmod")
check("snapshot_add captures the mode", utils.snapshot_add(st, A) and st.items[1].perm, "644")
check("snapshot_arm ok", utils.snapshot_arm(st), true)
utils.write_file(A, "clobbered")

shadow_bin("chmod", "#!/bin/sh\nexit 1\n")
shadow(true)
local failed = utils.snapshot_restore(st)
check("restore reports 'permissions'", failed[1] and failed[1].state, "permissions")
check("  the content was restored regardless", utils.read_file(A), "AAA")
shadow(false)

failed = utils.snapshot_restore(st)
check("restore is clean once chmod works", #failed, 0)
check("  the mode is back", tostring(fs.stat(A).modedec), "644")
utils.snapshot_discard(st)

--------------------------------------------------------------------------
group("ROLLBACK: bytes and modes of every recorded file")
--------------------------------------------------------------------------
utils.write_file(A, "AAA")
utils.write_file(B, "BBB")
sys.call("/bin/chmod 0644 " .. A .. " && /bin/chmod 0755 " .. B)
st = utils.snapshot_begin("rollback")
utils.snapshot_add(st, A)
utils.snapshot_add(st, B)
utils.snapshot_arm(st)
utils.write_file(A, "x")
utils.write_file(B, "y")
check("restore reports no failures", #utils.snapshot_restore(st), 0)
check("  a content", utils.read_file(A), "AAA")
check("  b content", utils.read_file(B), "BBB")
check("  a mode", tostring(fs.stat(A).modedec), "644")
check("  b mode", tostring(fs.stat(B).modedec), "755")
utils.snapshot_discard(st)

group("ROLLBACK: an absent file is recreated as absent")
sys.call("rm -f " .. A)
st = utils.snapshot_begin("absent")
utils.snapshot_add(st, A)
utils.snapshot_arm(st)
utils.write_file(A, "created by the transaction")
check("restore reports no failures", #utils.snapshot_restore(st), 0)
check("  the file is gone again", fs.stat(A), nil)
utils.snapshot_discard(st)

group("ROLLBACK: a lost snapshot copy must not truncate the live file")
utils.write_file(A, "AAA")
st = utils.snapshot_begin("lostcopy")
utils.snapshot_add(st, A)
utils.snapshot_arm(st)
fs.remove(st.dir .. "/001.dat")
utils.write_file(A, "clobbered")
failed = utils.snapshot_restore(st)
check("restore refuses and reports the failure", #failed, 1)
check("  the live file is left as it was, not emptied", utils.read_file(A), "clobbered")
utils.snapshot_discard(st)

group("ROLLBACK: a target replaced by a directory is reported, store kept")
utils.write_file(A, "AAA")
st = utils.snapshot_begin("blocked")
utils.snapshot_add(st, A)
utils.snapshot_arm(st)
block_path(A)
failed = utils.snapshot_restore(st)
check("restore reports one failure", #failed, 1)
check("  naming the path", failed[1] and failed[1].path, A)
check("  with state 'failed'", failed[1] and failed[1].state, "failed")
check("snapshot_keep marks it and returns the dir", utils.snapshot_keep(st), st.dir)
check("  the copy is still recoverable from it", utils.read_file(st.dir .. "/001.dat"), "AAA")
sys.call("rm -rf " .. A .. " " .. st.dir)

--------------------------------------------------------------------------
group("SWEEP: reclaim what changed nothing, preserve what may be half-applied")
--------------------------------------------------------------------------
local root = utils.secure_lock_root(utils.ROLLBACK_ROOT)
check("rollback root available", root, utils.ROLLBACK_ROOT)

-- The planted stores carry a KNOWN but dead owner: boot id of this boot, and a
-- pid that cannot exist. That is what makes "the owner is gone" provable, which
-- is the precondition for reclaiming anything. A store with NO owner record is a
-- different case and is covered separately below (it must be preserved).
local PLANT_BTIME = (utils.read_file("/proc/stat")):match("btime%s+(%d+)") or "0"
local function plant(name, stage)
  local dir = root .. "/" .. name
  sys.call("rm -rf " .. dir .. " && mkdir -m 0700 " .. dir)
  if stage then sys.call("printf '" .. stage .. "\\n' > " .. dir .. "/STAGE") end
  sys.call("printf '" .. PLANT_BTIME .. " 999999 12345\\n' > " .. dir .. "/OWNER")
  sys.call("echo copy > " .. dir .. "/001.dat")
  return dir
end

-- pid 999999 cannot be running: /proc/999999 does not exist.
local prepared = plant("x.999999.111111", "prepared")
local applying = plant("x.999998.222222", "applying")
local nostage  = plant("x.999997.333333", nil)

st = utils.snapshot_begin("sweep")   -- the sweep runs on entry
check("prepared + dead owner is reclaimed", fs.stat(prepared), nil)
check("applying + dead owner is PRESERVED", fs.stat(applying) ~= nil, true)
check("  and marked KEEP", fs.stat(applying .. "/KEEP") ~= nil, true)
check("  its copy is intact", utils.trim(utils.read_file(applying .. "/001.dat")), "copy")
check("dead owner with an unreadable stage is PRESERVED", fs.stat(nostage) ~= nil, true)
utils.snapshot_discard(st)

st = utils.snapshot_begin("sweep2")
check("a preserved store survives later sweeps", fs.stat(applying) ~= nil, true)
utils.snapshot_discard(st)
sys.call("rm -rf " .. applying .. " " .. nostage)

--------------------------------------------------------------------------
group("UCI STAGING: a delete is judged by the result, not the return code")
--------------------------------------------------------------------------
-- uci:delete answers false when the option was not there to begin with, which
-- is the normal case for every optional field. Treating that as a failure made
-- a perfectly good save report "Failed to save settings" and revert everything
-- the user had just typed.
do
  local ucim = require "luci.model.uci"
  local uci = ucim.cursor()
  local PKG = "tproxy-manager"

  check("raw uci:delete on a missing option returns false",
    uci:delete(PKG, "main", "zz_absent_probe"), false)
  check("uci_unset on the same option succeeds",
    utils.uci_unset(uci, PKG, "main", "zz_absent_probe"), true)

  check("uci_stage sets a value", utils.uci_stage(uci, PKG, "main", "zz_probe", "1"), true)
  check("  the value is readable", uci:get(PKG, "main", "zz_probe"), "1")
  check("uci_stage with an empty value clears it",
    utils.uci_stage(uci, PKG, "main", "zz_probe", ""), true)
  check("  and it is really gone", uci:get(PKG, "main", "zz_probe"), nil)
  check("clearing it a second time still succeeds",
    utils.uci_stage(uci, PKG, "main", "zz_probe", ""), true)
  check("uci_stage on a missing section fails",
    utils.uci_stage(uci, PKG, "no_such_section", "k", "v"), false)
  -- Nothing above is committed; drop it all so the router's config is untouched.
  uci:revert(PKG)
  check("the probe left nothing behind", uci:get(PKG, "main", "zz_probe"), nil)
end

--------------------------------------------------------------------------
group("EXCLUSIVE STAGING: a pre-created path must never be adopted")
--------------------------------------------------------------------------
-- Backup export and import stage into /tmp and then run cp/chmod/find/tar
-- through that directory as root. ensure_dir() (mkdir -p) happily accepts a
-- path someone else created, so the staging root has to be created
-- exclusively — that is what private_dir() guarantees.
check("random_hex returns the requested length", #(utils.random_hex(12) or ""), 24)
check("random_hex differs between calls", utils.random_hex(12) ~= utils.random_hex(12), true)

local parent = BASE .. "/stage"
sys.call("mkdir -p " .. parent)
local d1 = utils.private_dir(parent, "probe")
check("private_dir creates a directory", d1 ~= nil and fs.stat(d1) ~= nil, true)
check("  with mode 0700", tostring(fs.stat(d1).modedec), "700")
check("  owned by root", fs.stat(d1).uid, 0)
local d2 = utils.private_dir(parent, "probe")
check("consecutive calls do not collide", d1 ~= d2, true)

-- A pre-created directory at the exact name cannot be adopted: private_dir
-- picks a fresh random name, and the underlying mkdir refuses an existing one.
-- Verified directly against the primitive it relies on.
local planted = parent .. "/planted"
sys.call("mkdir -p " .. planted)
check("mkdir refuses an existing directory",
  sys.call("mkdir -m 0700 " .. planted .. " >/dev/null 2>&1") ~= 0, true)
local link = parent .. "/planted-link"
sys.call("ln -s /etc " .. link)
check("mkdir refuses an existing symlink",
  sys.call("mkdir -m 0700 " .. link .. " >/dev/null 2>&1") ~= 0, true)
check("  and the symlink target is untouched", fs.stat("/etc").type, "dir")
sys.call("rm -rf " .. parent)

--------------------------------------------------------------------------
group("RETRY AFTER A CRASH must not destroy the earlier snapshot")
--------------------------------------------------------------------------
-- backup.apply() used to keep its rollback inside the pending directory and
-- `rm -rf` it on entry, so a second attempt wiped the only copy of the state
-- the first (crashed) attempt had already half-changed. Stores are per-run and
-- an armed one is preserved, so a retry cannot reach it.
utils.write_file(A, "AAA")
local first = utils.snapshot_begin("retry")
utils.snapshot_add(first, A)
utils.snapshot_arm(first)
utils.write_file(A, "half-applied by the first attempt")
local second = utils.snapshot_begin("retry")          -- the "retry" sweeps on entry
check("the retry gets its own store", second.dir ~= first.dir, true)
check("the first store still exists", fs.stat(first.dir) ~= nil, true)
check("  and still holds the original", utils.read_file(first.dir .. "/001.dat"), "AAA")
utils.snapshot_discard(second)
utils.snapshot_discard(first)

--------------------------------------------------------------------------
group("PROCESS DEATH between two live writes")
--------------------------------------------------------------------------
-- The scenario the whole subsystem exists for: a CGI is killed after it has
-- written one of two files and before it could roll anything back. The store
-- must survive, be marked for the operator, and still hold both originals.
utils.write_file(A, "AAA")
utils.write_file(B, "BBB")

local child = BASE .. "/child.lua"
local marker = BASE .. "/child.dir"
local fh = io.open(child, "w")
fh:write(string.format([[
local utils = require "luci.model.cbi.tproxy_manager.utils"
utils.ROLLBACK_ROOT = %q
local st = assert(utils.snapshot_begin("crashtx"))
assert(utils.snapshot_add(st, %q))
assert(utils.snapshot_add(st, %q))
assert(utils.snapshot_arm(st))
utils.write_file(%q, "HALF-APPLIED")
local fh = io.open(%q, "w"); fh:write(st.dir); fh:close()
os.exit(9)   -- dies before the second write and before any discard
]], utils.ROLLBACK_ROOT, A, B, A, marker))
fh:close()

sys.call("lua " .. child .. " >/dev/null 2>&1")
local crashed = utils.trim(utils.read_file(marker))
check("the child left a store behind", crashed ~= "" and fs.stat(crashed) ~= nil, true)
check("  its stage says applying", utils.trim(utils.read_file(crashed .. "/STAGE")), "applying")
check("  the first live file is half-applied", utils.read_file(A), "HALF-APPLIED")
check("  the second live file is untouched", utils.read_file(B), "BBB")

st = utils.snapshot_begin("after-crash")   -- triggers the sweep
check("the crashed store SURVIVES the sweep", fs.stat(crashed) ~= nil, true)
check("  marked KEEP for the operator", fs.stat(crashed .. "/KEEP") ~= nil, true)
check("  the first original is recoverable", utils.read_file(crashed .. "/001.dat"), "AAA")
check("  the second original is recoverable", utils.read_file(crashed .. "/002.dat"), "BBB")
check("  MANIFEST lists both files", lines_in(crashed .. "/MANIFEST"), 2)
utils.snapshot_discard(st)

st = utils.snapshot_begin("after-crash-2")
check("still preserved on a later sweep", fs.stat(crashed) ~= nil, true)
utils.snapshot_discard(st)

--------------------------------------------------------------------------
group("RECOVERY: a preserved store can actually be put back")
--------------------------------------------------------------------------
-- Preserving a store used to be the end of the story: the files stayed
-- half-written and nothing could act on it. These are the three operations the
-- UI drives.
-- The suite runs against its own root (see the header), so the shipped default
-- is read from the module source rather than from the overridden field.
do
  local src = utils.read_file("/usr/lib/lua/luci/model/cbi/tproxy_manager/utils.lua")
  if src == "" then src = utils.read_file(os.getenv("TPM_UTILS_SRC") or "") end
  local shipped = src:match('M%.ROLLBACK_ROOT%s*=%s*"([^"]+)"')
  check("the shipped store root is NOT on tmpfs",
    shipped ~= nil and shipped:match("^/tmp/") == nil, true)
end

utils.write_file(A, "ORIGINAL")
local recov = utils.snapshot_begin("recovery")
utils.snapshot_add(recov, A)
utils.snapshot_arm(recov)
utils.write_file(A, "half-applied")
check("snapshot_keep marks it", utils.snapshot_keep(recov) ~= nil, true)

local found
for _, o in ipairs(utils.rollback_orphans()) do
  if o.dir == recov.dir then found = o end
end
check("rollback_orphans lists it", found ~= nil, true)
check("  with the file it can restore", found and #found.files, 1)
check("  and the recorded path", found and found.files[1].path, A)

check("rollback_recover restores the file", utils.rollback_recover(recov.dir), true)
check("  the content is back", utils.read_file(A), "ORIGINAL")
check("  and the store is gone", fs.stat(recov.dir), nil)

-- VISIBLE IMMEDIATELY. rollback_orphans() used to list only stores that already
-- carried a KEEP marker, and the marker is written by the sweeper - which ran
-- only inside snapshot_begin(). So a store left by a process that just died was
-- invisible until some unrelated write operation happened to start a
-- transaction. This is the exact sequence that was broken: crash, then look,
-- with nothing in between.
do
  local child = BASE .. "/orphan-child.lua"
  local marker = BASE .. "/orphan.dir"
  utils.write_file(A, "BEFORE-CRASH")
  local fh = io.open(child, "w")
  fh:write(string.format([[
local utils = require "luci.model.cbi.tproxy_manager.utils"
utils.ROLLBACK_ROOT = %q
local st = assert(utils.snapshot_begin("visible"))
assert(utils.snapshot_add(st, %q))
assert(utils.snapshot_arm(st))
utils.write_file(%q, "half-applied")
local fh = io.open(%q, "w"); fh:write(st.dir); fh:close()
os.exit(9)
]], utils.ROLLBACK_ROOT, A, A, marker))
  fh:close()
  sys.call("lua " .. child .. " >/dev/null 2>&1")
  local crashed = utils.trim(utils.read_file(marker))

  check("the crashed store exists on disk", fs.stat(crashed) ~= nil, true)
  check("  it has no KEEP marker yet", fs.stat(crashed .. "/KEEP"), nil)
  -- No snapshot_begin() in between: this is the whole point.
  local seen = false
  for _, o in ipairs(utils.rollback_orphans()) do
    if o.dir == crashed then seen = true end
  end
  check("rollback_orphans lists it WITHOUT a prior write operation", seen, true)
  check("  and marked it for the operator", fs.stat(crashed .. "/KEEP") ~= nil, true)
  check("  the recorded original is intact", utils.read_file(crashed .. "/001.dat"), "BEFORE-CRASH")
  sys.call("rm -rf " .. crashed)
end

-- PROCESS START TIME. /proc/<pid>/stat holds the executable name in field 2,
-- inside parentheses, and that name may itself contain ")" — so the tail has to
-- be taken after the LAST one. A pattern that binds to the first ")" silently
-- returns a field shifted by one, which then travels into the owner record and
-- stops protecting against pid reuse at all.
do
  -- Ground truth, computed independently of the implementation: strip up to the
  -- last ")" with sed, then take field 20 of what remains (state is field 3, so
  -- field 22 of the line is the 20th token after the name).
  local function starttime_via_shell(pid)
    local p = io.popen("sed 's/^.*)//' /proc/" .. pid .. "/stat 2>/dev/null | awk '{print $20}'")
    local out = p and utils.trim(p:read("*a") or "") or ""
    if p then p:close() end
    return out
  end

  local mine = utils.self_pid()
  check("proc_starttime matches an independent parse (plain name)",
    utils.proc_starttime(mine), starttime_via_shell(mine))

  -- A process whose comm contains ")". busybox is a single binary, so a copy
  -- under an awkward name is a normal process with an awkward comm.
  -- Retried: on a busy router a single attempt loses the race between the spawn
  -- and reading /proc, and the whole group then vanished from the count.
  local odd_pid, comm = "", ""
  for _ = 1, 3 do
    sys.call("cp /bin/sleep " .. BASE .. "/'a)b' 2>/dev/null || cp /bin/busybox " .. BASE .. "/'a)b'")
    sys.call("chmod 0755 " .. BASE .. "/'a)b'")
    local ph = io.popen(BASE .. "/'a)b' 60 >/dev/null 2>&1 & echo $!")
    odd_pid = ph and utils.trim(ph:read("*a") or "") or ""
    if ph then ph:close() end
    sys.call("sleep 1")
    comm = utils.read_file("/proc/" .. odd_pid .. "/stat"):match("%((.-)%)%s+%a") or ""
    if odd_pid:match("^%d+$") and comm:find(")", 1, true) then break end
  end
  if odd_pid:match("^%d+$") and comm:find(")", 1, true) then
    check("  the test process really has ')' in its name", comm:find(")", 1, true) ~= nil, true)
    local expected = starttime_via_shell(odd_pid)
    check("  proc_starttime is correct for such a name", utils.proc_starttime(odd_pid), expected)
    check("    and the value is numeric", (utils.proc_starttime(odd_pid) or ""):match("^%d+$") ~= nil, true)
  else
    skipped = skipped + 3
    print(string.format("  %-54s SKIP  (could not spawn a process with ')' in its name)", "proc_starttime with ')' in the name"))
  end
  sys.call("kill " .. odd_pid .. " 2>/dev/null")
  sys.call("rm -f " .. BASE .. "/'a)b'")
end

-- OWNER IDENTITY. The sweeper decides liveness from the recorded owner, so that
-- record must be mandatory and verified. It used to be written best-effort: an
-- unwritten or empty one made a live, still-"prepared" store look ownerless, and
-- the very next listing deleted it out from under the running transaction.
do
  local st_o = utils.snapshot_begin("owner")
  check("snapshot_begin records an owner", fs.stat(st_o.dir .. "/OWNER") ~= nil, true)
  local rec = utils.trim(utils.read_file(st_o.dir .. "/OWNER"))
  check("  it carries boot, pid and start time", select(2, rec:gsub("%S+", "")), 3)
  check("  the pid in it is ours", rec:match("^%S+%s+(%S+)"), utils.self_pid())

  -- A LIVE prepared store must survive a listing. This is the reported fault:
  -- store_before=true, store_after_read=false.
  local before = fs.stat(st_o.dir) ~= nil
  utils.rollback_orphans()
  check("a live prepared store survives rollback_orphans", before and fs.stat(st_o.dir) ~= nil, true)
  check("  and was not marked", fs.stat(st_o.dir .. "/KEEP"), nil)
  utils.snapshot_discard(st_o)
end

-- An unreadable owner record must not cause a delete: what cannot be reasoned
-- about is preserved for the operator instead.
do
  local st_u = utils.snapshot_begin("unknownowner")
  utils.snapshot_add(st_u, A)
  sys.call("rm -f " .. st_u.dir .. "/OWNER")
  local listed = false
  for _, o in ipairs(utils.rollback_orphans()) do if o.dir == st_u.dir then listed = true end end
  check("a store with no owner record is preserved, not deleted", fs.stat(st_u.dir) ~= nil, true)
  check("  it is surfaced to the operator", listed, true)
  check("  with a marker explaining why", fs.stat(st_u.dir .. "/KEEP") ~= nil, true)
  sys.call("rm -rf " .. st_u.dir)
end

-- PID REUSE, across a reboot and within one boot. pid 1 is always alive, so only
-- the recorded boot id and start time can tell these apart.
do
  local root = utils.secure_lock_root(utils.ROLLBACK_ROOT)
  local function plant_owner(name, owner)
    local dir = root .. "/" .. name
    sys.call("rm -rf " .. dir .. " && mkdir -m 0700 " .. dir)
    sys.call("printf 'applying\\n' > " .. dir .. "/STAGE")
    sys.call("printf '001 600 " .. A .. "\\n' > " .. dir .. "/MANIFEST")
    sys.call("echo old > " .. dir .. "/001.dat")
    sys.call("printf '" .. owner .. "\\n' > " .. dir .. "/OWNER")
    return dir
  end
  local btime = (utils.read_file("/proc/stat")):match("btime%s+(%d+)") or "0"
  local one_start = (utils.read_file("/proc/1/stat")):match("%)%s*(.*)$")
  do
    local n = 0
    for f in (one_start or ""):gmatch("%S+") do n = n + 1; if n == 20 then one_start = f; break end end
  end

  -- Earlier boot, pid 1 (live now): must be orphaned.
  local prev_boot = plant_owner("prevboot.1.555555", "1 1 " .. tostring(one_start))
  local seen = false
  for _, o in ipairs(utils.rollback_orphans()) do if o.dir == prev_boot then seen = true end end
  check("a store from an earlier boot is orphaned", seen, true)
  sys.call("rm -rf " .. prev_boot)

  -- This boot, pid 1, but a DIFFERENT start time: the number was recycled.
  local recycled = plant_owner("recycled.1.666666", btime .. " 1 999999999")
  seen = false
  for _, o in ipairs(utils.rollback_orphans()) do if o.dir == recycled then seen = true end end
  check("a recycled pid within one boot is orphaned", seen, true)
  sys.call("rm -rf " .. recycled)

  -- This boot, pid 1, matching start time: genuinely in flight, leave alone.
  local inflight = plant_owner("inflight.1.777777", btime .. " 1 " .. tostring(one_start))
  seen = false
  for _, o in ipairs(utils.rollback_orphans()) do if o.dir == inflight then seen = true end end
  check("a genuinely in-flight store is NOT reported", seen, false)
  check("  and is not marked", fs.stat(inflight .. "/KEEP"), nil)
  sys.call("rm -rf " .. inflight)
end

-- Discard: accept the current state instead.
utils.write_file(A, "ORIGINAL")
local disc = utils.snapshot_begin("discard")
utils.snapshot_add(disc, A)
utils.snapshot_arm(disc)
utils.write_file(A, "kept as-is")
utils.snapshot_keep(disc)
check("rollback_discard removes the store", utils.rollback_discard(disc.dir), true)
check("  and leaves the current content alone", utils.read_file(A), "kept as-is")
check("  the orphan list no longer shows it", (function()
  for _, o in ipairs(utils.rollback_orphans()) do if o.dir == disc.dir then return true end end
  return false
end)(), false)

--------------------------------------------------------------------------
reset()
print(string.format("\n%d passed, %d failed, %d skipped", pass, fail, skipped))
if fail > 0 then
  print("\nfailures:")
  for _, f in ipairs(failures) do print("  " .. f) end
  os.exit(1)
end
os.exit(0)
