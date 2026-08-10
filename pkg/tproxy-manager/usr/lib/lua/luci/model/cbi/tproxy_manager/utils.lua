local nixio = require "nixio"
local fs = require "nixio.fs"
local sys = require "luci.sys"
local jsonc = require "luci.jsonc"
local _ = require "luci.model.cbi.tproxy_manager.i18n"

local M = {}

-- utils.lua is required by almost every CBI module before the first use of
-- math.random() for temp file names (atomic_write here, and
-- validate_*_text in mihomo.lua/singbox.lua) — seed the PRNG in one place
-- instead of relying on some other module having seeded it first.
math.randomseed(os.time() + math.floor(os.clock() * 1000000))

function M.trim(value)
  return tostring(value or ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
end

function M.ensure_dir(path)
  local dir = M.trim(path)
  if dir == "" then return false end
  local st = fs.stat(dir)
  if st and st.type == "directory" then return true end
  return sys.call("mkdir -p " .. M.shellescape(dir) .. " >/dev/null 2>&1") == 0
end

-- promote_file: rename tmp -> path, with a sync+retry if the bare rename(2)
-- fails. Observed in the field on some flash filesystems (UBIFS/overlay)
-- under heavy write pressure: rename(2) — and even a plain unlink(2) — can
-- fail with a stale-handle error (ESTALE) even though tmp and path are on
-- the same filesystem and both paths are perfectly valid; the kernel's
-- cached view has simply drifted from the underlying filesystem's actual
-- state. A `sync` reliably reconciles that and lets a retried rename
-- succeed — confirmed by hand on an affected router. `mv` is used as the
-- last-resort fallback (not `cp`) because it does not touch the existing
-- destination at all when it fails, so a failed promote never risks losing
-- the previous, still-good file — it only leaves both tmp and path in
-- place for a later retry.
function M.promote_file(tmp, path)
  -- Verify the RESULT, never just the return code. If the target path has
  -- been replaced by a directory, `mv -f file dir` succeeds by moving the
  -- file INSIDE it and exits 0 — the write is then reported as done while
  -- the real path still holds a directory. rename(2) refuses that case, but
  -- the mv fallback does not, so the check has to cover every branch.
  local function landed()
    local st = fs.stat(path)
    return st ~= nil and st.type == "reg"
  end

  if fs.rename(tmp, path) and landed() then return true end
  sys.call("sync")
  if fs.rename(tmp, path) and landed() then return true end
  if sys.call("mv -f " .. M.shellescape(tmp) .. " " .. M.shellescape(path) .. " >/dev/null 2>&1") == 0 then
    if landed() then return true end
    -- mv "succeeded" into a directory: remove what it dropped there so the
    -- failed write leaves nothing behind under /etc or /usr.
    local base = tmp:match("([^/]+)$")
    if base then
      sys.call("rm -f " .. M.shellescape(path .. "/" .. base) .. " >/dev/null 2>&1")
    end
  end
  return false
end

-- create_exclusive: create a file in ONE syscall with O_CREAT|O_EXCL and
-- mode 0600. The previous shell-based version ("set -C; : > path" followed
-- by chmod and a separate io.open) was unsafe on two counts: the reopen was
-- a TOCTOU window, and io.open() follows symlinks, so anything that swapped
-- the path for a link in between would have had this root process truncate
-- and overwrite the link target.
--
-- O_EXCL is what actually stops that: POSIX requires open() to fail with
-- EEXIST when the final path component is a symlink, whether or not its
-- target exists. Verified on-device: errno 17 for both a live and a
-- dangling symlink, with the victim file left untouched. (nixio's
-- open_flags does not expose O_NOFOLLOW, so O_EXCL carries this alone.)
-- Returns the nixio file handle, or nil.
local EXCL_FLAGS = nixio.open_flags("wronly", "creat", "excl")

function M.create_exclusive(path)
  local fd = nixio.open(path, EXCL_FLAGS, "600")
  return fd or nil
end

-- secure_write: the single atomic-write path for sensitive files. The
-- temp file is created exclusively and is already 0600 BEFORE any content
-- is written, so the destination never briefly exists world-readable.
function M.secure_write(path, data)
  path = tostring(path or "")
  if path == "" then return false end
  data = tostring(data or ""):gsub("\r\n", "\n")
  local dir = path:match("^(.*)/[^/]+$")
  if dir and dir ~= "" then
    if not M.ensure_dir(dir) then return false end
  end

  -- The temp file lives inside a private 0700 directory on the target's own
  -- filesystem: exclusive creation alone still left a window between our
  -- close() and the rename in a world-writable directory like /tmp, where
  -- another user could swap the path. Inside a 0700 dir nobody else can
  -- even look it up.
  local tmpdir = M.private_tmpdir(path)
  if not tmpdir then return false end
  local tmp = tmpdir .. "/data"

  local fd = M.create_exclusive(tmp)
  if not fd then
    sys.call("rm -rf " .. M.shellescape(tmpdir) .. " >/dev/null 2>&1")
    return false
  end

  -- Every step is checked: a short write or a failed close would otherwise
  -- promote a truncated file over a good one.
  local written = fd:write(data)
  local closed = fd:close()
  if written ~= #data or not closed then
    sys.call("rm -rf " .. M.shellescape(tmpdir) .. " >/dev/null 2>&1")
    return false
  end

  local ok = M.promote_file(tmp, path)
  sys.call("rm -rf " .. M.shellescape(tmpdir) .. " >/dev/null 2>&1")
  if not ok then return false, "write" end
  -- promote_file may fall back to `mv`, which preserves the source mode, so
  -- re-assert 0600 on the final path.
  --
  -- Contract mirrors commit_uci(): the file is ALREADY replaced by this
  -- point, so a chmod failure must not look like "the write did not
  -- happen". A caller that rolled back on a plain false would undo a write
  -- that actually succeeded.
  --   true                 - written and secured
  --   false, "write"       - NOT written; safe to roll back
  --   false, "permissions" - written, but mode could not be set
  if sys.call("chmod 0600 " .. M.shellescape(path) .. " >/dev/null 2>&1") ~= 0 then
    return false, "permissions"
  end
  return true
end

-- secure_lock_root: create (or validate) the package's lock directory.
-- /var/lock is 1777, so the path can be pre-created by any local user; a
-- planted symlink or a foreign directory would either redirect our locks or
-- deny them entirely. mkdir is atomic and fails if the name exists in any
-- form, so a successful mkdir proves we made it. If it already exists we
-- verify with lstat that it is a real directory (not a symlink), owned by
-- root, mode 0700 - anything else is refused rather than used.
-- Returns the path, or nil plus a reason.
function M.secure_lock_root(path)
  if sys.call("mkdir -m 0700 " .. M.shellescape(path) .. " >/dev/null 2>&1") == 0 then
    return path
  end
  local st = fs.lstat(path)
  if not st then return nil, "lock directory is not accessible" end
  if st.type ~= "dir" and st.type ~= "directory" then
    return nil, "lock path exists but is not a directory"
  end
  if (st.uid or -1) ~= 0 then return nil, "lock directory is not owned by root" end
  if (st.modedec or 0) ~= 700 then
    sys.call("chmod 0700 " .. M.shellescape(path) .. " >/dev/null 2>&1")
    local again = fs.lstat(path)
    if not again or (again.modedec or 0) ~= 700 then
      return nil, "lock directory has unsafe permissions"
    end
  end
  return path
end

-- random_hex: CSPRNG bytes as hex. math.random is seeded from the clock, so
-- anything derived from it is guessable by a local user — unusable for a name
-- that root will later create, chmod and untar into. Returns nil rather than a
-- weak fallback: a caller that cannot get real entropy must fail, not proceed.
function M.random_hex(bytes)
  bytes = tonumber(bytes) or 16
  local fh = io.open("/dev/urandom", "rb")
  if not fh then return nil end
  local raw = fh:read(bytes)
  fh:close()
  if not raw or #raw ~= bytes then return nil end
  return (raw:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

-- private_dir: create a fresh 0700 directory under `parent` and prove we made
-- it. `mkdir` without -p fails if the name exists in ANY form — file, directory
-- or symlink — which is the whole point: ensure_dir()/mkdir -p happily adopt a
-- path someone else pre-created in world-writable /tmp, and every later chmod,
-- cp, find and tar would then follow their symlink as root.
--
-- Returns the path, or nil plus a reason.
function M.private_dir(parent, prefix)
  if not M.ensure_dir(parent) then return nil, "parent directory is unavailable" end
  prefix = tostring(prefix or "tpm"):gsub("[^%w%-_.]", "")
  if prefix == "" then prefix = "tpm" end
  for __ = 1, 8 do
    local suffix = M.random_hex(12)
    if not suffix then return nil, "no entropy available for a private directory" end
    local dir = string.format("%s/%s.%s", parent, prefix, suffix)
    if sys.call("mkdir -m 0700 " .. M.shellescape(dir) .. " >/dev/null 2>&1") == 0 then
      -- Confirm what we got is a real directory we own, not something that
      -- appeared between the mkdir and now.
      local st = fs.lstat(dir)
      if st and (st.type == "dir" or st.type == "directory")
        and (st.uid or -1) == 0 and (st.modedec or 0) == 700 then
        return dir
      end
      sys.call("rm -rf " .. M.shellescape(dir) .. " >/dev/null 2>&1")
      return nil, "private directory failed validation"
    end
  end
  return nil, "could not create a private directory"
end

function M.private_tmpdir(for_path)
  local dir = tostring(for_path or ""):match("^(.*)/[^/]+$") or "/tmp"
  if not M.ensure_dir(dir) then return nil end
  for __ = 1, 8 do
    local candidate = string.format("%s/.tpm-tmp.%d.%d", dir,
      math.random(1, 10 ^ 9), math.random(1, 10 ^ 9))
    -- mkdir is atomic and fails if the name exists in any form, including
    -- as a symlink - so this cannot be pre-planted either.
    if sys.call("mkdir -m 0700 " .. M.shellescape(candidate) .. " >/dev/null 2>&1") == 0 then
      return candidate
    end
  end
  return nil
end

-- uci_unset: delete an option and report the RESULT, not the return code.
-- uci:delete answers false when the option was not there to begin with, which
-- is the normal case for every optional field. Treating that as a staging
-- failure made a perfectly good save report "Failed to save settings" and
-- revert everything the user had just entered.
function M.uci_unset(uci, pkg, section, option)
  uci:delete(pkg, section, option)
  local left = uci:get(pkg, section, option)
  return left == nil or left == false
end

-- uci_stage: set a value, or clear the option when the value is empty.
-- Single place where "what does an empty field mean" is decided, so the
-- set and delete halves cannot drift apart between callers.
function M.uci_stage(uci, pkg, section, option, value)
  if value ~= nil and value ~= "" then
    return uci:set(pkg, section, option, value) and true or false
  end
  return M.uci_unset(uci, pkg, section, option)
end

-- self_pid: the PID recorded as a lock owner. nixio reports it directly;
-- /proc/self/stat is the fallback for a build without it.
function M.self_pid()
  if type(nixio.getpid) == "function" then
    local pid = nixio.getpid()
    if type(pid) == "number" and pid > 0 then return tostring(pid) end
  end
  local fh = io.open("/proc/self/stat")
  if not fh then return nil end
  local line = fh:read("*l"); fh:close()
  local pid = line and line:match("^(%d+)")
  return pid
end

-- lock_acquire: the package's shared mutex, byte-compatible with the one in
-- tproxy-manager-subscriptions.lua (same root, same "pid" file, same
-- staleness rules) so the LuCI side and the background fetch/sync runs
-- actually exclude each other instead of each honouring its own lock.
--
-- mkdir is the atomic primitive: whoever creates the directory owns it.
-- Staleness is PID-aware rather than TTL-only — a slow but live owner is
-- never interrupted, while a crashed one frees the lock at once. An
-- ownerless lock is the window between another process's mkdir and its pid
-- write, so it counts as live until `grace` seconds have passed.
--
-- Returns a table with .dir/.pid/.release(), or nil plus a reason.
function M.lock_acquire(name, grace)
  grace = grace or 300
  local root, err = M.secure_lock_root("/var/lock/tproxy-manager")
  if not root then return nil, err end
  local dir = root .. "/" .. name

  local function try_mkdir()
    return sys.call("mkdir " .. M.shellescape(dir) .. " >/dev/null 2>&1") == 0
  end

  local function claim()
    local pid = M.self_pid()
    if not pid then
      sys.call("rm -rf " .. M.shellescape(dir) .. " >/dev/null 2>&1")
      return nil, "could not determine the lock owner pid"
    end
    -- Written directly: secure_write() would create its temp directory next
    -- to the target and recurse through the very locking being set up here.
    fs.writefile(dir .. "/pid", pid .. "\n")
    if M.trim(M.read_file(dir .. "/pid")) ~= pid then
      sys.call("rm -rf " .. M.shellescape(dir) .. " >/dev/null 2>&1")
      return nil, "could not record the lock owner"
    end
    return {
      dir = dir,
      pid = pid,
      release = function()
        fs.remove(dir .. "/pid")
        sys.call("rmdir " .. M.shellescape(dir) .. " >/dev/null 2>&1")
      end,
    }
  end

  if try_mkdir() then return claim() end

  local owner = M.trim(M.read_file(dir .. "/pid"))
  local stale
  if owner:match("^%d+$") then
    stale = fs.stat("/proc/" .. owner) == nil
  else
    local st = fs.stat(dir)
    stale = ((st and st.mtime) and (os.time() - st.mtime) or 0) > grace
  end
  if not stale then return nil, "busy" end

  sys.call("rm -rf " .. M.shellescape(dir) .. " >/dev/null 2>&1")
  if try_mkdir() then return claim() end
  return nil, "busy"
end

-- The subscription database, the links file and every background fetch run
-- share this one lock name; it must match LOCK_DIR in
-- tproxy-manager-subscriptions.lua.
M.SUBSCRIPTIONS_LOCK = "watchdog.lock"

-- restore_one: put a single file back from an in-memory record and VERIFY the
-- result rather than trusting a return code. Only the store below uses this;
-- the record always comes from an on-disk snapshot copy, never from a value
-- that has been sitting in this process since before the first write.
--
--   "ok"          - the previous state is fully back (bytes and mode)
--   "permissions" - content is back, but the mode could not be restored
--   "failed"      - the previous state is NOT back; the caller must say so
local function restore_one(snap)
  if type(snap) ~= "table" or type(snap.path) ~= "string" then return "failed" end
  local path = snap.path

  if not snap.exists then
    fs.remove(path)
    if fs.stat(path) then return "failed" end
    return "ok"
  end

  if snap.type and snap.type ~= "reg" then return "failed" end

  local ok, why = M.secure_write(path, snap.data)
  if not ok and why ~= "permissions" then return "failed" end

  -- Content is verified by reading it back: `mv file dir` and a truncated
  -- write both look like success from the writer's side.
  local st = fs.stat(path)
  if not st or st.type ~= "reg" then return "failed" end
  if M.read_file_checked(path) ~= snap.data then return "failed" end

  if snap.perm then
    sys.call(string.format("chmod %s %s >/dev/null 2>&1", snap.perm, M.shellescape(path)))
    local after = fs.stat(path)
    if not after or tostring(after.modedec) ~= snap.perm then
      return "permissions"
    end
  end

  if not ok then return "permissions" end
  return "ok"
end

--------------------------------------------------------------------------
-- Durable rollback snapshots
--------------------------------------------------------------------------
-- A transaction that spans several files needs its "before" state to survive
-- more than the request that created it. Keeping it in memory meant a crash
-- (or an OOM-killed CGI) between the first write and the rollback left the
-- previous content nowhere at all, and a copy written next to the target only
-- AFTER a failed restore is written into exactly the situation that just
-- proved unwritable.
--
-- So: copy every file into a private 0700 directory BEFORE touching anything,
-- verify each copy by reading it back, and keep the directory only when the
-- rollback could not complete — its path is then shown to the user.
--
-- The root lives on PERSISTENT storage, not tmpfs. A store that survives only
-- until the next reboot is not a rollback: a transaction interrupted by a power
-- cut is exactly the case where the previous contents are needed, and tmpfs
-- loses them precisely then. The cost is a copy of the files a transaction is
-- about to rewrite anyway, and only for transactions that reach the arming
-- point; the happy path removes the store immediately afterwards.
--
-- It sits under /etc/tproxy-manager, which the package already owns, so the
-- directory inherits that parent's protection rather than living in
-- world-writable /tmp. It is still created and validated like the lock root.
M.ROLLBACK_ROOT = "/etc/tproxy-manager/.rollback"

-- A store carries its transaction STAGE, and the sweeper acts on it:
--
--   "prepared" - snapshots taken, no live file touched yet. An owner that died
--                here changed nothing, so the store is pure garbage and is
--                reclaimed.
--   "applying" - the transaction has begun writing live files. An owner that
--                died here may have written some of them and none of the
--                rollback, so the live state is UNKNOWN. Such a store is the
--                only record of the previous contents and must survive until
--                an operator deals with it.
--
-- Without the stage the sweeper had to guess, and it guessed "reclaim" — which
-- is exactly wrong for a half-applied transaction.
local STAGE_PREPARED = "prepared"
local STAGE_APPLYING = "applying"

-- write_meta: verified write of one of the store's own bookkeeping files. The
-- sweeper and the operator act on their content, so a silent failure here is
-- as damaging as losing a snapshot copy.
local function write_meta(path, data)
  local ok, why = M.secure_write(path, data)
  if not ok and why ~= "permissions" then return false end
  return M.read_file_checked(path) == data
end

-- Owner identity of a store: (boot id, pid, process start time).
--
-- A bare pid is not an identity. Across a reboot the numbers restart, so a
-- store from an earlier boot would look "alive" because something unrelated now
-- holds that number; within one boot pids are recycled the same way once the
-- counter wraps. Both are covered by pinning the boot and the process's own
-- start time, which the kernel never reuses for a different process in the same
-- boot.
local function boot_id()
  local data = M.read_file("/proc/stat")
  local btime = data:match("\nbtime%s+(%d+)") or data:match("^btime%s+(%d+)")
  return btime or ""
end

-- proc_starttime: field 22 of /proc/<pid>/stat.
--
-- Field 2 is the executable name in parentheses and may itself contain spaces
-- AND parentheses, so the tail has to start after the LAST ")". The pattern
-- must be anchored and greedy to get that: `"%)%s*(.*)$"` looks unanchored and
-- therefore lazy — Lua's match scans left to right for the first position where
-- the pattern can start, so it binds to the FIRST ")" and, for a process named
-- e.g. "a)b", returns a tail shifted by one field. `^.*%)` anchors at the start
-- and lets the greedy `.*` swallow everything up to the final ")".
function M.proc_starttime(pid)
  local data = M.read_file("/proc/" .. tostring(pid) .. "/stat")
  if data == "" then return nil end
  local tail = data:match("^.*%)%s+(.*)$")
  if not tail then return nil end
  local n = 0
  for field in tail:gmatch("%S+") do
    n = n + 1
    -- state is field 3, so field 22 is the 20th token after the name.
    if n == 20 then return field end
  end
  return nil
end

-- owner_token: what gets recorded, and what the sweeper compares against.
local function owner_token(pid)
  local b = boot_id()
  if b == "" then return nil end
  local st = M.proc_starttime(pid)
  if not st then return nil end
  return string.format("%s %s %s", b, tostring(pid), st)
end

local function store_stage(dir)
  local data = M.read_file_checked(dir .. "/STAGE")
  if not data then return nil end
  return M.trim(data)
end

-- snapshot_sweep: reclaim stores left behind by processes that no longer
-- exist, and PRESERVE the ones that died mid-apply. The directory name carries
-- the owning pid, so liveness is checked the same way the locks do it.
local function snapshot_sweep(root)
  local st = fs.stat(root)
  if not st or st.type ~= "dir" then return end
  local ok, iter = pcall(fs.dir, root)
  if not ok or not iter then return end
  for name in iter do
    local pid = name:match("^[%w%-_]+%.(%d+)%.%d+$")
    if pid then
      local dir = root .. "/" .. name
      -- Three outcomes, and the difference matters:
      --   recorded owner matches a live process -> in flight, leave alone;
      --   recorded owner is gone                -> decide by stage;
      --   owner cannot be established at all    -> PRESERVE. Deleting a store
      --     we cannot reason about is how a live transaction lost its snapshot.
      local recorded = M.trim(M.read_file(dir .. "/OWNER"))
      local owner_known = recorded ~= ""
      local owner_alive = owner_known and (recorded == owner_token(pid))

      -- Already marked for the operator: never reconsidered.
      if not fs.stat(dir .. "/KEEP") and not owner_alive then
        if owner_known and store_stage(dir) == STAGE_PREPARED then
          sys.call("rm -rf " .. M.shellescape(dir) .. " >/dev/null 2>&1")
        else
          -- Either mid-apply, or the stage itself is unreadable — both mean
          -- "cannot prove the live files are untouched", so keep it. Marking
          -- it makes the decision permanent and self-documenting.
          write_meta(dir .. "/KEEP", owner_known
            and ("owner pid " .. pid .. " died mid-transaction; live files may be half-written\n")
            or ("the owner of pid " .. pid .. " could not be established; preserved for inspection\n"))
          sys.exec(string.format(
            "logger -t tproxy-manager %s",
            M.shellescape("rollback snapshot preserved after an interrupted transaction: " .. dir)))
        end
      end
    end
  end
end

-- snapshot_keep: mark a store as deliberately preserved and return its path.
-- Returns nil if the marker could not be written - the caller must then not
-- promise the user that the contents are safe there.
function M.snapshot_keep(store)
  if not (store and store.dir) then return nil end
  if not write_meta(store.dir .. "/KEEP", "kept after an incomplete rollback\n") then
    return nil
  end
  return store.dir
end

-- snapshot_arm: record that live files are about to be written. MUST be called
-- after the last snapshot_add and before the first live write; if the stage
-- cannot be recorded the transaction has to abort, because a crash would then
-- leave a store the sweeper believes is safe to delete.
function M.snapshot_arm(store)
  if not (store and store.dir) then return nil, "no snapshot store" end
  if not write_meta(store.dir .. "/STAGE", STAGE_APPLYING .. "\n") then
    return nil, "could not record the transaction stage"
  end
  store.armed = true
  return true
end

function M.snapshot_begin(label)
  local root, err = M.secure_lock_root(M.ROLLBACK_ROOT)
  if not root then return nil, err end
  snapshot_sweep(root)
  label = tostring(label or "tx"):gsub("[^%w%-_]", "")
  if label == "" then label = "tx" end
  local pid = M.self_pid() or "0"
  for __ = 1, 8 do
    local dir = string.format("%s/%s.%s.%d", root, label, pid, math.random(100000, 999999))
    if sys.call("mkdir -m 0700 " .. M.shellescape(dir) .. " >/dev/null 2>&1") == 0 then
      if not write_meta(dir .. "/STAGE", STAGE_PREPARED .. "\n") then
        sys.call("rm -rf " .. M.shellescape(dir) .. " >/dev/null 2>&1")
        return nil, "could not record the transaction stage"
      end
      -- MANDATORY, not best effort. The sweeper decides whether the owner is
      -- alive from this file; an unwritten or empty one made a live, still
      -- "prepared" store look ownerless, and the very next listing deleted it
      -- out from under the running transaction.
      local owner = owner_token(pid)
      if not owner or not write_meta(dir .. "/OWNER", owner .. "\n") then
        sys.call("rm -rf " .. M.shellescape(dir) .. " >/dev/null 2>&1")
        return nil, "could not record the transaction owner"
      end
      return { dir = dir, items = {} }
    end
  end
  return nil, "could not create a rollback directory"
end

local function snapshot_manifest(store)
  local lines = {}
  for __, it in ipairs(store.items) do
    lines[#lines + 1] = string.format("%03d %-6s %s", it.idx,
      it.exists and (it.perm or "?") or "absent", it.path)
  end
  return write_meta(store.dir .. "/MANIFEST", table.concat(lines, "\n") .. "\n")
end

-- snapshot_add: record one file's current state. A file that does not exist is
-- recorded as absent so the rollback deletes whatever the transaction creates.
-- Returns nil plus a reason if the snapshot cannot be trusted — callers must
-- abort rather than proceed without a way back.
function M.snapshot_add(store, path)
  local idx = #store.items + 1
  local st = fs.stat(path)
  local item = { idx = idx, path = path }

  if not st then
    item.exists = false
  elseif st.type ~= "reg" then
    return nil, path .. " is not a regular file"
  else
    item.exists = true
    item.perm = st.modedec and tostring(st.modedec) or nil
    -- Checked read: an unreadable file must not be snapshotted as empty, or
    -- the rollback would truncate it.
    local data, rerr = M.read_file_checked(path)
    if not data then return nil, rerr end
    local copy = string.format("%s/%03d.dat", store.dir, idx)
    local ok, why = M.secure_write(copy, data)
    if not ok and why ~= "permissions" then
      return nil, "could not snapshot " .. path
    end
    -- Verified by reading it back: a silently truncated snapshot is worse than
    -- none, because the rollback would restore the truncation.
    if M.read_file_checked(copy) ~= data then
      return nil, "snapshot of " .. path .. " did not verify"
    end
    item.copy = copy
  end

  store.items[idx] = item
  -- The manifest is what an operator reads to know which copy belongs to which
  -- path; a store whose manifest could not be written is not usable evidence.
  if not snapshot_manifest(store) then
    store.items[idx] = nil
    return nil, "could not record the snapshot manifest"
  end
  return true
end

function M.snapshot_restore(store)
  local failed = {}
  for __, it in ipairs(store.items) do
    local state
    if not it.exists then
      fs.remove(it.path)
      state = fs.stat(it.path) and "failed" or "ok"
    else
      -- The copy is read with the CHECKED reader: a snapshot that has gone
      -- missing or become unreadable must not be restored as empty content,
      -- which would truncate the very file it was protecting.
      local data = M.read_file_checked(it.copy)
      if not data then
        state = "failed"
      else
        state = restore_one({
          path = it.path, exists = true, type = "reg",
          data = data, perm = it.perm,
        })
      end
    end
    if state ~= "ok" then failed[#failed + 1] = { path = it.path, state = state } end
  end
  return failed
end

function M.snapshot_discard(store)
  if store and store.dir then
    sys.call("rm -rf " .. M.shellescape(store.dir) .. " >/dev/null 2>&1")
  end
end

--------------------------------------------------------------------------
-- Recovery from an interrupted transaction
--------------------------------------------------------------------------
-- Preserving a store told the operator something was wrong but left the live
-- files half-written, with no way to act on it from the UI. These three
-- functions close that: list what was preserved, put it back, or accept the
-- current state and drop it.

-- rollback_orphans: preserved stores, newest first, each with the paths it can
-- restore. A store is "preserved" when it carries the KEEP marker - the sweeper
-- writes it for an owner that died mid-apply, and snapshot_keep() writes it for
-- a rollback that could not complete.
function M.rollback_orphans()
  local out = {}
  local root = fs.stat(M.ROLLBACK_ROOT)
  if not root or root.type ~= "dir" then return out end
  -- Sweep FIRST. A store left by a process that just died is still in the
  -- "applying" stage with no KEEP marker: the marker is what the sweeper
  -- writes. Without this the UI stayed silent about a half-applied change
  -- until some unrelated write operation happened to run snapshot_begin() —
  -- exactly the window in which an operator needs to see it.
  snapshot_sweep(M.ROLLBACK_ROOT)
  local ok, iter = pcall(fs.dir, M.ROLLBACK_ROOT)
  if not ok or not iter then return out end
  for name in iter do
    local dir = M.ROLLBACK_ROOT .. "/" .. name
    if fs.stat(dir .. "/KEEP") then
      local entry = { dir = dir, name = name, files = {} }
      local st = fs.stat(dir)
      entry.mtime = st and st.mtime or 0
      entry.reason = M.trim(M.read_file(dir .. "/KEEP"))
      -- The manifest is "NNN mode path" per line, written by snapshot_add.
      for line in (M.read_file(dir .. "/MANIFEST") .. "\n"):gmatch("([^\n]*)\n") do
        local idx, mode, path = line:match("^(%d+)%s+(%S+)%s+(.+)$")
        if idx then
          entry.files[#entry.files + 1] = {
            idx = idx, perm = (mode ~= "absent") and mode or nil,
            exists = (mode ~= "absent"), path = path,
            copy = dir .. "/" .. idx .. ".dat",
          }
        end
      end
      out[#out + 1] = entry
    end
  end
  table.sort(out, function(a, b) return (a.mtime or 0) > (b.mtime or 0) end)
  return out
end

-- rollback_recover: put one preserved store back. Returns true when every file
-- is restored (the store is then removed), or false plus the list of paths that
-- could not be restored - in which case the store is deliberately left in place.
function M.rollback_recover(dir)
  local target
  for __, entry in ipairs(M.rollback_orphans()) do
    if entry.dir == dir then target = entry; break end
  end
  if not target then return false, { "no such preserved snapshot" } end
  if #target.files == 0 then return false, { "the snapshot manifest is unreadable" } end

  local failed = M.snapshot_restore({ dir = dir, items = target.files })
  if #failed > 0 then
    local names = {}
    for __, f in ipairs(failed) do names[#names + 1] = f.path .. (f.state == "permissions" and " (mode)" or "") end
    return false, names
  end
  sys.call("rm -rf " .. M.shellescape(dir) .. " >/dev/null 2>&1")
  return true
end

-- rollback_discard: accept the current state of the files and drop the store.
function M.rollback_discard(dir)
  local target
  for __, entry in ipairs(M.rollback_orphans()) do
    if entry.dir == dir then target = entry; break end
  end
  if not target then return false end
  sys.call("rm -rf " .. M.shellescape(dir) .. " >/dev/null 2>&1")
  return fs.stat(dir) == nil
end

-- commit_uci: commit and then re-apply 0600 to the config (uci recreates
-- it 0644, and it holds tokens and paths).
--
-- Returns:
--   true                    - committed AND secured
--   false, "commit"         - NOT committed; the caller may safely undo
--   false, "permissions"    - committed, but chmod failed
--
-- The distinction matters: a caller that rolls its file back on any falsy
-- return would corrupt state in the "permissions" case, where the UCI
-- change is already durable and must NOT be undone.
function M.commit_uci(uci, pkg)
  if not uci:commit(pkg) then
    return false, "commit"
  end
  if sys.call("chmod 0600 " .. M.shellescape("/etc/config/" .. pkg) .. " >/dev/null 2>&1") ~= 0 then
    return false, "permissions"
  end
  return true
end

-- atomic_write / write_file are the historical entry points used all over
-- the CBI modules (list files, engine configs, watchdog files). They now
-- delegate to the single checked writer: exclusive creation inside a
-- private 0700 directory on the target filesystem, verified write/close,
-- promote, 0600. Kept as thin aliases so every existing caller is covered
-- without touching dozens of call sites.
function M.atomic_write(path, data)
  return M.secure_write(path, data)
end

function M.read_file(path)
  if type(path) ~= "string" or path == "" then return "" end
  return fs.readfile(path) or ""
end

-- read_file_checked: read_file() collapses every failure into "" — a missing
-- file, an unreadable one and a genuinely empty one are indistinguishable.
-- That is tolerable when rendering a page, and unacceptable when the result
-- becomes a rollback snapshot: a failed read would be stored as empty content
-- and the rollback would then TRUNCATE the file it was meant to protect.
--
-- Returns the data, or nil plus a reason. The size cross-check catches a short
-- read; if the file is being rewritten underneath us the snapshot is refused
-- rather than taken half-way, which is the safe direction.
function M.read_file_checked(path)
  if type(path) ~= "string" or path == "" then return nil, "empty path" end
  local st = fs.stat(path)
  if not st then return nil, path .. " does not exist" end
  if st.type ~= "reg" then return nil, path .. " is not a regular file" end
  local data = fs.readfile(path)
  if data == nil then return nil, path .. " could not be read" end
  if st.size and #data ~= st.size then
    return nil, path .. " changed while being read"
  end
  return data
end


function M.write_file(path, data)
  return M.atomic_write(path, data or "")
end

function M.strip_json_comments(s)
  s = tostring(s or "")
  local out, i, n = {}, 1, #s
  local in_str, esc = false, false
  while i <= n do
    local c = s:sub(i, i)
    local d = s:sub(i + 1, i + 1)
    if in_str then
      out[#out + 1] = c
      if esc then
        esc = false
      elseif c == "\\" then
        esc = true
      elseif c == '"' then
        in_str = false
      end
      i = i + 1
    else
      if c == '"' then
        in_str = true
        out[#out + 1] = c
        i = i + 1
      elseif c == "/" and d == "/" then
        i = i + 2
        while i <= n and s:sub(i, i) ~= "\n" do i = i + 1 end
      elseif c == "/" and d == "*" then
        i = i + 2
        while i <= n - 1 and not (s:sub(i, i) == "*" and s:sub(i + 1, i + 1) == "/") do
          i = i + 1
        end
        i = i + 2
      else
        out[#out + 1] = c
        i = i + 1
      end
    end
  end
  return table.concat(out)
end

function M.parse_jsonc(text)
  local cleaned = M.strip_json_comments(text or "")
  local ok, parsed = pcall(jsonc.parse, cleaned)
  if not ok or parsed == nil then
    return nil, _("Invalid JSON/JSONC")
  end
  return parsed
end

function M.parse_jsonc_or_error(text, empty_value)
  local raw = tostring(text or "")
  if raw == "" then return empty_value or {} end
  return M.parse_jsonc(raw)
end

function M.validate_jsonc_text(text)
  local parsed = M.parse_jsonc(text or "")
  return parsed ~= nil
end

function M.shellescape(value)
  value = tostring(value or "")
  if value == "" then return "''" end
  return "'" .. value:gsub("'", "'\\''") .. "'"
end

function M.parse_kv_text(text)
  local data = {}
  for line in ((text or "") .. "\n"):gmatch("([^\n]*)\n") do
    local k, v = line:match("^([A-Za-z0-9_]+)=(.*)$")
    if k then data[k] = v end
  end
  return data
end

function M.make_temp_message_store(err_file, info_file, err_ttl)
  local ttl = tonumber(err_ttl) or 0

  local function set_file(path, text)
    if text and text ~= "" then
      M.write_file(path, text)
    else
      fs.remove(path)
    end
  end

  -- Both err and info use the same TTL-based staleness check rather than a
  -- "read once, then delete" one-shot: the LuCI CBI framework calls a
  -- DummyValue's cfgvalue() more than once per request even when a redirect
  -- was issued (its own render pass never reaches the client, but it still
  -- runs). A one-shot clear-on-read would then already consume the message
  -- during that first, discarded pass, so the real page the user actually
  -- sees on the next request finds nothing left to show. TTL expiry has no
  -- such race: the message just reads back correctly however many times
  -- cfgvalue() happens to run, and disappears on its own after err_ttl
  -- seconds instead of relying on being "seen" exactly once.
  local function make_getter(path)
    return function()
      local st = fs.stat(path)
      if st and st.mtime and ttl > 0 and (os.time() - st.mtime) > ttl then
        fs.remove(path)
        return ""
      end
      return M.read_file(path)
    end
  end

  return {
    set_err = function(text) set_file(err_file, text) end,
    get_err = make_getter(err_file),
    set_info = function(text) set_file(info_file, text) end,
    get_info = make_getter(info_file),
  }
end

function M.is_port(value)
  local n = tonumber(value)
  return n ~= nil and n >= 1 and n <= 65535 and tostring(value):match("^%d+$") ~= nil
end

function M.is_uint(value, min_value, max_value)
  if not tostring(value or ""):match("^%d+$") then return false end
  local n = tonumber(value)
  if min_value ~= nil and n < min_value then return false end
  if max_value ~= nil and n > max_value then return false end
  return true
end

function M.is_ipv4(value)
  local a, b, c, d = tostring(value or ""):match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then return false end
  for __, part in ipairs({ a, b, c, d }) do
    local n = tonumber(part)
    if not n or n < 0 or n > 255 then return false end
  end
  return true
end

function M.is_abs_path(path)
  path = tostring(path or "")
  if path:match("^/[%w%._%-%+/@:]*$") == nil then return false end
  -- separately reject any ".." path segment, so directory traversal
  -- (e.g. "/etc/x/../../etc/passwd") cannot slip through even though
  -- every individual character is allowed by the class above.
  for segment in (path .. "/"):gmatch("([^/]*)/") do
    if segment == ".." then return false end
  end
  return true
end

function M.is_iface_name(name)
  name = tostring(name or "")
  return name:match("^[%w%._:%-]+$") ~= nil
end

function M.is_nft_table_name(name)
  name = tostring(name or "")
  return name:match("^[A-Za-z_][A-Za-z0-9_%-]*$") ~= nil
end

function M.is_fwmark(value)
  value = tostring(value or "")
  return value:match("^0x[%da-fA-F]+$") ~= nil or value:match("^%d+$") ~= nil
end

return M
