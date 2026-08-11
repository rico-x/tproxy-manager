local jsonc = require "luci.jsonc"

local M = {}

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

local function read_file(path)
  local fh = io.open(path, "rb")
  if not fh then return "" end
  local data = fh:read("*a") or ""
  fh:close()
  return data
end

local function exec_capture(cmd)
  local p = io.popen(cmd .. " 2>&1")
  if not p then return 1, "" end
  local out = p:read("*a") or ""
  local ok, _, code = p:close()
  return ok and 0 or tonumber(code) or 1, trim(out)
end

local function exec_ok(cmd)
  local rc = os.execute(cmd)
  return rc == true or rc == 0
end


local function command_output(cmd)
  local p = io.popen(cmd .. " 2>/dev/null")
  if not p then return "" end
  local out = trim(p:read("*a") or "")
  p:close()
  return out
end

local function file_exists(path)
  local fh = io.open(path, "rb")
  if fh then fh:close(); return true end
  return false
end

local function ensure_dir(path)
  return exec_ok("mkdir -p " .. shellescape(path) .. " >/dev/null 2>&1")
end

-- Paths this module must never delete or claim ownership of, whatever a caller
-- passes in. ensure_private_dir() WIPES what it cannot trust, and a shared root
-- can never pass the "root-only" test — /tmp is mode 1777 by definition — so a
-- caller that resolved one by accident would have had root run `rm -rf /tmp`.
-- Nothing here is worth a clever rule: an explicit refusal list, plus a minimum
-- depth so the shallowest thing that can ever be touched is a NAMED CHILD of a
-- system directory rather than the directory itself.
local DANGEROUS_PATHS = {
  [""] = true, ["."] = true, [".."] = true, ["/"] = true,
  ["/bin"] = true, ["/dev"] = true, ["/dev/shm"] = true, ["/etc"] = true,
  ["/etc/config"] = true, ["/lib"] = true, ["/mnt"] = true, ["/overlay"] = true,
  ["/proc"] = true, ["/root"] = true, ["/sbin"] = true, ["/sys"] = true,
  ["/tmp"] = true, ["/usr"] = true, ["/usr/bin"] = true, ["/usr/lib"] = true,
  ["/usr/sbin"] = true, ["/var"] = true, ["/var/lock"] = true,
  ["/var/log"] = true, ["/var/run"] = true, ["/var/tmp"] = true, ["/www"] = true,
}

local function owned_path_ok(path)
  path = tostring(path or "")
  if DANGEROUS_PATHS[path] then return false end
  if path:sub(1, 1) ~= "/" then return false end          -- absolute only
  if path:sub(-1) == "/" then return false end            -- no trailing slash
  if path:find("//", 1, true) then return false end
  -- No traversal: "/tmp/x/../.." would otherwise resolve upwards past anything.
  if path:find("/%.%.?/") or path:match("/%.%.?$") then return false end
  local depth = 0
  for _ in path:gmatch("[^/]+") do depth = depth + 1 end
  return depth >= 2
end

local function remove_path(path)
  -- Refuses rather than deletes: this is reached with caller-supplied paths.
  if not owned_path_ok(path) then return false end
  return exec_ok("rm -rf " .. shellescape(path) .. " >/dev/null 2>&1")
end

-- The rollback store and the release cache live under fixed, predictable names in
-- the world-writable /tmp, so anything already sitting at one of those paths may
-- have been planted by an unprivileged local process. `mkdir -p` would happily
-- adopt such a directory (or follow a symlink out of /tmp), root would then write
-- the previous binary inside a location that process controls, and the next
-- rollback would copy whatever it finds there over the live engine binary and
-- restart it as root. So the store is inspected before it is trusted: only a real
-- directory owned by root that nobody else can write to qualifies.
local function path_facts(path)
  local rc, out = exec_capture("ls -ldn " .. shellescape(path))
  if rc ~= 0 or out == "" then return nil end
  local mode, uid = out:match("^(%S+)%s+%S+%s+(%d+)")
  if not mode or #mode < 10 then return nil end
  return {
    kind = mode:sub(1, 1),
    uid = uid,
    group_write = mode:sub(6, 6) == "w",
    other_write = mode:sub(9, 9) == "w",
  }
end

local function root_only(path, kind)
  local f = path_facts(path)
  return f ~= nil and f.kind == kind and f.uid == "0"
    and not f.group_write and not f.other_write
end

-- Wipes and recreates the path unless it is already a directory only root can
-- write to. `rm -rf` on a symlink removes the link itself, never its target, and
-- `mkdir` without -p fails if a racing process re-creates the path — so this
-- either yields a trustworthy directory or fails closed.
--
-- The candidate is screened FIRST, before anything is deleted: a shared root such
-- as /tmp fails the root-only test by design, so without the screen this function
-- would delete it.
local function ensure_private_dir(path)
  if not owned_path_ok(path) then return false end
  if not root_only(path, "d") then
    remove_path(path)
    if not exec_ok("mkdir -m 0700 " .. shellescape(path) .. " >/dev/null 2>&1") then return false end
  end
  return root_only(path, "d")
end

-- Gate for anything root is about to install, execute or parse out of /tmp.
local function trusted_file(path)
  return root_only(path, "-")
end

-- Writes through a uniquely named temp file inside the target's own directory and
-- renames it over the target.
--
-- "Remove the path, then open it" is not enough: between the unlink and the open
-- another process can put the symlink back, and root then writes through it into
-- a file it never chose. rename(2) has no such window — it swaps the directory
-- entry itself, atomically, and cannot be redirected by a symlink left at the
-- destination. The temp name is unique so two concurrent runs cannot collide.
--
-- The directory MUST already be one only root can write to; otherwise the temp
-- file itself would be substitutable and the write is refused instead.
local function write_file(path, data)
  if not owned_path_ok(path) then return false end
  local dir = tostring(path):match("^(.*)/[^/]+$") or ""
  if not root_only(dir, "d") then return false end
  local tmp
  for _ = 1, 8 do
    local cand = string.format("%s/.tmp.%d.%d", dir, math.random(1, 10 ^ 9), math.random(1, 10 ^ 9))
    if not path_facts(cand) then tmp = cand; break end
  end
  if not tmp then return false end
  local fh = io.open(tmp, "wb")
  if not fh then return false end
  fh:write(data or "")
  fh:close()
  exec_ok("chmod 0600 " .. shellescape(tmp) .. " >/dev/null 2>&1")
  if not os.rename(tmp, path) then
    remove_path(tmp)
    return false
  end
  return trusted_file(path)
end

-- Reads a file only if root alone could have written it. The release cache is
-- parsed for the download URLs that install() then hands to curl, so a cache an
-- unprivileged process can substitute (directly or through a planted symlink)
-- decides which binary root installs. Anything that does not pass is discarded
-- rather than parsed.
local function read_trusted_file(path)
  if not trusted_file(path) then
    if path_facts(path) then remove_path(path) end
    return ""
  end
  return read_file(path)
end

local function number_output(cmd)
  local out = command_output(cmd)
  return tonumber(out:match("(%d+)") or "") or 0
end

local function file_size_kb(path)
  if not file_exists(path) then return 0 end
  return number_output("du -k " .. shellescape(path) .. " | awk '{print $1}'")
end

local function fs_available_kb(path)
  local dir = path:match("^(.*)/[^/]+$") or path
  local out = command_output("df -k " .. shellescape(dir) .. " | awk 'NR==2 {print $4}'")
  return tonumber(out:match("(%d+)") or "") or 0
end

local function parse_version(value)
  local a, b, c = tostring(value or ""):match("v?(%d+)%.(%d+)%.(%d+)")
  if not a then return nil end
  return { tonumber(a), tonumber(b), tonumber(c) }
end

local function version_string(value)
  local v = parse_version(value)
  return v and string.format("%d.%d.%d", v[1], v[2], v[3]) or ""
end

local function compare_versions(a, b)
  local va, vb = parse_version(a), parse_version(b)
  if not va or not vb then return nil end
  for i = 1, 3 do
    if va[i] < vb[i] then return -1 end
    if va[i] > vb[i] then return 1 end
  end
  return 0
end

local function current_version(cfg, bin)
  local args = cfg.version_args or { "version" }
  local parts = { shellescape(bin) }
  for _, arg in ipairs(args) do
    parts[#parts + 1] = shellescape(arg)
  end
  local rc, out = exec_capture(table.concat(parts, " "))
  if rc ~= 0 then return "", out end
  return version_string(out), out
end

local function detect_bin(cfg)
  if cfg.env_bin and trim(os.getenv(cfg.env_bin)) ~= "" then return trim(os.getenv(cfg.env_bin)) end
  for _, path in ipairs(cfg.bin_paths or {}) do
    if file_exists(path) then return path end
  end
  local found = command_output("command -v " .. shellescape(cfg.binary))
  return found ~= "" and found or (cfg.bin_paths and cfg.bin_paths[1] or cfg.binary)
end

-- Resolves where the release cache lives: a directory this module may own, plus a
-- file inside it. Separate from the rollback store so the two have independent
-- lifetimes, but created and checked the same way — the cache decides which URL
-- install() downloads, so it has to be as untouchable as the binary it leads to.
--
-- The directory part of cache_file is deliberately NOT used as a fallback. The
-- historical layout was "/tmp/tproxy-manager-<engine>-releases.json", whose
-- dirname is the shared /tmp: deriving the store from it handed a path that can
-- never be root-only to a function that wipes what it cannot trust. A caller that
-- names no cache_dir gets a dedicated child derived from cfg.name instead, and if
-- even that is not available the caller gets nothing and runs without a cache.
local function resolve_cache(cfg)
  local dir = cfg.cache_dir
  local file = cfg.cache_file
  if not owned_path_ok(dir) then
    local name = tostring(cfg.name or ""):match("^[%w%-_]+$")
    if not name then return nil, nil end
    dir = "/tmp/tproxy-manager-" .. name .. "-cache"
    file = nil
  end
  -- The file must sit inside the store, or the write would land outside the only
  -- directory whose ownership was verified.
  if not file or not owned_path_ok(file) or file:sub(1, #dir + 1) ~= dir .. "/" then
    file = dir .. "/releases.json"
  end
  return dir, file
end

local function fetch_releases(cfg, force)
  local dir, cache_file = resolve_cache(cfg)
  local store_ok = dir ~= nil and ensure_private_dir(dir)
  -- Earlier versions kept the cache directly in /tmp. Drop that file once the
  -- private store exists so a stale copy nobody validates cannot be read by an
  -- older script left on the system, and so /tmp does not keep the litter.
  if store_ok and cfg.legacy_cache_file then
    remove_path(cfg.legacy_cache_file)
  end
  -- A cache that is not root's alone is not read at all, so nothing an
  -- unprivileged process planted can reach the JSON parser.
  local raw = store_ok and read_trusted_file(cache_file) or ""
  if raw ~= "" and not force then return raw end
  local cmd = "curl -fsSL --connect-timeout 8 --max-time 25 -H " ..
    shellescape("Accept: application/vnd.github+json") .. " " .. shellescape(cfg.api_url)
  local rc, out = exec_capture(cmd)
  if rc == 0 and out:match("^%[") then
    -- Caching is an optimisation: if the store cannot be trusted, keep working
    -- from what was just fetched rather than persisting it somewhere unsafe.
    if store_ok then write_file(cache_file, out) end
    return out
  end
  if raw ~= "" then return raw end
  return nil, out ~= "" and out or "unable to fetch GitHub releases"
end

local function parse_releases(cfg, force)
  local raw, err = fetch_releases(cfg, force)
  if not raw then return nil, err end
  local ok, parsed = pcall(jsonc.parse, raw)
  if not ok or type(parsed) ~= "table" then return nil, "invalid GitHub releases response" end
  return parsed
end

local function asset_for_release(cfg, release)
  if type(release) ~= "table" or type(release.assets) ~= "table" then return nil end
  local wanted = cfg.asset_name(release.tag_name or "", command_output("uname -m"))
  for _, asset in ipairs(release.assets) do
    if type(asset) == "table" and asset.name == wanted then
      return {
        tag = release.tag_name or "",
        published_at = release.published_at or "",
        prerelease = release.prerelease == true,
        name = asset.name,
        url = asset.browser_download_url,
        digest = asset.digest or "",
      }
    end
  end
  return nil
end

local function items_with_asset(cfg, force)
  local releases, err = parse_releases(cfg, force)
  if not releases then return nil, err end
  local out = {}
  for _, release in ipairs(releases) do
    local item = asset_for_release(cfg, release)
    if item then out[#out + 1] = item end
  end
  return out
end

local function latest_stable(items)
  for _, item in ipairs(items or {}) do
    if not item.prerelease then return item end
  end
  return nil
end

local function find_release(items, tag)
  tag = trim(tag)
  for _, item in ipairs(items or {}) do
    if item.tag == tag then return item end
  end
  return nil
end

local function sha256_file(path)
  local rc, out = exec_capture("sha256sum " .. shellescape(path))
  if rc ~= 0 then return "" end
  return trim(out:match("^([0-9a-fA-F]+)") or ""):lower()
end

local function download_file(url, path)
  local rc, out = exec_capture("curl -fL --connect-timeout 10 --max-time 180 -o " .. shellescape(path) .. " " .. shellescape(url))
  return rc == 0, out
end

local function verify_digest(item, archive)
  local expected = tostring(item.digest or ""):match("^sha256:([0-9a-fA-F]+)$")
  expected = expected and expected:lower() or ""
  if expected == "" then return false, "release asset has no SHA256 digest" end
  local actual = sha256_file(archive)
  if actual == "" or actual ~= expected then return false, "SHA256 verification failed" end
  return true
end

local function ends_with(s, suffix)
  s, suffix = tostring(s or ""), tostring(suffix or "")
  return #s >= #suffix and s:sub(#s - #suffix + 1) == suffix
end

local function unpack_archive(cfg, item, archive, work)
  local out_bin = work .. "/" .. cfg.binary
  local rc, out
  if item.name:match("%.tar%.gz$") then
    -- Release tarballs also bundle LICENSE/README (and, for some engines,
    -- geo databases) that this installer never uses. List the archive and
    -- extract ONLY the binary member instead of the whole archive, so that
    -- extra content is never written to /tmp (which may be a small
    -- RAM-backed tmpfs on constrained routers) just to be deleted a moment
    -- later.
    local listing = command_output("tar tzf " .. shellescape(archive))
    local member = nil
    for line in (listing .. "\n"):gmatch("([^\n]*)\n") do
      if line ~= "" and (line == cfg.binary or ends_with(line, "/" .. cfg.binary)) then
        member = line
        break
      end
    end
    if not member then return nil, "binary not found in archive" end
    rc, out = exec_capture("tar xzf " .. shellescape(archive) .. " -C " .. shellescape(work) .. " " .. shellescape(member))
    if rc ~= 0 then return nil, out end
    local found = work .. "/" .. member
    if not file_exists(found) then return nil, "binary not found in archive" end
    return found
  elseif item.name:match("%.gz$") then
    rc, out = exec_capture("gzip -dc " .. shellescape(archive) .. " > " .. shellescape(out_bin) .. " && chmod 0755 " .. shellescape(out_bin))
    if rc ~= 0 then return nil, out end
    return out_bin
  end
  return nil, "unsupported archive format"
end

local function replace_binary(cfg, bin, unpacked, old_version)
  local backup_dir = cfg.backup_dir or ("/tmp/tproxy-manager-" .. tostring(cfg.name or "core") .. "-backup")
  local backup_file = cfg.backup_file or (backup_dir .. "/" .. tostring(cfg.binary or "binary") .. ".previous")
  local backup_meta = cfg.backup_meta or (backup_file .. ".version")
  local bin_dir = bin:match("^(.*)/[^/]+$") or "/usr/bin"
  local needed_kb = file_size_kb(unpacked)
  local current_kb = file_size_kb(bin)
  local available_kb = fs_available_kb(bin_dir)
  local reserve_kb = tonumber(cfg.install_reserve_kb or 1024) or 1024

  if needed_kb > 0 and (available_kb + current_kb) < (needed_kb + reserve_kb) then
    return false, string.format(
      "not enough overlay space: need %d KB, available after removing old binary %d KB",
      needed_kb + reserve_kb,
      available_kb + current_kb
    )
  end

  -- Refuse rather than write the rollback copy into a directory that is not
  -- exclusively root's: the whole point of the store is that rollback can trust
  -- what it finds there.
  if not ensure_private_dir(backup_dir) then
    return false, "refusing to install: " .. backup_dir ..
      " is not a directory only root can write to"
  end
  ensure_dir(bin_dir)
  remove_path(backup_file)
  remove_path(backup_meta)

  local have_old = file_exists(bin)
  if have_old then
    local rc, out = exec_capture("cp " .. shellescape(bin) .. " " .. shellescape(backup_file) ..
      " && chmod 0755 " .. shellescape(backup_file))
    if rc ~= 0 then return false, "unable to create temporary backup: " .. out end
    write_file(backup_meta, old_version or "")
  end

  -- Avoid keeping two large binaries in overlay. The rollback copy is in /tmp.
  -- Known trade-off: this makes the swap non-atomic — the old binary is gone
  -- before the new one is fully in place, so a crash/power loss in this exact
  -- window leaves the router with no engine binary at all (recoverable by
  -- re-running install, or manually restoring backup_file if it survived).
  -- We accept this risk deliberately to keep flash usage low on routers with
  -- very little free overlay space; do not "fix" it by holding both copies
  -- on the main partition at once.
  if have_old then remove_path(bin) end

  local rc, out = exec_capture("cp " .. shellescape(unpacked) .. " " .. shellescape(bin) ..
    " && chmod 0755 " .. shellescape(bin))
  if rc ~= 0 then
    remove_path(bin)
    if have_old then
      exec_capture("cp " .. shellescape(backup_file) .. " " .. shellescape(bin) ..
        " && chmod 0755 " .. shellescape(bin))
    end
    return false, "unable to install binary: " .. out
  end

  local new_version, new_raw = current_version(cfg, bin)
  if new_version == "" then
    remove_path(bin)
    if have_old then
      exec_capture("cp " .. shellescape(backup_file) .. " " .. shellescape(bin) ..
        " && chmod 0755 " .. shellescape(bin))
    else
      remove_path(bin)
    end
    return false, "installed binary is not executable on this system: " .. tostring(new_raw)
  end

  return true, new_version
end

local function print_kv(k, v)
  print(tostring(k) .. "=" .. tostring(v or ""))
end

function M.status(cfg, force)
  local bin = detect_bin(cfg)
  local cur_version, raw_version = current_version(cfg, bin)
  local items, err = items_with_asset(cfg, force)
  local latest = items and latest_stable(items) or nil
  local latest_version = latest and version_string(latest.tag) or ""
  local cmp = latest_version ~= "" and cur_version ~= "" and compare_versions(cur_version, latest_version) or nil
  local status, color = "unknown", "gray"
  if cmp == 0 then status, color = "latest", "green"
  elseif cmp and cmp < 0 then status, color = "older", "blue"
  elseif cmp and cmp > 0 then status, color = "newer", "orange" end
  print_kv("BIN", bin)
  print_kv("CURRENT_VERSION", cur_version)
  print_kv("CURRENT_VERSION_RAW", raw_version:gsub("\n", " | "))
  print_kv("ARCH", command_output("uname -m"))
  print_kv("ASSET", latest and latest.name or cfg.asset_name("", command_output("uname -m")))
  print_kv("LATEST_TAG", latest and latest.tag or "")
  print_kv("LATEST_VERSION", latest_version)
  print_kv("STATUS", status)
  print_kv("STATUS_COLOR", color)
  print_kv("BACKUP_FILE", file_exists(cfg.backup_file) and cfg.backup_file or "")
  print_kv("BACKUP_VERSION", trim(read_file(cfg.backup_meta)))
  if err then print_kv("ERROR", err) end
end

function M.list(cfg, force)
  local items, err = items_with_asset(cfg, force)
  if not items then io.stderr:write(tostring(err) .. "\n"); os.exit(1) end
  for _, item in ipairs(items) do
    print(table.concat({ item.tag, item.published_at, item.prerelease and "1" or "0", item.name }, "\t"))
  end
end

function M.install(cfg, tag)
  local items, err = items_with_asset(cfg, true)
  if not items then return false, err end
  local item = find_release(items, tag)
  if not item then return false, "release or architecture asset not found: " .. tostring(tag) end
  local work = trim(command_output("mktemp -d /tmp/tproxy-manager-" .. cfg.name .. ".XXXXXX"))
  if work == "" then return false, "unable to create temporary directory" end
  local archive = work .. "/" .. item.name
  local ok, msg = download_file(item.url, archive)
  if not ok then remove_path(work); return false, msg end
  ok, msg = verify_digest(item, archive)
  if not ok then remove_path(work); return false, msg end
  local unpacked, unpack_err = unpack_archive(cfg, item, archive, work)
  if not unpacked then remove_path(work); return false, unpack_err end
  local unpacked_version, unpacked_raw = current_version(cfg, unpacked)
  if unpacked_version == "" then
    remove_path(work)
    return false, "downloaded binary is not executable on this system: " .. tostring(unpacked_raw)
  end

  local bin = detect_bin(cfg)
  local old_version = current_version(cfg, bin)
  local replaced, replace_msg = replace_binary(cfg, bin, unpacked, old_version)
  if not replaced then
    remove_path(work)
    return false, replace_msg
  end
  local new_version = replace_msg
  remove_path(work)
  if cfg.restart_service then exec_ok(cfg.restart_service .. " >/dev/null 2>&1") end
  return true, "installed " .. item.tag .. " (" .. tostring(new_version) .. ")"
end

function M.rollback(cfg)
  if not file_exists(cfg.backup_file) then return false, "backup is not available" end
  -- This copies a binary from /tmp over the live engine and restarts it as root,
  -- so the store has to be verified before it is believed. Both checks matter:
  -- the directory, because a writable one lets anybody swap the file underneath
  -- us, and the file, because it is what actually gets installed. Nothing is
  -- deleted or recreated here — a store that fails the check is left alone and
  -- the rollback simply refuses, so a tampered store is reported rather than
  -- quietly replaced (and an untampered one is never destroyed).
  local store = cfg.backup_dir or "/tmp"
  if not root_only(store, "d") then
    return false, "refusing to roll back: " .. store ..
      " is not a directory only root can write to"
  end
  if not trusted_file(cfg.backup_file) then
    return false, "refusing to roll back: " .. tostring(cfg.backup_file) ..
      " is not a regular file owned by root only"
  end
  local bin = detect_bin(cfg)
  local swap = store .. "/" .. tostring(cfg.binary or "binary") .. ".current." .. tostring(os.time())
  if file_exists(bin) then
    local rc, out = exec_capture("cp " .. shellescape(bin) .. " " .. shellescape(swap) ..
      " && chmod 0755 " .. shellescape(swap))
    if rc ~= 0 then return false, "unable to prepare rollback swap: " .. out end
    remove_path(bin)
  end
  local rc, out = exec_capture("cp " .. shellescape(cfg.backup_file) .. " " .. shellescape(bin) ..
    " && chmod 0755 " .. shellescape(bin))
  if rc ~= 0 then
    if file_exists(swap) then
      exec_capture("cp " .. shellescape(swap) .. " " .. shellescape(bin) ..
        " && chmod 0755 " .. shellescape(bin))
    end
    remove_path(swap)
    return false, "unable to restore backup"
  end
  if file_exists(swap) then
    remove_path(cfg.backup_file)
    exec_ok("mv " .. shellescape(swap) .. " " .. shellescape(cfg.backup_file))
    local cur_version = current_version(cfg, cfg.backup_file)
    write_file(cfg.backup_meta, cur_version or "")
  end
  if cfg.restart_service then exec_ok(cfg.restart_service .. " >/dev/null 2>&1") end
  return true, "rollback completed"
end

function M.dispatch(cfg, argv)
  local mode = argv and argv[1] or "status"
  if mode == "status" then M.status(cfg, argv and argv[2] == "--refresh")
  elseif mode == "list" then M.list(cfg, argv and argv[2] == "--refresh")
  elseif mode == "install" then
    local tag = trim(argv and argv[2])
    if tag == "" then io.stderr:write("install requires release tag\n"); os.exit(1) end
    local ok, msg = M.install(cfg, tag)
    if ok then print(msg) else io.stderr:write(tostring(msg) .. "\n"); os.exit(1) end
  elseif mode == "rollback" then
    local ok, msg = M.rollback(cfg)
    if ok then print(msg) else io.stderr:write(tostring(msg) .. "\n"); os.exit(1) end
  else
    io.stderr:write("usage: status|list|install <tag>|rollback\n")
    os.exit(1)
  end
end

M.version_string = version_string

-- Exported for tests/engine-cache-store.lua. These two decide whether root
-- deletes a directory tree, so the suite checks them directly instead of
-- inferring the decision from behaviour further up.
M._owned_path_ok = owned_path_ok
M._resolve_cache = resolve_cache
M._ensure_private_dir = ensure_private_dir

return M
