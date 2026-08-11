#!/usr/bin/lua

local jsonc = require "luci.jsonc"

local API_URL = "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=20"
-- The cache lives inside a root-only directory rather than directly in
-- world-writable /tmp: it supplies the download URL that install() hands to
-- curl, so whoever can write it decides which binary root installs.
local CACHE_DIR = "/tmp/tproxy-manager-xray-cache"
local CACHE_FILE = CACHE_DIR .. "/releases.json"
local LEGACY_CACHE_FILE = "/tmp/tproxy-manager-xray-releases.json"
local BACKUP_DIR = "/tmp/tproxy-manager-xray-backup"
local BACKUP_FILE = BACKUP_DIR .. "/xray.previous"
local BACKUP_META = BACKUP_DIR .. "/xray.previous.version"
local MIN_HY2_VERSION = "26.3.27"

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
  local rc = ok and 0 or tonumber(code) or 1
  return rc, trim(out)
end

local function exec_ok(cmd)
  local rc = os.execute(cmd)
  return rc == true or rc == 0
end

local function file_exists(path)
  local fh = io.open(path, "rb")
  if fh then fh:close(); return true end
  return false
end

local function ensure_dir(path)
  return exec_ok("mkdir -p " .. shellescape(path) .. " >/dev/null 2>&1")
end

-- Paths this script must never delete or claim ownership of. ensure_private_dir()
-- WIPES what it cannot trust, and a shared root can never pass the "root-only"
-- test — /tmp is mode 1777 by definition — so a path resolved to one by accident
-- would have had root run `rm -rf /tmp`. An explicit refusal list plus a minimum
-- depth, so the shallowest thing that can ever be touched is a NAMED CHILD of a
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
  if path:find("/%.%.?/") or path:match("/%.%.?$") then return false end
  local depth = 0
  for _ in path:gmatch("[^/]+") do depth = depth + 1 end
  return depth >= 2
end

local function remove_path(path)
  -- Refuses rather than deletes.
  if not owned_path_ok(path) then return false end
  return exec_ok("rm -rf " .. shellescape(path) .. " >/dev/null 2>&1")
end

-- The rollback store and the release cache live under fixed, predictable names in
-- the world-writable /tmp, so anything already sitting at one of those paths may
-- have been planted by an unprivileged local process. `mkdir -p` would happily
-- adopt such a directory (or follow a symlink out of /tmp), root would then write
-- the previous binary inside a location that process controls, and the next
-- rollback would copy whatever it finds there over /usr/bin/xray and restart it
-- as root. So the store is inspected before it is trusted: only a real directory
-- owned by root that nobody else can write to qualifies.
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
local function ensure_private_dir(path)
  -- Screened FIRST, before anything is deleted.
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

-- Reads a file only if root alone could have written it. Anything else is
-- discarded rather than parsed.
local function read_trusted_file(path)
  if not trusted_file(path) then
    if path_facts(path) then remove_path(path) end
    return ""
  end
  return read_file(path)
end

local function command_output(cmd)
  local p = io.popen(cmd .. " 2>/dev/null")
  if not p then return "" end
  local out = trim(p:read("*a") or "")
  p:close()
  return out
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

local function detect_xray_bin()
  local env_bin = trim(os.getenv("XRAY_BIN"))
  if env_bin ~= "" then return env_bin end
  if file_exists("/usr/bin/xray") then return "/usr/bin/xray" end
  if file_exists("/usr/sbin/xray") then return "/usr/sbin/xray" end
  local found = command_output("command -v xray")
  return found ~= "" and found or "/usr/bin/xray"
end

local function uname_m()
  return command_output("uname -m")
end

local function asset_for_arch(arch)
  arch = trim(arch):lower()
  local map = {
    ["x86_64"] = "Xray-linux-64.zip",
    ["amd64"] = "Xray-linux-64.zip",
    ["i386"] = "Xray-linux-32.zip",
    ["i486"] = "Xray-linux-32.zip",
    ["i586"] = "Xray-linux-32.zip",
    ["i686"] = "Xray-linux-32.zip",
    ["aarch64"] = "Xray-linux-arm64-v8a.zip",
    ["arm64"] = "Xray-linux-arm64-v8a.zip",
    ["armv8l"] = "Xray-linux-arm64-v8a.zip",
    ["armv7l"] = "Xray-linux-arm32-v7a.zip",
    ["armv6l"] = "Xray-linux-arm32-v6.zip",
    ["armv5l"] = "Xray-linux-arm32-v5.zip",
    ["mips"] = "Xray-linux-mips32.zip",
    ["mipsel"] = "Xray-linux-mips32le.zip",
    ["mips64"] = "Xray-linux-mips64.zip",
    ["mips64el"] = "Xray-linux-mips64le.zip",
    ["riscv64"] = "Xray-linux-riscv64.zip",
    ["loongarch64"] = "Xray-linux-loong64.zip",
    ["loong64"] = "Xray-linux-loong64.zip",
  }
  return map[arch] or ""
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

local function current_version(bin)
  local rc, out = exec_capture(shellescape(bin) .. " version")
  if rc ~= 0 then return "", out end
  return version_string(out), out
end

local function fetch_releases(force)
  local store_ok = ensure_private_dir(CACHE_DIR)
  -- Earlier versions kept the cache directly in /tmp; drop that file once the
  -- private store exists.
  if store_ok then remove_path(LEGACY_CACHE_FILE) end
  local raw = store_ok and read_trusted_file(CACHE_FILE) or ""
  if raw ~= "" and not force then
    return raw
  end
  local cmd = "curl -fsSL --connect-timeout 8 --max-time 25 -H " ..
    shellescape("Accept: application/vnd.github+json") .. " " .. shellescape(API_URL)
  local rc, out = exec_capture(cmd)
  if rc == 0 and out:match("^%[") then
    -- Caching is an optimisation: if the store cannot be trusted, work from what
    -- was just fetched rather than persisting it somewhere unsafe.
    if store_ok then write_file(CACHE_FILE, out) end
    return out
  end
  if raw ~= "" then return raw end
  return nil, out ~= "" and out or "unable to fetch GitHub releases"
end

local function parse_releases(force)
  local raw, err = fetch_releases(force)
  if not raw then return nil, err end
  local ok, parsed = pcall(jsonc.parse, raw)
  if not ok or type(parsed) ~= "table" then return nil, "invalid GitHub releases response" end
  return parsed
end

local function asset_urls(release, asset_name)
  if type(release) ~= "table" or type(release.assets) ~= "table" then return nil, nil end
  local zip_url, dgst_url
  for _, asset in ipairs(release.assets) do
    if type(asset) == "table" then
      if asset.name == asset_name then zip_url = asset.browser_download_url end
      if asset.name == asset_name .. ".dgst" then dgst_url = asset.browser_download_url end
    end
  end
  return zip_url, dgst_url
end

local function releases_with_asset(asset_name, force)
  local releases, err = parse_releases(force)
  if not releases then return nil, err end
  local out = {}
  for _, release in ipairs(releases) do
    local zip_url, dgst_url = asset_urls(release, asset_name)
    if zip_url and dgst_url then
      out[#out + 1] = {
        tag = release.tag_name or "",
        name = release.name or "",
        published_at = release.published_at or "",
        prerelease = release.prerelease == true,
        zip_url = zip_url,
        dgst_url = dgst_url,
        asset = asset_name,
      }
    end
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

local function print_kv(key, value)
  print(tostring(key) .. "=" .. tostring(value or ""))
end

local function command_status(force)
  local bin = detect_xray_bin()
  local arch = uname_m()
  local asset = asset_for_arch(arch)
  local cur_version, raw_version = current_version(bin)
  local items, err = nil, nil
  if asset ~= "" then items, err = releases_with_asset(asset, force) end
  local latest = items and latest_stable(items) or nil
  local latest_version = latest and version_string(latest.tag) or ""
  local cmp = latest_version ~= "" and cur_version ~= "" and compare_versions(cur_version, latest_version) or nil
  local status, color = "unknown", "gray"
  if cmp == 0 then status, color = "latest", "green"
  elseif cmp and cmp < 0 then status, color = "older", "blue"
  elseif cmp and cmp > 0 then status, color = "newer", "orange" end
  local hy2_cmp = cur_version ~= "" and compare_versions(cur_version, MIN_HY2_VERSION) or nil

  print_kv("XRAY_BIN", bin)
  print_kv("CURRENT_VERSION", cur_version)
  print_kv("CURRENT_VERSION_RAW", raw_version:gsub("\n", " | "))
  print_kv("ARCH", arch)
  print_kv("ASSET", asset)
  print_kv("LATEST_TAG", latest and latest.tag or "")
  print_kv("LATEST_VERSION", latest_version)
  print_kv("STATUS", status)
  print_kv("STATUS_COLOR", color)
  print_kv("MIN_HY2_VERSION", MIN_HY2_VERSION)
  print_kv("HY2_SUPPORTED", (hy2_cmp and hy2_cmp >= 0) and "1" or "0")
  print_kv("BACKUP_FILE", file_exists(BACKUP_FILE) and BACKUP_FILE or "")
  print_kv("BACKUP_VERSION", trim(read_file(BACKUP_META)))
  if err then print_kv("ERROR", err) end
end

local function command_list(force)
  local asset = asset_for_arch(uname_m())
  if asset == "" then
    io.stderr:write("unsupported architecture\n")
    os.exit(1)
  end
  local items, err = releases_with_asset(asset, force)
  if not items then
    io.stderr:write(tostring(err) .. "\n")
    os.exit(1)
  end
  for _, item in ipairs(items) do
    print(table.concat({
      item.tag,
      item.published_at,
      item.prerelease and "1" or "0",
      item.asset
    }, "\t"))
  end
end

local function sha256_file(path)
  local rc, out = exec_capture("sha256sum " .. shellescape(path))
  if rc ~= 0 then return "" end
  return trim(out:match("^([0-9a-fA-F]+)") or ""):lower()
end

local function download_file(url, path)
  local cmd = "curl -fL --connect-timeout 10 --max-time 120 -o " .. shellescape(path) .. " " .. shellescape(url)
  local rc, out = exec_capture(cmd)
  return rc == 0, out
end

local function replace_xray_binary(bin, unpacked, old_version)
  local bin_dir = bin:match("^(.*)/[^/]+$") or "/usr/bin"
  local needed_kb = file_size_kb(unpacked)
  local current_kb = file_size_kb(bin)
  local available_kb = fs_available_kb(bin_dir)
  local reserve_kb = 1024

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
  if not ensure_private_dir(BACKUP_DIR) then
    return false, "refusing to install: " .. BACKUP_DIR ..
      " is not a directory only root can write to"
  end
  ensure_dir(bin_dir)
  remove_path(BACKUP_FILE)
  remove_path(BACKUP_META)

  local have_old = file_exists(bin)
  if have_old then
    local rc, out = exec_capture("cp " .. shellescape(bin) .. " " .. shellescape(BACKUP_FILE) ..
      " && chmod 0755 " .. shellescape(BACKUP_FILE))
    if rc ~= 0 then return false, "unable to create temporary backup: " .. out end
    write_file(BACKUP_META, old_version or "")
  end

  -- Keep archives, extracted binary and rollback backup in /tmp. Overlay receives
  -- only the final active binary, avoiding a second full-size copy in /usr/bin.
  -- Known trade-off: this makes the swap non-atomic — the old binary is gone
  -- before the new one is fully in place, so a crash/power loss in this exact
  -- window leaves the router with no xray binary at all (recoverable by
  -- re-running install, or manually restoring BACKUP_FILE if it survived).
  -- We accept this risk deliberately to keep flash usage low on routers with
  -- very little free overlay space; do not "fix" it by holding both copies
  -- on the main partition at once.
  if have_old then remove_path(bin) end

  local rc, out = exec_capture("cp " .. shellescape(unpacked) .. " " .. shellescape(bin) ..
    " && chmod 0755 " .. shellescape(bin))
  if rc ~= 0 then
    remove_path(bin)
    if have_old then
      exec_capture("cp " .. shellescape(BACKUP_FILE) .. " " .. shellescape(bin) ..
        " && chmod 0755 " .. shellescape(bin))
    end
    return false, "unable to install xray binary: " .. out
  end

  local new_version, new_raw = current_version(bin)
  if new_version == "" then
    remove_path(bin)
    if have_old then
      exec_capture("cp " .. shellescape(BACKUP_FILE) .. " " .. shellescape(bin) ..
        " && chmod 0755 " .. shellescape(bin))
    else
      remove_path(bin)
    end
    return false, "installed xray binary is not executable: " .. tostring(new_raw)
  end

  return true, new_version
end

local function install_release(tag)
  local arch = uname_m()
  local asset = asset_for_arch(arch)
  if asset == "" then return false, "unsupported architecture: " .. arch end
  local items, err = releases_with_asset(asset, true)
  if not items then return false, err end
  local item = find_release(items, tag)
  if not item then return false, "release or architecture asset not found: " .. tag end

  local work = trim(command_output("mktemp -d /tmp/tproxy-manager-xray.XXXXXX"))
  if work == "" then return false, "unable to create temporary directory" end
  local archive = work .. "/" .. asset
  local dgst = archive .. ".dgst"
  local ok, dl_err = download_file(item.zip_url, archive)
  if not ok then remove_path(work); return false, dl_err end
  ok, dl_err = download_file(item.dgst_url, dgst)
  if not ok then remove_path(work); return false, dl_err end

  local expected = read_file(dgst):match("SHA2%-256=%s*([0-9a-fA-F]+)")
  expected = expected and expected:lower() or ""
  local actual = sha256_file(archive)
  if expected == "" or actual == "" or expected ~= actual then
    remove_path(work)
    return false, "SHA2-256 verification failed"
  end

  -- The official Xray release zip also bundles geoip.dat/geosite.dat,
  -- README.md and LICENSE (several MB combined) that this installer never
  -- uses — GEO databases are managed separately by the "GEO обновления" tab.
  -- Extract only the "xray" member instead of the whole archive, so those
  -- files are never written to /tmp (which may be a small RAM-backed tmpfs
  -- on constrained routers) just to be deleted a moment later.
  local rc, unzip_out = exec_capture("unzip -o " .. shellescape(archive) .. " xray -d " .. shellescape(work))
  if rc ~= 0 or not file_exists(work .. "/xray") then
    remove_path(work)
    return false, unzip_out ~= "" and unzip_out or "unable to unpack xray archive"
  end

  local bin = detect_xray_bin()
  local cur_version = current_version(bin)
  local replaced, replace_msg = replace_xray_binary(bin, work .. "/xray", cur_version)
  if not replaced then
    remove_path(work)
    return false, replace_msg
  end
  local new_version = replace_msg
  remove_path(work)
  exec_ok("/etc/init.d/xray restart >/dev/null 2>&1")
  return true, "installed " .. item.tag .. " (" .. tostring(new_version) .. ")"
end

local function rollback()
  if not file_exists(BACKUP_FILE) then return false, "backup is not available" end
  -- This copies a binary from /tmp over /usr/bin/xray and restarts it as root, so
  -- the store has to be verified before it is believed. Both checks matter: the
  -- directory, because a writable one lets anybody swap the file underneath us,
  -- and the file, because it is what actually gets installed. Nothing is deleted
  -- or recreated here — a store that fails the check is left alone and the
  -- rollback simply refuses, so a tampered store is reported rather than quietly
  -- replaced (and an untampered one is never destroyed).
  if not root_only(BACKUP_DIR, "d") then
    return false, "refusing to roll back: " .. BACKUP_DIR ..
      " is not a directory only root can write to"
  end
  if not trusted_file(BACKUP_FILE) then
    return false, "refusing to roll back: " .. BACKUP_FILE ..
      " is not a regular file owned by root only"
  end
  local bin = detect_xray_bin()
  local tmp = BACKUP_DIR .. "/xray.current." .. tostring(os.time())
  if file_exists(bin) then
    local rc, out = exec_capture("cp " .. shellescape(bin) .. " " .. shellescape(tmp) ..
      " && chmod 0755 " .. shellescape(tmp))
    if rc ~= 0 then return false, "unable to prepare rollback swap: " .. out end
    remove_path(bin)
  end
  local rc, out = exec_capture("cp " .. shellescape(BACKUP_FILE) .. " " .. shellescape(bin) ..
    " && chmod 0755 " .. shellescape(bin))
  if rc ~= 0 then
    if file_exists(tmp) then
      exec_capture("cp " .. shellescape(tmp) .. " " .. shellescape(bin) ..
        " && chmod 0755 " .. shellescape(bin))
    end
    remove_path(tmp)
    return false, "unable to restore backup"
  end
  if file_exists(tmp) then
    remove_path(BACKUP_FILE)
    exec_ok("mv " .. shellescape(tmp) .. " " .. shellescape(BACKUP_FILE))
    local cur_version = current_version(BACKUP_FILE)
    write_file(BACKUP_META, cur_version or "")
  end
  exec_ok("/etc/init.d/xray restart >/dev/null 2>&1")
  return true, "rollback completed"
end

local mode = arg and arg[1] or "status"
if mode == "status" then
  command_status(arg and arg[2] == "--refresh")
elseif mode == "list" then
  command_list(arg and arg[2] == "--refresh")
elseif mode == "install" then
  local tag = trim(arg and arg[2])
  if tag == "" then io.stderr:write("install requires release tag\n"); os.exit(1) end
  local ok, msg = install_release(tag)
  if ok then print(msg) else io.stderr:write(tostring(msg) .. "\n"); os.exit(1) end
elseif mode == "rollback" then
  local ok, msg = rollback()
  if ok then print(msg) else io.stderr:write(tostring(msg) .. "\n"); os.exit(1) end
else
  io.stderr:write("usage: tproxy-manager-xray-version.lua status|list|install <tag>|rollback\n")
  os.exit(1)
end
