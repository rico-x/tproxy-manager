local jsonc = require "luci.jsonc"

local M = {}

local function trim(value)
  return tostring(value or ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
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

local function write_file(path, data)
  local fh = assert(io.open(path, "wb"))
  fh:write(data or "")
  fh:close()
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

local function remove_path(path)
  return exec_ok("rm -rf " .. shellescape(path) .. " >/dev/null 2>&1")
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

local function fetch_releases(cfg, force)
  local raw = read_file(cfg.cache_file)
  if raw ~= "" and not force then return raw end
  local cmd = "curl -fsSL --connect-timeout 8 --max-time 25 -H " ..
    shellescape("Accept: application/vnd.github+json") .. " " .. shellescape(cfg.api_url)
  local rc, out = exec_capture(cmd)
  if rc == 0 and out:match("^%[") then
    write_file(cfg.cache_file, out)
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

  ensure_dir(backup_dir)
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
  if not ok then exec_ok("rm -rf " .. shellescape(work)); return false, msg end
  ok, msg = verify_digest(item, archive)
  if not ok then exec_ok("rm -rf " .. shellescape(work)); return false, msg end
  local unpacked, unpack_err = unpack_archive(cfg, item, archive, work)
  if not unpacked then exec_ok("rm -rf " .. shellescape(work)); return false, unpack_err end
  local unpacked_version, unpacked_raw = current_version(cfg, unpacked)
  if unpacked_version == "" then
    exec_ok("rm -rf " .. shellescape(work))
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
  local bin = detect_bin(cfg)
  local swap = (cfg.backup_dir or "/tmp") .. "/" .. tostring(cfg.binary or "binary") .. ".current." .. tostring(os.time())
  ensure_dir(cfg.backup_dir or "/tmp")
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

return M
