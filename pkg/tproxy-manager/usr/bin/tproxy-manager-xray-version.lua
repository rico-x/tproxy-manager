#!/usr/bin/lua

local jsonc = require "luci.jsonc"

local API_URL = "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=20"
local CACHE_FILE = "/tmp/tproxy-manager-xray-releases.json"
local BACKUP_DIR = "/etc/tproxy-manager/xray-backup"
local BACKUP_FILE = BACKUP_DIR .. "/xray.previous"
local BACKUP_META = BACKUP_DIR .. "/xray.previous.version"
local MIN_HY2_VERSION = "26.3.27"

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

local function command_output(cmd)
  local p = io.popen(cmd .. " 2>/dev/null")
  if not p then return "" end
  local out = trim(p:read("*a") or "")
  p:close()
  return out
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
  local raw = read_file(CACHE_FILE)
  if raw ~= "" and not force then
    return raw
  end
  local cmd = "curl -fsSL --connect-timeout 8 --max-time 25 -H " ..
    shellescape("Accept: application/vnd.github+json") .. " " .. shellescape(API_URL)
  local rc, out = exec_capture(cmd)
  if rc == 0 and out:match("^%[") then
    write_file(CACHE_FILE, out)
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
  if not ok then exec_ok("rm -rf " .. shellescape(work)); return false, dl_err end
  ok, dl_err = download_file(item.dgst_url, dgst)
  if not ok then exec_ok("rm -rf " .. shellescape(work)); return false, dl_err end

  local expected = read_file(dgst):match("SHA2%-256=%s*([0-9a-fA-F]+)")
  expected = expected and expected:lower() or ""
  local actual = sha256_file(archive)
  if expected == "" or actual == "" or expected ~= actual then
    exec_ok("rm -rf " .. shellescape(work))
    return false, "SHA2-256 verification failed"
  end

  local rc, unzip_out = exec_capture("unzip -o " .. shellescape(archive) .. " -d " .. shellescape(work))
  if rc ~= 0 or not file_exists(work .. "/xray") then
    exec_ok("rm -rf " .. shellescape(work))
    return false, unzip_out ~= "" and unzip_out or "unable to unpack xray archive"
  end

  local bin = detect_xray_bin()
  local bin_dir = bin:match("^(.*)/[^/]+$") or "/usr/bin"
  ensure_dir(BACKUP_DIR)
  ensure_dir(bin_dir)
  local cur_version = current_version(bin)
  if file_exists(bin) then
    exec_ok("cp " .. shellescape(bin) .. " " .. shellescape(BACKUP_FILE))
    write_file(BACKUP_META, cur_version or "")
  end
  local tmp_bin = bin .. ".tmp." .. tostring(os.time())
  rc, unzip_out = exec_capture("cp " .. shellescape(work .. "/xray") .. " " .. shellescape(tmp_bin) .. " && chmod 0755 " .. shellescape(tmp_bin))
  if rc ~= 0 then
    exec_ok("rm -rf " .. shellescape(work))
    return false, unzip_out
  end
  if not os.rename(tmp_bin, bin) then
    exec_ok("rm -f " .. shellescape(tmp_bin))
    exec_ok("rm -rf " .. shellescape(work))
    return false, "unable to replace xray binary"
  end
  local new_version = current_version(bin)
  exec_ok("rm -rf " .. shellescape(work))
  exec_ok("/etc/init.d/xray restart >/dev/null 2>&1")
  return true, "installed " .. item.tag .. " (" .. tostring(new_version) .. ")"
end

local function rollback()
  if not file_exists(BACKUP_FILE) then return false, "backup is not available" end
  local bin = detect_xray_bin()
  local tmp = bin .. ".rollback." .. tostring(os.time())
  if file_exists(bin) then
    exec_ok("cp " .. shellescape(bin) .. " " .. shellescape(tmp))
  end
  local ok = exec_ok("cp " .. shellescape(BACKUP_FILE) .. " " .. shellescape(bin) .. " && chmod 0755 " .. shellescape(bin))
  if not ok then
    exec_ok("rm -f " .. shellescape(tmp))
    return false, "unable to restore backup"
  end
  if file_exists(tmp) then
    exec_ok("mv " .. shellescape(tmp) .. " " .. shellescape(BACKUP_FILE))
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
