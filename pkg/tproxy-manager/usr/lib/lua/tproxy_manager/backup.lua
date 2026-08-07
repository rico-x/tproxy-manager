-- backup.lua: export/import of tproxy-manager settings as a single archive.
--
-- Pure data/logic module: no HTTP, no HTML. The LuCI controller/CBI layer
-- (luci/controller/tproxy_manager.lua and modules/tproxy.lua) drive this
-- module and handle the request/response and rendering side.
--
-- Archive layout (tar.gz):
--   manifest.json   -- schema_version, package_version, created_at, files[]
--   uci.json        -- flat key/value map of tproxy-manager.main.*
--   files/<path>    -- mirrored absolute paths, leading "/" stripped
--
-- Import is a two-step flow: extract_pending() unpacks the upload into a
-- token-named staging directory under /tmp and returns a diff; apply()/
-- cancel() act on that same token later. Nothing is touched on disk outside
-- /tmp until apply() is explicitly called.

local fs    = require "nixio.fs"
local sys   = require "luci.sys"
local jsonc = require "luci.jsonc"
local ucim  = require "luci.model.uci"
local utils = require "luci.model.cbi.tproxy_manager.utils"

local M = {}

local PKG      = "tproxy-manager"
local BASE_DIR = "/etc/tproxy-manager"

local XRAY_DIR    = "/etc/xray"
local MIHOMO_DIR  = "/etc/mihomo"
local SINGBOX_DIR = "/etc/sing-box"

local GEO_CFG   = BASE_DIR .. "/geo-sources.conf"
local CRON_FILE = "/etc/crontabs/root"
local CRON_TAG  = "# tproxy-manager-geo-update"

-- Must stay in sync with the `defaults` table in modules/tproxy.lua: these
-- are the fallback paths used when the corresponding UCI option is unset.
local CORE_FILE_DEFAULTS = {
  ports_file          = BASE_DIR .. "/tproxy-manager.ports",
  bypass_v4_file      = BASE_DIR .. "/tproxy-manager.v4",
  bypass_v6_file      = BASE_DIR .. "/tproxy-manager.v6",
  src_only_v4_file    = BASE_DIR .. "/tproxy-manager.src4.only",
  src_only_v6_file    = BASE_DIR .. "/tproxy-manager.src6.only",
  src_bypass_v4_file  = BASE_DIR .. "/tproxy-manager.src4.bypass",
  src_bypass_v6_file  = BASE_DIR .. "/tproxy-manager.src6.bypass",
}

local DEFAULT_LINKS_FILE = BASE_DIR .. "/watchdog.links"
local DEFAULT_SHARE_FILE = BASE_DIR .. "/watchdog-share.json"
local DEFAULT_SUBS_FILE  = BASE_DIR .. "/watchdog-subscriptions.json"

M.SCHEMA_VERSION = 1
M.MODULE_ORDER   = { "core", "xray", "mihomo", "singbox", "watchdog", "geo" }

-- A line-diff on files bigger than this is skipped (only a size summary is
-- shown) to keep the O(n*m) LCS computation bounded on router-class CPUs.
local MAX_DIFF_LINES = 800

local PENDING_ROOT   = "/tmp"
local PENDING_PREFIX = "tproxy-manager-backup-pending-"
local PENDING_TTL    = 20 * 60 -- seconds; stale pending imports are swept opportunistically

--------------------------------------------------------------------------
-- small helpers
--------------------------------------------------------------------------

local function trim(s) return utils.trim(s) end

local function file_exists(path)
  local st = fs.stat(path)
  return st ~= nil and st.type == "reg"
end

local function read_file(path)
  return fs.readfile(path) or ""
end

-- math.random(0, 0xffffffff) throws "integer expected, got number" on this
-- router's Lua runtime for values above 2^31-1, so build the token out of
-- the same range already proven safe elsewhere in this codebase (see
-- utils.lua's atomic_write / happ_decrypt.lua's write_file temp names).
local function random_token()
  return string.format("%x%x%x", math.random(1, 10 ^ 9), math.random(1, 10 ^ 9), os.time())
end

local function module_of_key(key)
  if key:match("^xray_profile_") then return "xray" end
  if key:match("^mihomo_profile_") then return "mihomo" end
  if key:match("^singbox_profile_") then return "singbox" end
  if key:match("^watchdog_") then return "watchdog" end
  return "core"
end

-- Strip a leading "/" so the value is safe to use as a tar member path
-- (files/<relpath>) and to rejoin with "/" .. relpath on the way back out.
local function rel_path(abs_path)
  return (abs_path:gsub("^/+", ""))
end

-- nixio.fs.dir() returns an iterator function (for name in fs.dir(dir) do),
-- not a table - matches the list_json/list_yaml helpers in the engine tabs.
local function list_dir_matching(dir, suffix)
  local out = {}
  local it = fs.dir(dir)
  if it then
    for name in it do
      if name:sub(- #suffix) == suffix then
        out[#out + 1] = dir .. "/" .. name
      end
    end
  end
  table.sort(out)
  return out
end

--------------------------------------------------------------------------
-- collecting current live state
--------------------------------------------------------------------------

-- Flat key/value map of tproxy-manager.main.* (the package only ever uses
-- this one section; see manage.lua). Every option here is a scalar string.
function M.collect_uci(uci)
  uci = uci or ucim.cursor()
  local out = {}
  local sec = uci:get_all(PKG, "main")
  if type(sec) == "table" then
    for k, v in pairs(sec) do
      if type(k) == "string" and k:sub(1, 1) ~= "." and type(v) ~= "table" then
        out[k] = tostring(v)
      end
    end
  end
  return out
end

local function core_file_path(uci_map, key)
  local v = trim(uci_map[key] or "")
  if v ~= "" then return v end
  return CORE_FILE_DEFAULTS[key] or ""
end

-- List every file this feature knows how to back up, tagged with the
-- module it belongs to. Paths for the 7 TPROXY list-files and the two
-- watchdog files are resolved from the current live UCI config, not
-- hardcoded, so a router with custom paths is still backed up correctly.
function M.list_files(uci_map)
  local out = {}
  local function add(module_id, path)
    if path and path ~= "" then
      out[#out + 1] = { module = module_id, path = path }
    end
  end

  for key in pairs(CORE_FILE_DEFAULTS) do
    add("core", core_file_path(uci_map, key))
  end

  for _, p in ipairs(list_dir_matching(XRAY_DIR, ".json")) do add("xray", p) end
  for _, p in ipairs(list_dir_matching(MIHOMO_DIR, ".yaml")) do add("mihomo", p) end
  for _, p in ipairs(list_dir_matching(SINGBOX_DIR, ".json")) do add("singbox", p) end

  local links_file = trim(uci_map.watchdog_links_file or "")
  if links_file == "" then links_file = DEFAULT_LINKS_FILE end
  add("watchdog", links_file)

  local share_file = trim(uci_map.watchdog_share_file or "")
  if share_file == "" then share_file = DEFAULT_SHARE_FILE end
  add("watchdog", share_file)

  add("watchdog", DEFAULT_SUBS_FILE)

  add("geo", GEO_CFG)

  return out
end

local function geo_cron_line()
  local body = read_file(CRON_FILE)
  for line in (body .. "\n"):gmatch("([^\n]*)\n") do
    if line:find(CRON_TAG, 1, true) then return line end
  end
  return ""
end

--------------------------------------------------------------------------
-- export
--------------------------------------------------------------------------

local function package_version()
  local out = sys.exec("apk info -v " .. utils.shellescape(PKG) .. " 2>/dev/null") or ""
  out = trim(out)
  if out == "" then return "unknown" end
  return out
end

-- Builds the archive in /tmp and returns its path. Caller is responsible
-- for streaming and then removing it.
function M.export()
  local uci_map = M.collect_uci()
  local files = M.list_files(uci_map)

  local stage = string.format("%s/tproxy-manager-backup-export-%s", PENDING_ROOT, random_token())
  utils.ensure_dir(stage .. "/files")

  local manifest_files = {}
  for _, entry in ipairs(files) do
    if file_exists(entry.path) then
      local dest = stage .. "/files/" .. rel_path(entry.path)
      utils.ensure_dir(dest:match("^(.*)/[^/]+$") or stage)
      sys.call("cp -f " .. utils.shellescape(entry.path) .. " " .. utils.shellescape(dest) .. " >/dev/null 2>&1")
      manifest_files[#manifest_files + 1] = { module = entry.module, path = rel_path(entry.path) }
    end
  end

  local cron_line = geo_cron_line()
  if cron_line ~= "" then
    utils.ensure_dir(stage .. "/files/etc/tproxy-manager")
    fs.writefile(stage .. "/files/etc/tproxy-manager/.geo-cron-line", cron_line)
    manifest_files[#manifest_files + 1] = { module = "geo", path = "etc/tproxy-manager/.geo-cron-line" }
  end

  fs.writefile(stage .. "/uci.json", jsonc.stringify(uci_map, true))
  fs.writefile(stage .. "/manifest.json", jsonc.stringify({
    schema_version  = M.SCHEMA_VERSION,
    package_version = package_version(),
    created_at      = os.time(),
    files           = manifest_files,
  }, true))

  local archive = string.format("%s/tproxy-manager-backup-%d.tar.gz", PENDING_ROOT, os.time())
  local rc = sys.call("tar czf " .. utils.shellescape(archive) ..
    " -C " .. utils.shellescape(stage) .. " manifest.json uci.json files 2>/dev/null")
  sys.call("rm -rf " .. utils.shellescape(stage) .. " >/dev/null 2>&1")

  if rc ~= 0 or not file_exists(archive) then
    return nil, "failed to build the backup archive"
  end
  return archive
end

--------------------------------------------------------------------------
-- import: stage 1 - extract + validate + build diff
--------------------------------------------------------------------------

local function pending_dir(token)
  return string.format("%s/%s%s", PENDING_ROOT, PENDING_PREFIX, token)
end

-- Only allow member names we ourselves produce: manifest.json, uci.json, or
-- files/<safe path> - never an absolute path or a ".." segment. This is the
-- only thing standing between an uploaded archive and writing outside the
-- pending directory, so it is intentionally strict (allowlist, not denylist).
local function safe_member(name)
  if name == "manifest.json" or name == "uci.json" then return true end
  if not name:match("^files/") then return false end
  if name:match("^/") then return false end
  for seg in (name .. "/"):gmatch("([^/]*)/") do
    if seg == ".." then return false end
  end
  return true
end

-- Removes pending import directories older than PENDING_TTL. Called
-- opportunistically (on upload and whenever the Backup section renders)
-- since the package has no general-purpose cron/timer of its own besides
-- the GEO updater.
function M.cleanup_stale()
  local now = os.time()
  local it = fs.dir(PENDING_ROOT)
  if not it then return end
  for name in it do
    if name:sub(1, #PENDING_PREFIX) == PENDING_PREFIX then
      local path = PENDING_ROOT .. "/" .. name
      local st = fs.stat(path)
      if st and st.type == "directory" and st.mtime and (now - st.mtime) > PENDING_TTL then
        sys.call("rm -rf " .. utils.shellescape(path) .. " >/dev/null 2>&1")
      end
    end
  end
end

-- upload_path: a file already fully written to disk (by the controller's
-- own setfilehandler), safe to read/move from. Returns token on success.
function M.extract_pending(upload_path)
  M.cleanup_stale()

  if not file_exists(upload_path) then
    return nil, "upload is missing"
  end

  local listing = sys.exec("tar tzf " .. utils.shellescape(upload_path) .. " 2>/dev/null") or ""
  if trim(listing) == "" then
    return nil, "not a valid backup archive"
  end
  local members = {}
  for line in (listing .. "\n"):gmatch("([^\n]*)\n") do
    line = trim(line)
    if line ~= "" then
      if not safe_member(line) then
        return nil, "backup archive contains an unsafe path: " .. line
      end
      members[#members + 1] = line
    end
  end
  if #members == 0 then
    return nil, "backup archive is empty"
  end

  local token = random_token()
  local dir = pending_dir(token)
  utils.ensure_dir(dir)

  local rc = sys.call("tar xzf " .. utils.shellescape(upload_path) ..
    " -C " .. utils.shellescape(dir) .. " >/dev/null 2>&1")
  if rc ~= 0 then
    sys.call("rm -rf " .. utils.shellescape(dir) .. " >/dev/null 2>&1")
    return nil, "failed to extract backup archive"
  end

  local manifest_raw = read_file(dir .. "/manifest.json")
  local ok, manifest = pcall(jsonc.parse, manifest_raw)
  if not ok or type(manifest) ~= "table" then
    sys.call("rm -rf " .. utils.shellescape(dir) .. " >/dev/null 2>&1")
    return nil, "backup archive is missing a valid manifest.json"
  end
  if tonumber(manifest.schema_version) ~= M.SCHEMA_VERSION then
    sys.call("rm -rf " .. utils.shellescape(dir) .. " >/dev/null 2>&1")
    return nil, "unsupported backup format version"
  end

  return token, nil, manifest
end

function M.cancel(token)
  if not token or not token:match("^[0-9a-f]+$") then return false end
  sys.call("rm -rf " .. utils.shellescape(pending_dir(token)) .. " >/dev/null 2>&1")
  return true
end

--------------------------------------------------------------------------
-- line diff (pure-Lua LCS; no `diff` binary is available in this router's
-- busybox build, confirmed on-device before writing this)
--------------------------------------------------------------------------

local function split_lines(text)
  local lines = {}
  if text == "" then return lines end
  for line in (text .. "\n"):gmatch("([^\n]*)\n") do
    lines[#lines + 1] = line
  end
  return lines
end

-- Returns a list of {tag="same"/"add"/"del", text=...}, or nil if either
-- side exceeds MAX_DIFF_LINES (caller falls back to a size-only summary).
local function line_diff(old_text, new_text)
  local old_lines, new_lines = split_lines(old_text), split_lines(new_text)
  local n, m = #old_lines, #new_lines
  if n > MAX_DIFF_LINES or m > MAX_DIFF_LINES then
    return nil, n, m
  end

  local dp = {}
  for i = 0, n do dp[i] = {} end
  for j = 0, m do dp[n][j] = 0 end
  for i = 0, n do dp[i][m] = 0 end
  for i = n - 1, 0, -1 do
    for j = m - 1, 0, -1 do
      if old_lines[i + 1] == new_lines[j + 1] then
        dp[i][j] = dp[i + 1][j + 1] + 1
      else
        local a, b = dp[i + 1][j], dp[i][j + 1]
        dp[i][j] = (a > b) and a or b
      end
    end
  end

  local out = {}
  local i, j = 0, 0
  while i < n and j < m do
    if old_lines[i + 1] == new_lines[j + 1] then
      out[#out + 1] = { tag = "same", text = old_lines[i + 1] }
      i, j = i + 1, j + 1
    elseif dp[i + 1][j] >= dp[i][j + 1] then
      out[#out + 1] = { tag = "del", text = old_lines[i + 1] }
      i = i + 1
    else
      out[#out + 1] = { tag = "add", text = new_lines[j + 1] }
      j = j + 1
    end
  end
  while i < n do out[#out + 1] = { tag = "del", text = old_lines[i + 1] }; i = i + 1 end
  while j < m do out[#out + 1] = { tag = "add", text = new_lines[j + 1] }; j = j + 1 end
  return out
end

--------------------------------------------------------------------------
-- import: stage 2 - build the diff (current live state vs pending)
--------------------------------------------------------------------------

-- diff.modules[id] = { uci = {changed={}, added={}, removed={}}, files = { {path,status,diff|old_lines|new_lines} } }
-- diff.touched[id] = true for any module with at least one change.
function M.diff(token)
  local dir = pending_dir(token)
  local manifest_raw = read_file(dir .. "/manifest.json")
  local ok, manifest = pcall(jsonc.parse, manifest_raw)
  if not ok or type(manifest) ~= "table" then
    return nil, "pending import not found or expired"
  end

  local current_uci = M.collect_uci()
  local ok2, backup_uci = pcall(jsonc.parse, read_file(dir .. "/uci.json"))
  if not ok2 or type(backup_uci) ~= "table" then backup_uci = {} end

  local modules = {}
  local touched = {}
  for _, id in ipairs(M.MODULE_ORDER) do
    modules[id] = { uci = { changed = {}, added = {}, removed = {} }, files = {} }
  end

  local seen_keys = {}
  for k, v in pairs(current_uci) do
    seen_keys[k] = true
    local id = module_of_key(k)
    local nv = backup_uci[k]
    if nv == nil then
      modules[id].uci.removed[#modules[id].uci.removed + 1] = { key = k, old = v }
      touched[id] = true
    elseif tostring(nv) ~= tostring(v) then
      modules[id].uci.changed[#modules[id].uci.changed + 1] = { key = k, old = v, new = tostring(nv) }
      touched[id] = true
    end
  end
  for k, v in pairs(backup_uci) do
    if not seen_keys[k] then
      local id = module_of_key(k)
      modules[id].uci.added[#modules[id].uci.added + 1] = { key = k, new = tostring(v) }
      touched[id] = true
    end
  end

  for _, entry in ipairs(manifest.files or {}) do
    local id = entry.module or "core"
    local rel = entry.path
    -- The synthetic cron-line file is displayed under its own pseudo path.
    local live_path = "/" .. rel
    local display_path = live_path
    if rel == "etc/tproxy-manager/.geo-cron-line" then
      display_path = "GEO update schedule (cron)"
      live_path = CRON_FILE -- read below via a dedicated branch, not directly
    end

    local backup_content = read_file(dir .. "/files/" .. rel)
    local current_content
    if rel == "etc/tproxy-manager/.geo-cron-line" then
      current_content = geo_cron_line()
    else
      current_content = file_exists(live_path) and read_file(live_path) or nil
    end

    if current_content == nil then
      modules[id].files[#modules[id].files + 1] = { path = display_path, status = "added" }
      touched[id] = true
    elseif current_content ~= backup_content then
      local diff, old_n, new_n = line_diff(current_content, backup_content)
      modules[id].files[#modules[id].files + 1] = {
        path = display_path, status = "changed", diff = diff, old_lines = old_n, new_lines = new_n,
      }
      touched[id] = true
    end
  end

  -- Files that exist now but are absent from the backup (module downgrade,
  -- or a file deleted after the backup was made) show as "removed".
  local current_files = M.list_files(current_uci)
  local in_manifest = {}
  for _, entry in ipairs(manifest.files or {}) do in_manifest[entry.path] = true end
  for _, entry in ipairs(current_files) do
    local rel = rel_path(entry.path)
    if not in_manifest[rel] and file_exists(entry.path) then
      modules[entry.module].files[#modules[entry.module].files + 1] = {
        path = entry.path, status = "removed",
      }
      touched[entry.module] = true
    end
  end

  return {
    manifest = manifest,
    modules  = modules,
    touched  = touched,
    order    = M.MODULE_ORDER,
  }
end

--------------------------------------------------------------------------
-- import: stage 3 - apply or cancel
--------------------------------------------------------------------------

-- Copies a pending file into place. The pending dir lives on tmpfs (/tmp)
-- while most targets live on the overlay (/etc) - a different filesystem,
-- so a plain rename(2) always fails with EXDEV there. To keep the final
-- swap atomic on the TARGET filesystem, the pending file is first copied
-- into a same-directory temp name next to the real target, then promoted
-- with utils.promote_file (which already handles this router's ESTALE
-- quirk via sync+retry, with an mv fallback for anything else).
local function restore_file(src, dest)
  local dest_dir = dest:match("^(.*)/[^/]+$") or "/"
  utils.ensure_dir(dest_dir)
  local tmp = string.format("%s/.%s.import.%d.tmp", dest_dir, dest:match("([^/]+)$") or "tmp", math.random(1, 10 ^ 9))
  if sys.call("cp -f " .. utils.shellescape(src) .. " " .. utils.shellescape(tmp) .. " >/dev/null 2>&1") ~= 0 then
    return false
  end
  local ok = utils.promote_file(tmp, dest)
  if not ok then fs.remove(tmp) end
  return ok
end

-- Small helper used only by the cron-line restore branch in M.apply: writes
-- text to a temp file next to `path` and promotes it, same as restore_file
-- but starting from an in-memory string instead of an existing file.
local function restore_file_from_text(path, text)
  local dir = path:match("^(.*)/[^/]+$") or "/"
  utils.ensure_dir(dir)
  local tmp = string.format("%s/.%s.import.%d.tmp", dir, path:match("([^/]+)$") or "tmp", math.random(1, 10 ^ 9))
  fs.writefile(tmp, text)
  local ok = utils.promote_file(tmp, path)
  if not ok then fs.remove(tmp) end
  return ok
end

-- Applies a previously-diffed pending import. Returns (true, touched) where
-- touched is the same {module_id=true,...} table diff() would produce, so
-- the caller (tproxy.lua) knows which services need restarting.
function M.apply(token)
  local diff, err = M.diff(token)
  if not diff then return false, err end

  local dir = pending_dir(token)
  local uci = ucim.cursor()

  local ok2, backup_uci = pcall(jsonc.parse, read_file(dir .. "/uci.json"))
  if ok2 and type(backup_uci) == "table" then
    local current = M.collect_uci(uci)
    for k in pairs(current) do
      if backup_uci[k] == nil then uci:delete(PKG, "main", k) end
    end
    for k, v in pairs(backup_uci) do
      uci:set(PKG, "main", k, tostring(v))
    end
    uci:commit(PKG)
  end

  for _, entry in ipairs(diff.manifest.files or {}) do
    local rel = entry.path
    if rel == "etc/tproxy-manager/.geo-cron-line" then
      local body = read_file(CRON_FILE)
      local new_line = trim(read_file(dir .. "/files/" .. rel))
      local kept = {}
      for line in (body .. "\n"):gmatch("([^\n]*)\n") do
        if not line:find(CRON_TAG, 1, true) and line ~= "" then kept[#kept + 1] = line end
      end
      if new_line ~= "" then kept[#kept + 1] = new_line end
      restore_file_from_text(CRON_FILE, table.concat(kept, "\n") .. (#kept > 0 and "\n" or ""))
    else
      restore_file(dir .. "/files/" .. rel, "/" .. rel)
    end
  end

  M.cancel(token)
  return true, diff.touched
end

return M
