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

local GEO_CFG    = BASE_DIR .. "/geo-sources.conf"
local GEO_SCRIPT = "/usr/bin/tproxy-manager-geo-update.sh"
local CRON_FILE  = "/etc/crontabs/root"
local CRON_TAG   = "# tproxy-manager-geo-update"

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
-- Exposed so the controller's upload handler can stop writing chunks to
-- disk (and respond 413) as soon as the same limit extract_pending() would
-- reject on anyway, instead of only finding out after the whole body
-- already landed on tmpfs.
M.MAX_ARCHIVE_BYTES = 8 * 1024 * 1024

-- A line-diff on files bigger than this is skipped (only a size summary is
-- shown) to keep the O(n*m) LCS computation bounded on router-class CPUs.
local MAX_DIFF_LINES = 800

local PENDING_ROOT   = "/tmp"
local PENDING_PREFIX = "tproxy-manager-backup-pending-"
-- Must match the name the controller's upload handler builds; exported so
-- that handler cannot drift from what cleanup_stale() sweeps.
M.UPLOAD_PREFIX      = "tproxy-manager-backup-upload-"
local UPLOAD_PREFIX  = M.UPLOAD_PREFIX
local PENDING_TTL    = 20 * 60 -- seconds; stale pending imports are swept opportunistically

-- Upload size/shape limits. Checked from the tar listing BEFORE extraction
-- where possible, so a crafted small archive that would decompress into
-- something huge (a "zip bomb") is rejected without ever touching /tmp's
-- tmpfs budget with the decompressed content.
local MAX_ARCHIVE_BYTES         = M.MAX_ARCHIVE_BYTES -- compressed upload
local MAX_TOTAL_EXTRACTED_BYTES = 32 * 1024 * 1024    -- sum of all member sizes
local MAX_ITEMS                 = 256
local MAX_FILE_BYTES            = 2 * 1024 * 1024     -- any single member

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

-- UCI option names are always plain identifiers; a backup's uci.json is
-- fully attacker-controlled content, so keys and values are validated
-- before anything downstream ever calls uci:set()/uci:delete() with them.
-- Rejects (returns nil) rather than silently substituting an empty table -
-- a corrupted/malicious uci.json must never be treated as "no UCI changes",
-- since that would make M.apply() delete every current option outright.
local UCI_KEY_PATTERN = "^[A-Za-z0-9_]+$"

local function parse_uci_map(raw)
  local ok, map = pcall(jsonc.parse, raw)
  if not ok or type(map) ~= "table" then return nil, "uci.json is missing or is not valid JSON" end
  for k, v in pairs(map) do
    if type(k) ~= "string" or not k:match(UCI_KEY_PATTERN) then
      return nil, "uci.json contains an invalid option name: " .. tostring(k)
    end
    if type(v) ~= "string" and type(v) ~= "number" and type(v) ~= "boolean" then
      return nil, "uci.json option '" .. k .. "' is not a scalar value"
    end
  end
  return map
end

-- math.random(0, 0xffffffff) throws "integer expected, got number" on this
-- router's Lua runtime for values above 2^31-1, so build the token out of
-- the same range already proven safe elsewhere in this codebase (see
-- utils.lua's atomic_write / happ_decrypt.lua's write_file temp names).
-- The token names a directory under world-writable /tmp and travels back as a
-- form value, so it must not be guessable. math.random is seeded from the clock,
-- so anything derived from it can be predicted by a local user who then
-- pre-creates the path. Returns nil when no entropy is available.
local function random_token()
  return utils.random_hex(16)
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

-- A cron schedule field is one or more digits/*//,- characters (matches the
-- character set updates.lua's own cron-spec validator accepts). This is not
-- meant to be a full cron-syntax validator, only strict enough to make sure
-- a restored line cannot smuggle a shell command or an unexpected path.
local function is_valid_cron_field(f)
  return f ~= "" and f:match("^[%d%*/,%-]+$") ~= nil
end

-- A GEO cron line restored from a backup must be either empty (schedule
-- disabled) or exactly "<5 valid fields> <fixed updater script> <our tag>" -
-- the same shape updates.lua itself always writes. Anything else (a
-- different command, a missing/extra field, no tag) is refused outright;
-- M.apply() treats a failed validation as a hard error, never a partial
-- write, since this line is appended verbatim into root's crontab.
local function validate_geo_cron_line(line)
  line = trim(line)
  if line == "" then return true end
  local suffix = " " .. GEO_SCRIPT .. " " .. CRON_TAG
  if line:sub(- #suffix) ~= suffix then return false end
  local spec = line:sub(1, #line - #suffix)
  local fields = {}
  for f in spec:gmatch("%S+") do fields[#fields + 1] = f end
  if #fields ~= 5 then return false end
  for _, f in ipairs(fields) do
    if not is_valid_cron_field(f) then return false end
  end
  return true
end

-- Only these directories/module-specific paths are ever legal restore
-- targets, regardless of what an uploaded manifest.json claims. Engine
-- config directories are matched by prefix+extension so restoring onto a
-- fresh router (where the file doesn't exist yet) still works; core/geo/
-- watchdog paths are matched against the CURRENT router's own resolved
-- paths (defaults or whatever is already configured in live UCI), never
-- against anything the backup itself claims - a malicious manifest cannot
-- redirect a restore to an arbitrary file by declaring a fake path.
function M.is_allowed_path(module_id, rel, current_uci)
  current_uci = current_uci or M.collect_uci()
  rel = tostring(rel or "")

  local function flat_name(prefix)
    if rel:sub(1, #prefix) ~= prefix then return nil end
    local name = rel:sub(#prefix + 1)
    if name == "" or name:find("/") then return nil end
    return name
  end

  if module_id == "xray" then
    local name = flat_name("etc/xray/")
    return name ~= nil and name:match("%.json$") ~= nil
  elseif module_id == "mihomo" then
    local name = flat_name("etc/mihomo/")
    return name ~= nil and name:match("%.yaml$") ~= nil
  elseif module_id == "singbox" then
    local name = flat_name("etc/sing-box/")
    return name ~= nil and name:match("%.json$") ~= nil
  elseif module_id == "geo" then
    return rel == rel_path(GEO_CFG) or rel == "etc/tproxy-manager/.geo-cron-line"
  elseif module_id == "watchdog" or module_id == "core" then
    -- Allowed = the fixed defaults, plus whatever paths the CURRENT live
    -- UCI points at. `current_uci` is always the pre-import snapshot: the
    -- only caller chain is M.diff() (fresh M.collect_uci()) and M.apply(),
    -- which runs M.diff() before staging any UCI change and never commits
    -- until every file is written. So within a single import, a path the
    -- backup itself redefines can never become that same import's
    -- destination.
    --
    -- Accepted residual risk (deliberate, see plan): across TWO imports an
    -- admin who applies archive A that repoints e.g. ports_file, and then
    -- applies archive B, lets B write to that new location. Closing this
    -- entirely would mean refusing to restore custom paths at all, which
    -- breaks export->import round-trip on any router that uses them.
    if rel == rel_path(DEFAULT_LINKS_FILE) or rel == rel_path(DEFAULT_SHARE_FILE)
      or rel == rel_path(DEFAULT_SUBS_FILE) then
      return true
    end
    for key, default_path in pairs(CORE_FILE_DEFAULTS) do
      if rel == rel_path(default_path) or rel == rel_path(core_file_path(current_uci, key)) then
        return true
      end
    end
    local links_file = trim(current_uci.watchdog_links_file or "")
    local share_file = trim(current_uci.watchdog_share_file or "")
    if (links_file ~= "" and rel == rel_path(links_file))
      or (share_file ~= "" and rel == rel_path(share_file)) then
      return true
    end
    return false
  end
  return false
end

-- Parses `tar tvzf` output (busybox and GNU tar share this listing shape:
-- perms owner/group size date time name) into {name=, size=, kind=}, where
-- kind is the first character of the permissions field: "-" regular file,
-- "d" directory, anything else (l/c/b/p/s: symlink/device/fifo/socket) is
-- rejected outright below, before a single byte is ever extracted.
-- Reads the listing line by line and stops one past MAX_ITEMS, so an
-- archive with a huge member count never materialises as a large Lua table
-- (the caller rejects on #entries > MAX_ITEMS).
local function parse_tar_listing(upload_path)
  local p = io.popen("tar tvzf " .. utils.shellescape(upload_path) .. " 2>/dev/null")
  if not p then return {} end
  local entries = {}
  for line in p:lines() do
    if trim(line) ~= "" then
      local perms, size, name = line:match("^(%S+)%s+%S+%s+(%d+)%s+%S+%s+%S+%s+(.+)$")
      if not perms then
        entries[#entries + 1] = { name = trim(line), size = 0, kind = "?" }
      else
        entries[#entries + 1] = { name = name, size = tonumber(size) or 0, kind = perms:sub(1, 1) }
      end
      if #entries > MAX_ITEMS then break end
    end
  end
  p:close()
  return entries
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

  -- Exclusive 0700 staging: a predictable name plus ensure_dir() (mkdir -p)
  -- would adopt a directory or symlink a local user pre-created, and every
  -- cp/chmod/find/tar below would then run through it as root.
  local stage, stage_err = utils.private_dir(PENDING_ROOT, "tproxy-manager-backup-export")
  if not stage then
    return nil, "failed to prepare the backup staging directory: " .. tostring(stage_err)
  end
  if not utils.ensure_dir(stage .. "/files") then
    sys.call("rm -rf " .. utils.shellescape(stage) .. " >/dev/null 2>&1")
    return nil, "failed to prepare the backup staging directory"
  end

  local function abort(msg)
    sys.call("rm -rf " .. utils.shellescape(stage) .. " >/dev/null 2>&1")
    return nil, msg
  end

  -- The export side enforces the same caps the import side checks, so this
  -- feature can never produce an archive it would later refuse to read back.
  local manifest_files = {}
  local total = 0
  for _, entry in ipairs(files) do
    local st = fs.stat(entry.path)
    if st and st.type == "reg" then
      if (st.size or 0) > MAX_FILE_BYTES then
        return abort(string.format("%s is too large to back up (max %d MiB per file)",
          entry.path, MAX_FILE_BYTES / 1024 / 1024))
      end
      total = total + (st.size or 0)
      if total > MAX_TOTAL_EXTRACTED_BYTES then
        return abort(string.format("configuration exceeds the backup size limit (max %d MiB)",
          MAX_TOTAL_EXTRACTED_BYTES / 1024 / 1024))
      end
      if #manifest_files + 1 > MAX_ITEMS then
        return abort(string.format("too many files to back up (max %d)", MAX_ITEMS))
      end
      local dest = stage .. "/files/" .. rel_path(entry.path)
      if not utils.ensure_dir(dest:match("^(.*)/[^/]+$") or stage) then
        return abort("failed to prepare the backup staging directory")
      end
      if sys.call("cp -f " .. utils.shellescape(entry.path) .. " " .. utils.shellescape(dest) .. " >/dev/null 2>&1") ~= 0 then
        return abort("failed to copy " .. entry.path .. " into the backup")
      end
      manifest_files[#manifest_files + 1] = { module = entry.module, path = rel_path(entry.path) }
    end
  end

  local function write_checked(path, data)
    utils.ensure_dir(path:match("^(.*)/[^/]+$") or stage)
    fs.writefile(path, data)
    local st = fs.stat(path)
    return st ~= nil and st.type == "reg" and (st.size or 0) == #data
  end

  local cron_line = geo_cron_line()
  if cron_line ~= "" then
    if not write_checked(stage .. "/files/etc/tproxy-manager/.geo-cron-line", cron_line) then
      return abort("failed to write the GEO schedule into the backup")
    end
    manifest_files[#manifest_files + 1] = { module = "geo", path = "etc/tproxy-manager/.geo-cron-line" }
  end

  if not write_checked(stage .. "/uci.json", jsonc.stringify(uci_map, true)) then
    return abort("failed to write the configuration snapshot into the backup")
  end
  if not write_checked(stage .. "/manifest.json", jsonc.stringify({
    schema_version  = M.SCHEMA_VERSION,
    package_version = package_version(),
    created_at      = os.time(),
    files           = manifest_files,
  }, true)) then
    return abort("failed to write the backup manifest")
  end

  -- Directories need the execute bit to stay traversable, so set file and
  -- directory modes separately instead of a blanket chmod -R.
  sys.call("find " .. utils.shellescape(stage) .. " -type d -exec chmod 0700 {} + >/dev/null 2>&1")
  sys.call("find " .. utils.shellescape(stage) .. " -type f -exec chmod 0600 {} + >/dev/null 2>&1")

  -- Built inside its OWN exclusive 0700 directory rather than straight into
  -- /tmp: a root `tar czf` would follow a symlink planted at that path and
  -- overwrite whatever it points at.
  local outdir, outdir_err = utils.private_dir(PENDING_ROOT, "tproxy-manager-backup-out")
  if not outdir then
    sys.call("rm -rf " .. utils.shellescape(stage) .. " >/dev/null 2>&1")
    return nil, "failed to prepare the backup output directory: " .. tostring(outdir_err)
  end
  local archive = outdir .. "/tproxy-manager-backup.tar.gz"
  local rc = sys.call("tar czf " .. utils.shellescape(archive) ..
    " -C " .. utils.shellescape(stage) .. " manifest.json uci.json files 2>/dev/null")
  sys.call("rm -rf " .. utils.shellescape(stage) .. " >/dev/null 2>&1")

  if rc ~= 0 or not file_exists(archive) then
    sys.call("rm -rf " .. utils.shellescape(outdir) .. " >/dev/null 2>&1")
    return nil, "failed to build the backup archive"
  end
  sys.call("chmod 0600 " .. utils.shellescape(archive) .. " >/dev/null 2>&1")

  -- Финальная проверка уже собранного архива: он должен пройти те же
  -- лимиты, что и на импорте, иначе экспорт молча создаёт файл, который
  -- сам же потом откажется принимать.
  local ast = fs.stat(archive)
  if not ast or (ast.size or 0) > MAX_ARCHIVE_BYTES then
    fs.remove(archive)
    return nil, string.format("backup archive exceeds the %d MiB limit and was discarded",
      MAX_ARCHIVE_BYTES / 1024 / 1024)
  end
  local produced = parse_tar_listing(archive)
  if #produced > MAX_ITEMS then
    fs.remove(archive)
    return nil, string.format("backup archive has too many entries (max %d)", MAX_ITEMS)
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

-- Recursively walks the extracted pending dir and rejects (returns false)
-- if anything other than a regular file or directory is found. Uses lstat,
-- not stat, specifically so a symlink is seen as a symlink and not silently
-- resolved to whatever regular file it points at.
local function lstat_sweep_is_clean(dir)
  local it = fs.dir(dir)
  if not it then return true end
  for name in it do
    local path = dir .. "/" .. name
    local st = fs.lstat(path)
    if not st then return false end
    if st.type == "dir" or st.type == "directory" then
      if not lstat_sweep_is_clean(path) then return false end
    elseif st.type ~= "reg" then
      return false
    elseif (st.nlink or 1) > 1 then
      -- A hardlink to a file outside the pending dir: type is "reg" so the
      -- normal check passes, but any chmod/write here would hit the other
      -- inode too. The listing-level " -> " check already rejects these;
      -- this is the belt-and-braces catch if a tar build ever lists them
      -- differently.
      return false
    end
  end
  return true
end

-- discard_export: remove the archive AND the exclusive directory holding it.
-- The caller only ever sees the archive path, so without this the (now empty)
-- private directory would be left behind in tmpfs after every download.
function M.discard_export(archive)
  archive = tostring(archive or "")
  local dir = archive:match("^(.*)/[^/]+$")
  if dir and dir:sub(1, #PENDING_ROOT + 1) == PENDING_ROOT .. "/"
    and dir:match("/tproxy%-manager%-backup%-out%.%x+$") then
    sys.call("rm -rf " .. utils.shellescape(dir) .. " >/dev/null 2>&1")
    return
  end
  if archive ~= "" then fs.remove(archive) end
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
    -- Pending import dirs AND raw upload temp files: a client that aborts
    -- mid-upload kills the CGI process before its own cleanup runs, so
    -- those partial files would otherwise sit in tmpfs (RAM) until reboot.
    local is_pending = name:sub(1, #PENDING_PREFIX) == PENDING_PREFIX
    local is_upload  = name:sub(1, #UPLOAD_PREFIX) == UPLOAD_PREFIX
    -- Private temp dirs created by utils.private_tmpdir(): an aborted upload
    -- leaves one behind, and it no longer matches UPLOAD_PREFIX now that the
    -- upload lives inside such a directory rather than as a bare file.
    local is_privtmp = name:sub(1, 10) == ".tpm-tmp.0" or name:match("^%.tpm%-tmp%.%d+%.%d+$") ~= nil
    -- Exclusive staging/output dirs from an export that died before its own
    -- cleanup: they no longer carry the old predictable names.
    local is_export = name:match("^tproxy%-manager%-backup%-export%.%x+$") ~= nil
      or name:match("^tproxy%-manager%-backup%-out%.%x+$") ~= nil
    if is_pending or is_upload or is_privtmp or is_export then
      local path = PENDING_ROOT .. "/" .. name
      local st = fs.stat(path)
      if st and st.mtime and (now - st.mtime) > PENDING_TTL then
        sys.call("rm -rf " .. utils.shellescape(path) .. " >/dev/null 2>&1")
      end
    end
  end
end

-- upload_path: a file already fully written to disk (by the controller's
-- own setfilehandler), safe to read/move from. Returns token on success.
-- Rejects oversized archives, symlinks/devices/hardlinks, unsafe paths and
-- too many/too large members BEFORE calling `tar xzf`, so a crafted small
-- archive that would decompress into something huge never gets the chance.
function M.extract_pending(upload_path)
  M.cleanup_stale()

  if not file_exists(upload_path) then
    return nil, "upload is missing"
  end

  local ust = fs.stat(upload_path)
  if not ust or (ust.size or 0) > MAX_ARCHIVE_BYTES then
    return nil, string.format("backup archive is too large (max %d MiB compressed)", MAX_ARCHIVE_BYTES / 1024 / 1024)
  end

  local entries = parse_tar_listing(upload_path)
  if #entries == 0 then
    return nil, "not a valid backup archive"
  end
  if #entries > MAX_ITEMS then
    return nil, string.format("backup archive has too many entries (max %d)", MAX_ITEMS)
  end

  local total_size = 0
  local seen_member = {}
  for _, e in ipairs(entries) do
    -- Дубли в архиве опасны тем, что tar распаковывает их по очереди и
    -- на диске остаётся ПОСЛЕДНИЙ, тогда как проверки схемы видели бы
    -- первый: содержимое, которое одобрил пользователь, и содержимое,
    -- которое реально применится, могли бы различаться.
    if seen_member[e.name] then
      return nil, "backup archive contains a duplicate entry: " .. e.name
    end
    seen_member[e.name] = true
    if e.kind ~= "-" and e.kind ~= "d" then
      return nil, "backup archive contains an unsupported entry type: " .. e.name
    end
    -- busybox tar reports a HARDLINK with typeflag '1' as a regular file
    -- ("-") of size 0 and appends " -> <target>" to the listed name, so the
    -- kind check above cannot catch it, and lstat() can't either (a hardlink
    -- really is a regular file). Left unchecked, `tar xzf` would link() the
    -- victim inode into the pending dir and the following chmod would then
    -- alter the real file's mode. Any listing name carrying a link arrow is
    -- refused outright - our own archives never produce one.
    if e.name:find(" -> ", 1, true) then
      return nil, "backup archive contains a link entry: " .. e.name
    end
    if not safe_member(e.name) then
      return nil, "backup archive contains an unsafe path: " .. e.name
    end
    if e.size > MAX_FILE_BYTES then
      return nil, string.format("backup archive contains an oversized file (max %d MiB): %s", MAX_FILE_BYTES / 1024 / 1024, e.name)
    end
    total_size = total_size + e.size
  end
  if total_size > MAX_TOTAL_EXTRACTED_BYTES then
    return nil, string.format("backup archive is too large uncompressed (max %d MiB)", MAX_TOTAL_EXTRACTED_BYTES / 1024 / 1024)
  end

  local token = random_token()
  if not token then
    return nil, "no entropy available to stage the backup"
  end
  local dir = pending_dir(token)
  -- Exclusive creation, not ensure_dir(): `mkdir` without -p fails if the name
  -- exists in any form, so a pre-created directory or symlink can never be
  -- adopted as the extraction target for a root tar.
  if sys.call("mkdir -m 0700 " .. utils.shellescape(dir) .. " >/dev/null 2>&1") ~= 0 then
    return nil, "failed to prepare the backup staging directory"
  end
  local dst = fs.lstat(dir)
  if not dst or (dst.type ~= "dir" and dst.type ~= "directory")
    or (dst.uid or -1) ~= 0 or (dst.modedec or 0) ~= 700 then
    sys.call("rm -rf " .. utils.shellescape(dir) .. " >/dev/null 2>&1")
    return nil, "failed to prepare the backup staging directory"
  end

  local rc = sys.call("tar xzf " .. utils.shellescape(upload_path) ..
    " -C " .. utils.shellescape(dir) .. " >/dev/null 2>&1")
  if rc ~= 0 then
    sys.call("rm -rf " .. utils.shellescape(dir) .. " >/dev/null 2>&1")
    return nil, "failed to extract backup archive"
  end

  -- Defense in depth: the pre-extraction type check above already rejects
  -- non-regular/non-directory tar entries by their listed permissions, but
  -- re-verify with lstat on what actually landed on disk in case some tar
  -- implementation's listing and extraction behavior ever disagree.
  if not lstat_sweep_is_clean(dir) then
    sys.call("rm -rf " .. utils.shellescape(dir) .. " >/dev/null 2>&1")
    return nil, "backup archive contains an unsupported file type after extraction"
  end

  sys.call("find " .. utils.shellescape(dir) .. " -type d -exec chmod 0700 {} + >/dev/null 2>&1")
  sys.call("find " .. utils.shellescape(dir) .. " -type f -exec chmod 0600 {} + >/dev/null 2>&1")

  local function fail(msg)
    sys.call("rm -rf " .. utils.shellescape(dir) .. " >/dev/null 2>&1")
    return nil, msg
  end

  local manifest_raw = read_file(dir .. "/manifest.json")
  local ok, manifest = pcall(jsonc.parse, manifest_raw)
  if not ok or type(manifest) ~= "table" then
    return fail("backup archive is missing a valid manifest.json")
  end
  if tonumber(manifest.schema_version) ~= M.SCHEMA_VERSION then
    return fail("unsupported backup format version")
  end
  if type(manifest.files) ~= "table" then
    return fail("manifest.json is missing its files list")
  end

  -- Cross-check manifest.files against what the archive actually contains:
  -- every declared path must have a matching files/<path> member, and every
  -- files/<path> member in the archive must be declared - no undeclared
  -- extras and no dangling declarations pointing at a member that was never
  -- actually included. Also reject duplicate declarations outright.
  local extracted_files = {}
  for _, e in ipairs(entries) do
    local rel = e.name:match("^files/(.+)$")
    if rel and e.kind == "-" then extracted_files[rel] = true end
  end
  local known_module = {}
  for _, id in ipairs(M.MODULE_ORDER) do known_module[id] = true end

  local declared = {}
  for _, entry in ipairs(manifest.files) do
    if type(entry) ~= "table" or type(entry.path) ~= "string" or entry.path == "" then
      return fail("manifest.json contains an invalid file entry")
    end
    -- `module` decides which allowlist branch a path is checked against and
    -- which service gets restarted, so it must be an exact known id - never
    -- defaulted, never free-form.
    if type(entry.module) ~= "string" or not known_module[entry.module] then
      return fail("manifest.json entry has an unknown module: " .. tostring(entry.module))
    end
    -- Reject non-normalised spellings ("./x", "a//b", trailing "/") so the
    -- allowlist's string comparisons can't be sidestepped by an alternate
    -- rendering of the same path.
    if entry.path:find("//", 1, true) or entry.path:sub(1, 2) == "./"
      or entry.path:sub(-1) == "/" or entry.path:find("/./", 1, true) then
      return fail("manifest.json contains a non-normalised path: " .. entry.path)
    end
    if declared[entry.path] then
      return fail("manifest.json declares a duplicate path: " .. entry.path)
    end
    declared[entry.path] = true
    if not extracted_files[entry.path] then
      return fail("manifest.json declares a file that is not in the archive: " .. entry.path)
    end
  end
  for rel in pairs(extracted_files) do
    if not declared[rel] then
      return fail("archive contains an undeclared file: " .. rel)
    end
  end

  local _, uci_err = parse_uci_map(read_file(dir .. "/uci.json"))
  if uci_err then
    return fail(uci_err)
  end

  return token, nil, manifest
end

-- Tokens are generated by random_token() and are always lowercase hex.
-- Validated on every entry point that turns one into a filesystem path, so
-- a hand-crafted backup_token form value can never point pending_dir() at
-- something else.
local function valid_token(token)
  return type(token) == "string" and token:match("^[0-9a-f]+$") ~= nil
end

function M.cancel(token)
  if not valid_token(token) then return false end
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
  if not valid_token(token) then return nil, "pending import not found or expired" end
  local dir = pending_dir(token)
  local manifest_raw = read_file(dir .. "/manifest.json")
  local ok, manifest = pcall(jsonc.parse, manifest_raw)
  if not ok or type(manifest) ~= "table" then
    return nil, "pending import not found or expired"
  end

  local current_uci = M.collect_uci()

  -- Validate every declared path against the module-aware allowlist, and
  -- the GEO cron entry's exact shape, before building anything the user
  -- could approve. A manifest.json is fully attacker-controlled content
  -- inside the uploaded archive - none of its declared paths or file
  -- contents are trusted just because the archive extracted cleanly.
  for _, entry in ipairs(manifest.files or {}) do
    local id = entry.module
    if not M.is_allowed_path(id, entry.path, current_uci) then
      return nil, "backup references a path outside the allowed set: " .. tostring(entry.path)
    end
    if entry.path == "etc/tproxy-manager/.geo-cron-line" then
      local new_line = trim(read_file(dir .. "/files/" .. entry.path))
      if not validate_geo_cron_line(new_line) then
        return nil, "backup's GEO cron entry failed validation"
      end
    end
  end

  local backup_uci, uci_err = parse_uci_map(read_file(dir .. "/uci.json"))
  if not backup_uci then return nil, uci_err end

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
    local id = entry.module
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
  -- or a file deleted after the backup was made) are listed for information
  -- only: apply() restores the manifest and never deletes anything outside
  -- it, so these files are left exactly as they are.
  --
  -- They deliberately do NOT set touched[]: `touched` is the set of modules
  -- this restore actually changes, and it drives the service restarts. A
  -- module whose only entry is an untouched file would otherwise have its
  -- service bounced for a change that never happened.
  local current_files = M.list_files(current_uci)
  local in_manifest = {}
  for _, entry in ipairs(manifest.files or {}) do in_manifest[entry.path] = true end
  for _, entry in ipairs(current_files) do
    local rel = rel_path(entry.path)
    if not in_manifest[rel] and file_exists(entry.path) then
      modules[entry.module].files[#modules[entry.module].files + 1] = {
        path = entry.path, status = "removed",
      }
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
-- Returns the secure_write tri-state unchanged: true / false,"write" /
-- false,"permissions". Callers must treat "permissions" as a COMPLETED
-- write - the destination is already replaced.
local function restore_file(src, dest)
  local st = fs.stat(src)
  if not st or st.type ~= "reg" then return false, "write" end
  local data = fs.readfile(src)
  if data == nil then return false, "write" end
  return utils.secure_write(dest, data)
end

-- Small helper used only by the cron-line restore branch in M.apply: writes
-- text to a temp file next to `path` and promotes it, same as restore_file
-- but starting from an in-memory string instead of an existing file.
local function restore_file_from_text(path, text)
  -- Goes through the shared secure writer: exclusive temp creation, checked
  -- write/close/promote, 0600 on the result.
  return utils.secure_write(path, text)
end

local function apply_geo_cron_entry(dir, rel)
  local new_line = trim(read_file(dir .. "/files/" .. rel))
  if not validate_geo_cron_line(new_line) then return false, "write" end
  local body = read_file(CRON_FILE)
  local kept = {}
  for line in (body .. "\n"):gmatch("([^\n]*)\n") do
    if not line:find(CRON_TAG, 1, true) and line ~= "" then kept[#kept + 1] = line end
  end
  if new_line ~= "" then kept[#kept + 1] = new_line end
  -- Passes the tri-state through unchanged so apply() can tell a real
  -- failure from a mode-only problem.
  return restore_file_from_text(CRON_FILE, table.concat(kept, "\n") .. (#kept > 0 and "\n" or ""))
end

local function live_path_of(rel)
  if rel == "etc/tproxy-manager/.geo-cron-line" then return CRON_FILE end
  return "/" .. rel
end

-- Applies a previously-diffed pending import as an all-or-nothing operation:
-- 1. re-validate (M.diff already checks paths/cron shape/uci.json; re-run
--    so apply() is safe to call on its own, not only right after a fresh
--    diff);
-- 2. snapshot the current content AND mode of every file about to change
--    into an on-disk rollback/ subdirectory next to the pending import -
--    not held as Lua strings, so a run with many/large files never holds
--    more than one file's content in process memory at a time;
-- 3. stage UCI changes (set/delete) WITHOUT committing yet;
-- 4. restore files one by one, checking every single result;
-- 5. on the first failure, restore every already-changed file (and its
--    mode) from the on-disk snapshot, uci:revert() the staged UCI changes,
--    and return false while keeping the pending import in place so the
--    user can retry - nothing is committed and no service is restarted on
--    a partial failure;
-- 6. only once every file succeeded, commit UCI and delete the pending
--    import (rollback/ included).
-- Returns (true, touched) on success, matching the previous contract, or
-- (false, err) - err is a plain string, never partial success.
function M.apply(token)
  if not valid_token(token) then return false, "pending import not found or expired" end

  local dir = pending_dir(token)

  -- GLOBAL lock, not per-token: two DIFFERENT backups applied at the same
  -- time would each pass a per-token lock while writing to the same live
  -- files and the same UCI section, interleaving into a state that matches
  -- neither archive. mkdir is atomic, so whoever creates it first wins.
  -- Root-only 0700 parent: in world-writable /tmp (or /var/lock, also 1777)
  -- any local user could pre-create the lock path and deny imports forever.
  local lock_root, lock_err = utils.secure_lock_root("/var/lock/tproxy-manager")
  if not lock_root then
    return false, "refusing to run: " .. tostring(lock_err)
  end
  local lock = lock_root .. "/backup-apply.lock"
  -- Recover a lock left behind by a process that died mid-apply. PID-aware
  -- rather than TTL-only: waiting 20 minutes after a crash is needlessly
  -- long, and a pure TTL would eventually steal the lock from a genuinely
  -- slow but still-running apply. The owner PID is written inside the lock
  -- directory; if that process is gone, the lock is stale immediately.
  do
    local lst = fs.stat(lock)
    if lst then
      local owner = trim(read_file(lock .. "/pid"))
      local age = lst.mtime and (os.time() - lst.mtime) or 0
      local stale
      if owner ~= "" then
        -- Owner is known: the lock is stale only if that process is gone.
        -- A live but slow apply is never interrupted, no matter how long
        -- it runs.
        stale = fs.stat("/proc/" .. owner) == nil
      else
        -- No pid yet. This is the race window between another process's
        -- mkdir() and its pid write - treat a young ownerless lock as LIVE
        -- so we do not delete a lock that is being acquired right now.
        -- Only an ownerless lock older than the TTL counts as abandoned.
        stale = age > PENDING_TTL
      end
      if stale then
        sys.call("rm -rf " .. utils.shellescape(lock) .. " >/dev/null 2>&1")
      end
    end
  end
  if sys.call("mkdir " .. utils.shellescape(lock) .. " >/dev/null 2>&1") ~= 0 then
    return false, "this backup is already being applied"
  end
  local function unlock()
    sys.call("rm -rf " .. utils.shellescape(lock) .. " >/dev/null 2>&1")
  end

  -- Record our PID inside the lock so a later run can tell a crashed owner
  -- from a live one. If the owner cannot be recorded, release the lock at
  -- once instead of leaving an unattributable one behind.
  do
    local pid = trim(sys.exec("echo $PPID") or "")
    if pid == "" or not pid:match("^%d+$") then
      unlock()
      return false, "could not record the import lock owner"
    end
    fs.writefile(lock .. "/pid", pid)
    local check = trim(read_file(lock .. "/pid"))
    if check ~= pid then
      unlock()
      return false, "could not record the import lock owner"
    end
  end

  local diff, err = M.diff(token)
  if not diff then unlock(); return false, err end

  -- The rollback snapshot lives in utils' durable store, NOT inside the pending
  -- directory. Two reasons, both of which bit this code before:
  --
  --   * a retry of apply() used to `rm -rf` the rollback directory on entry,
  --     destroying the only copy of the pre-import state left behind by a
  --     crashed first attempt;
  --   * the store records a transaction STAGE, so a process killed between two
  --     file writes leaves a snapshot the sweeper PRESERVES instead of
  --     reclaiming, and its restore verifies content byte-for-byte instead of
  --     only checking that the target exists.
  --
  -- Every target from the manifest is recorded, present or not: the store puts
  -- an absent file back by deleting whatever the import created.
  local store, store_err = utils.snapshot_begin("backup-apply")
  if store then
    for _, entry in ipairs(diff.manifest.files or {}) do
      if not store then break end
      local ok_s, aerr = utils.snapshot_add(store, live_path_of(entry.path))
      if not ok_s then store_err = aerr; utils.snapshot_discard(store); store = nil end
    end
  end
  if not store then
    unlock()
    return false, "could not create the rollback snapshot: " .. tostring(store_err)
  end

  local uci = ucim.cursor()
  local current_uci = M.collect_uci(uci)

  local backup_uci, uci_err = parse_uci_map(read_file(dir .. "/uci.json"))
  if not backup_uci then
    utils.snapshot_discard(store)
    unlock()
    return false, uci_err
  end
  for k in pairs(current_uci) do
    if backup_uci[k] == nil then
      if not uci:delete(PKG, "main", k) then
        uci:revert(PKG)
        utils.snapshot_discard(store)
        unlock()
        return false, "could not stage removal of UCI option " .. k
      end
    end
  end
  for k, v in pairs(backup_uci) do
    if not uci:set(PKG, "main", k, tostring(v)) then
      uci:revert(PKG)
      utils.snapshot_discard(store)
      unlock()
      return false, "could not stage UCI option " .. k
    end
  end

  -- Armed immediately before the first live write. From here on, a process
  -- killed mid-apply leaves a snapshot the sweeper preserves rather than one it
  -- reclaims as "changed nothing" - which is precisely the half-applied import
  -- this whole rollback exists for.
  local armed, arm_err = utils.snapshot_arm(store)
  if not armed then
    uci:revert(PKG)
    utils.snapshot_discard(store)
    unlock()
    return false, "could not arm the rollback snapshot: " .. tostring(arm_err)
  end

  local applied = {}
  local fail_reason = nil
  local perm_files = {}
  for _, entry in ipairs(diff.manifest.files or {}) do
    local rel = entry.path
    local ok, why
    if rel == "etc/tproxy-manager/.geo-cron-line" then
      ok, why = apply_geo_cron_entry(dir, rel)
    else
      ok, why = restore_file(dir .. "/files/" .. rel, "/" .. rel)
    end
    if ok or why == "permissions" then
      -- "permissions" means the destination WAS replaced, only its mode
      -- could not be set. It must join `applied` so a later failure still
      -- rolls it back; treating it as "not written" used to leave such a
      -- file in place after a formally failed restore.
      applied[#applied + 1] = rel
      if not ok then perm_files[#perm_files + 1] = "/" .. rel end
    else
      fail_reason = "failed to restore: " .. rel
      break
    end
  end

  -- Единая проверяемая процедура отката для ОБЕИХ веток отказа (ошибка
  -- файла и ошибка uci:commit): раньше это был продублированный код, и
  -- расхождение между копиями означало бы, что один из путей откатывает
  -- не всё. Возвращает список невосстановленных целей.
  -- The store restores content AND mode and verifies both by reading the file
  -- back; the previous version only checked that the target still existed, so a
  -- rollback that wrote nothing counted as complete. Returns the paths that did
  -- NOT come back.
  local function do_rollback()
    local unrestored = {}
    for _, f in ipairs(utils.snapshot_restore(store)) do
      unrestored[#unrestored + 1] = f.path .. (f.state == "permissions" and " (mode)" or "")
    end
    uci:revert(PKG)
    return unrestored
  end

  local function finish_failed(reason)
    local unrestored = do_rollback()
    if #unrestored > 0 then
      -- The store is KEPT and marked: it holds the only copy of the original
      -- content for the targets that could not be put back, and the marker
      -- stops the sweeper from ever reclaiming it.
      local kept = utils.snapshot_keep(store) or store.dir
      unlock()
      return false, string.format(
        "%s - ROLLBACK INCOMPLETE, these targets still hold restored content: %s (originals kept in %s)",
        reason, table.concat(unrestored, ", "), kept)
    end
    utils.snapshot_discard(store)
    unlock()
    return false, reason .. " - rolled back, backup kept for retry"
  end

  if fail_reason then
    return finish_failed(fail_reason)
  end

  local committed, why = utils.commit_uci(uci, PKG)
  if not committed and why == "commit" then
    -- Genuinely not committed: undoing the files is correct.
    return finish_failed("failed to commit UCI configuration")
  end
  -- why == "permissions": UCI IS already durable. Rolling the files back
  -- here would leave the restored config pointing at pre-restore files -
  -- exactly the desynchronised state the rollback exists to prevent. Finish
  -- the restore and surface the permissions problem instead.
  local warn_parts = {}
  if not committed then
    warn_parts[#warn_parts + 1] = "/etc/config/" .. PKG
  end
  for _, f in ipairs(perm_files) do warn_parts[#warn_parts + 1] = f end
  local perm_warning = (#warn_parts > 0) and
    ("permissions could not be set to 0600 for: " .. table.concat(warn_parts, ", ")) or nil

  utils.snapshot_discard(store)
  unlock()
  M.cancel(token)
  return true, diff.touched, perm_warning
end

return M
