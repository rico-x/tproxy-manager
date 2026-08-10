local fs = require "nixio.fs"
local sys = require "luci.sys"
local jsonc = require "luci.jsonc"
local proxy_links = require "tproxy_manager.proxy_links"
local utils = require "luci.model.cbi.tproxy_manager.utils"

local M = {}

M.DEFAULT_CONFIG = {
  version = 1,
  selection_mode = "all",
  selected = {},
}

M.VARIANTS = {
  { slug = "plain", label = "plain" },
  { slug = "base64", label = "base64" },
}

local b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function trim(value)
  return tostring(value or ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
end

local function shellescape(value)
  value = tostring(value or "")
  if value == "" then return "''" end
  return "'" .. value:gsub("'", "'\\''") .. "'"
end

local function ensure_dir(path)
  local dir = tostring(path or ""):match("^(.*)/[^/]+$")
  if dir and dir ~= "" then
    sys.call("mkdir -p " .. shellescape(dir) .. " >/dev/null 2>&1")
  end
end

-- Единая безопасная атомарная запись из utils: временный файл создаётся
-- эксклюзивно и получает 0600 до наполнения, поэтому расшаренный список
-- прокси-ссылок ни на мгновение не лежит доступным на чтение всем.
local function atomic_write(path, data)
  return utils.secure_write(path, data)
end

local function parse_link_line(line)
  return proxy_links.parse_link_line(line)
end

local function normalize_selected(value)
  local selected = {}
  if type(value) ~= "table" then return selected end
  for key, flag in pairs(value) do
    if type(key) == "number" then
      local hash = trim(flag)
      if hash:match("^[0-9a-fA-F]+$") then selected[hash:lower()] = true end
    elseif flag == true or flag == 1 or flag == "1" or flag == "true" then
      local hash = trim(key)
      if hash:match("^[0-9a-fA-F]+$") then selected[hash:lower()] = true end
    end
  end
  return selected
end

local function normalize_config(config)
  if type(config) ~= "table" then config = {} end
  local mode = trim(config.selection_mode)
  if mode ~= "selected" then mode = "all" end
  return {
    version = 1,
    selection_mode = mode,
    selected = normalize_selected(config.selected),
  }
end

local function json_escape(value)
  value = tostring(value or "")
  return value:gsub("[%z\1-\31\\\"]", function(c)
    if c == "\\" then return "\\\\" end
    if c == "\"" then return "\\\"" end
    if c == "\n" then return "\\n" end
    if c == "\r" then return "\\r" end
    if c == "\t" then return "\\t" end
    return string.format("\\u%04x", c:byte())
  end)
end

local function stringify_config(config)
  config = normalize_config(config)
  local keys = {}
  for hash in pairs(config.selected) do keys[#keys + 1] = hash end
  table.sort(keys)

  local out = {
    "{",
    '  "version": 1,',
    string.format('  "selection_mode": "%s",', json_escape(config.selection_mode)),
    '  "selected": {',
  }
  for idx, hash in ipairs(keys) do
    out[#out + 1] = string.format('    "%s": true%s', json_escape(hash), idx < #keys and "," or "")
  end
  out[#out + 1] = "  }"
  out[#out + 1] = "}"
  return table.concat(out, "\n") .. "\n"
end

local function base64_encode(data)
  data = tostring(data or "")
  return ((data:gsub(".", function(x)
    local bits, byte = "", x:byte()
    for i = 8, 1, -1 do
      bits = bits .. (byte % 2 ^ i - byte % 2 ^ (i - 1) > 0 and "1" or "0")
    end
    return bits
  end) .. "0000"):gsub("%d%d%d?%d?%d?%d?", function(x)
    if #x < 6 then return "" end
    local c = 0
    for i = 1, 6 do
      c = c + (x:sub(i, i) == "1" and 2 ^ (6 - i) or 0)
    end
    return b64:sub(c + 1, c + 1)
  end) .. ({ "", "==", "=" })[#data % 3 + 1])
end

function M.is_variant(slug)
  slug = trim(slug):lower()
  return slug == "plain" or slug == "base64"
end

function M.read_config(path)
  local raw = fs.readfile(path) or ""
  if raw == "" then return normalize_config(M.DEFAULT_CONFIG) end
  local ok, parsed = pcall(jsonc.parse, raw)
  if not ok or type(parsed) ~= "table" then return normalize_config(M.DEFAULT_CONFIG) end
  return normalize_config(parsed)
end

function M.write_config(path, config)
  return atomic_write(path, stringify_config(config))
end

function M.parse_links_file(path)
  local entries = {}
  local seen = {}
  local raw = fs.readfile(path) or ""
  for line in (raw .. "\n"):gmatch("([^\n]*)\n") do
    local entry = parse_link_line(line)
    if entry and not seen[entry.hash] then
      seen[entry.hash] = true
      entries[#entries + 1] = entry
    end
  end
  return entries
end

function M.selected_entries(entries, config)
  config = normalize_config(config)
  if config.selection_mode ~= "selected" then return entries or {} end
  local out = {}
  for _, entry in ipairs(entries or {}) do
    if config.selected[entry.hash] then out[#out + 1] = entry end
  end
  return out
end

function M.render_payload(entries, variant)
  local lines = {}
  for _, entry in ipairs(entries or {}) do
    if trim(entry.raw_link) ~= "" then lines[#lines + 1] = trim(entry.raw_link) end
  end
  local plain = #lines > 0 and (table.concat(lines, "\n") .. "\n") or ""
  if variant == "base64" then return base64_encode(plain) end
  return plain
end

function M.selected_count(config)
  local count = 0
  config = normalize_config(config)
  for _ in pairs(config.selected) do count = count + 1 end
  return count
end

return M
