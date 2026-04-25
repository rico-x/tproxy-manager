local fs = require "nixio.fs"
local sys = require "luci.sys"
local jsonc = require "luci.jsonc"

local M = {}

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

function M.atomic_write(path, data)
  path = tostring(path or "")
  data = tostring(data or ""):gsub("\r\n", "\n")
  local dir, base = path:match("^(.*)/([^/]+)$")
  local tmpdir = (dir and dir ~= "") and dir or "/tmp"
  if dir and dir ~= "" then
    M.ensure_dir(dir)
  end
  local tmp = string.format("%s/.%s.%d.tmp", tmpdir, base or "tmp", math.random(1, 10^9))
  fs.writefile(tmp, data)
  fs.rename(tmp, path)
end

function M.read_file(path)
  return fs.readfile(path) or ""
end

function M.write_file(path, data)
  M.atomic_write(path, data or "")
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
    return nil, "Некорректный JSON/JSONC"
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

  local function get_err()
    local st = fs.stat(err_file)
    if st and st.mtime and ttl > 0 and (os.time() - st.mtime) > ttl then
      fs.remove(err_file)
      return ""
    end
    return M.read_file(err_file)
  end

  local function get_info()
    return M.read_file(info_file)
  end

  return {
    set_err = function(text) set_file(err_file, text) end,
    get_err = get_err,
    set_info = function(text) set_file(info_file, text) end,
    get_info = get_info,
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
  for _, part in ipairs({ a, b, c, d }) do
    local n = tonumber(part)
    if not n or n < 0 or n > 255 then return false end
  end
  return true
end

function M.is_abs_path(path)
  path = tostring(path or "")
  return path:match("^/[%w%._%-%+/@:]*$") ~= nil
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
