local sys = require "luci.sys"

local M = {}

local function trim(value)
  return tostring(value or ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
end

local function shellescape(value)
  value = tostring(value or "")
  if value == "" then return "''" end
  return "'" .. value:gsub("'", "'\\''") .. "'"
end

local function urldecode_component(s)
  s = tostring(s or ""):gsub("+", " ")
  return (s:gsub("%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end))
end

function M.scheme(raw_link)
  local scheme = trim(raw_link):match("^([A-Za-z][A-Za-z0-9+.-]*)://")
  return scheme and scheme:lower() or ""
end

function M.is_supported(raw_link)
  local scheme = M.scheme(raw_link)
  return scheme == "vless" or scheme == "hysteria2" or scheme == "hy2"
end

function M.protocol(raw_link)
  local scheme = M.scheme(raw_link)
  if scheme == "hysteria2" or scheme == "hy2" then return "hy2" end
  if scheme == "vless" then return "vless" end
  return ""
end

function M.protocol_label(raw_link)
  local proto = M.protocol(raw_link)
  if proto == "hy2" then return "HY2" end
  if proto == "vless" then return "VLESS" end
  return "-"
end

function M.hash(raw_link)
  local out = sys.exec("printf %s " .. shellescape(raw_link) .. " | md5sum 2>/dev/null | awk '{print $1}'") or ""
  return trim(out):match("^[0-9a-fA-F]+$") and trim(out):lower() or ""
end

function M.split_link_comment(line)
  local value = trim(line)
  local raw_link, external_comment = value, ""
  if value:find(" # ", 1, true) then
    raw_link = value:match("^(.-) # ") or value
    external_comment = trim(value:match(" # (.*)$") or "")
  end
  return trim(raw_link), external_comment
end

function M.display_comment(raw_link, external_comment)
  local fragment = tostring(raw_link or ""):match("#(.*)$") or ""
  local comment = trim(external_comment)
  if comment == "" then comment = trim(urldecode_component(fragment)) end
  return comment
end

function M.display_link(raw_link)
  return tostring(raw_link or ""):gsub("#.*$", "")
end

function M.parse_link_line(line)
  local value = trim(line)
  if value == "" or value:match("^#") then return nil end

  local raw_link, external_comment = M.split_link_comment(value)
  if not M.is_supported(raw_link) then return nil end

  local hash = M.hash(raw_link)
  if hash == "" then return nil end

  return {
    hash = hash,
    raw_link = raw_link,
    display_link = M.display_link(raw_link),
    comment = M.display_comment(raw_link, external_comment),
    external_comment = external_comment,
    protocol = M.protocol(raw_link),
    protocol_label = M.protocol_label(raw_link),
  }
end

function M.extract_from_text(text)
  local out, seen = {}, {}
  local source = tostring(text or "")
  for link in source:gmatch("([A-Za-z0-9+.-]+://[^%s\"'<>]+)") do
    if M.is_supported(link) then
      local hash = M.hash(link)
      if hash ~= "" and not seen[hash] then
        out[#out + 1] = {
          hash = hash,
          raw_link = link,
          protocol = M.protocol(link),
          protocol_label = M.protocol_label(link),
        }
        seen[hash] = true
      end
    end
  end
  return out, seen
end

M.trim = trim
M.shellescape = shellescape
M.urldecode_component = urldecode_component

return M
