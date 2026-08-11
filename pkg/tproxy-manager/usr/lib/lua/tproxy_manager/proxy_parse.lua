local M = {}

local function trim(value)
  -- Assigning first truncates gsub's second return value (the replacement
  -- count). Returning it straight through made every caller receive two
  -- values, and `tonumber(trim(x))` then read that count as the numeric
  -- base -- an outright error for a count of 0 or 1.
  local text = tostring(value or ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
  return text
end

local function urldecode(s)
  s = tostring(s or ""):gsub("+", " ")
  return (s:gsub("%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end))
end

local function urlencode(s)
  return (tostring(s or ""):gsub("([^A-Za-z0-9%-%._~])", function(c)
    return string.format("%%%02X", string.byte(c))
  end))
end

local function parse_query(q)
  local t = {}
  q = tostring(q or "")
  for pair in q:gmatch("[^&]+") do
    local k, v = pair:match("^([^=]*)=?(.*)$")
    if k and k ~= "" then t[urldecode(k)] = urldecode(v or "") end
  end
  return t
end

local function split_csv(value)
  local out = {}
  for item in tostring(value or ""):gmatch("[^,]+") do
    item = trim(item)
    if item ~= "" then out[#out + 1] = item end
  end
  return out
end

local function split_link_comment(line)
  local value = trim(line)
  local raw_link, external_comment = value, ""
  if value:find(" # ", 1, true) then
    raw_link = value:match("^(.-) # ") or value
    external_comment = trim(value:match(" # (.*)$") or "")
  end
  return trim(raw_link), external_comment
end

local function split_uri(raw_link)
  local fragment = raw_link:match("#(.*)$") or ""
  local without_fragment = raw_link:gsub("#.*$", "")
  local base, query = without_fragment, ""
  if without_fragment:find("?", 1, true) then
    base = without_fragment:match("^(.-)%?") or without_fragment
    query = without_fragment:match("%?(.*)$") or ""
  end
  local scheme, body = base:match("^([A-Za-z][A-Za-z0-9+.-]*)://(.+)$")
  return (scheme or ""):lower(), body or "", query, fragment
end

local function parse_hostport(hostport, fallback_port)
  local address, port
  if hostport:match("^%[") then
    address, port = hostport:match("^%[([^%]]+)%]:(.+)$")
    if not address then
      address = hostport:match("^%[([^%]]+)%]$")
      port = fallback_port
    end
  else
    address, port = hostport:match("^([^:]+):(.+)$")
    if not address then
      address = hostport
      port = fallback_port
    end
  end
  port = tostring(port or fallback_port or "443")
  local first_port = tonumber(port:match("^(%d+)") or "")
  return trim(address), first_port or tonumber(fallback_port) or 443, port
end

function M.parse(line)
  local raw_link, external_comment = split_link_comment(line)
  local scheme, body, query, fragment = split_uri(raw_link)
  if scheme ~= "vless" and scheme ~= "hysteria2" and scheme ~= "hy2" then
    return nil, "unsupported scheme"
  end

  local authority = (body or ""):gsub("/.*$", "")
  local userinfo, hostport = authority:match("^(.-)@(.+)$")
  if not hostport then
    userinfo = ""
    hostport = authority
  end
  local params = parse_query(query)
  local remarks = urldecode(fragment)
  if remarks == "" then remarks = external_comment end

  if scheme == "vless" then
    local address, port = parse_hostport(hostport, "443")
    if trim(userinfo) == "" or address == "" then return nil, "invalid vless link" end
    local security = trim(params.security or "")
    return {
      protocol = "vless",
      raw_link = raw_link,
      remarks = remarks,
      uuid = urldecode(userinfo),
      address = address,
      port = port,
      encryption = trim(params.encryption or "none"),
      flow = trim(params.flow or ""),
      network = trim(params.type or params.network or "tcp"),
      security = security,
      sni = trim(params.sni or params.serverName or params.host or ""),
      fp = trim(params.fp or params.fingerprint or ""),
      pbk = trim(params.pbk or params.publicKey or ""),
      sid = trim(params.sid or params.shortId or ""),
      spx = trim(params.spx or params.spiderX or "/"),
      header_type = trim(params.headerType or "none"),
      path = trim(params.path or ""),
      host = trim(params.host or ""),
      service_name = trim(params.serviceName or ""),
      mode = trim(params.mode or ""),
      alpn = split_csv(params.alpn or ""),
      allow_insecure = (params.allowinsecure == "1" or params.allowInsecure == "1" or tostring(params.allowInsecure or ""):lower() == "true")
    }
  end

  local address, port, port_raw = parse_hostport(hostport, "443")
  if address == "" then return nil, "invalid hysteria2 link" end
  local auth = urldecode(userinfo or "")
  if auth == "" then auth = trim(params.auth or params.password or "") end
  return {
    protocol = "hy2",
    raw_link = raw_link,
    remarks = remarks,
    auth = auth,
    address = address,
    port = port,
    port_raw = port_raw,
    sni = trim(params.sni or ""),
    insecure = (params.insecure == "1" or tostring(params.insecure or ""):lower() == "true"),
    pin_sha256 = trim(params.pinSHA256 or params.pinsha256 or ""),
    ech = trim(params.ech or ""),
    alpn = split_csv(params.alpn or ""),
    obfs = trim(params.obfs or ""),
    obfs_password = trim(params["obfs-password"] or params.obfsPassword or "")
  }
end

function M.load_first(path)
  local fh = io.open(path, "r")
  if not fh then return nil, "unable to read links file" end
  for line in fh:lines() do
    local parsed = M.parse(line)
    if parsed then fh:close(); return parsed end
  end
  fh:close()
  return nil, "no supported proxy links found"
end

function M.load_all(path)
  local out = {}
  local fh = io.open(path, "r")
  if not fh then return out end
  for line in fh:lines() do
    local parsed = M.parse(line)
    if parsed then out[#out + 1] = parsed end
  end
  fh:close()
  return out
end

M.trim = trim
M.urldecode = urldecode
M.urlencode = urlencode

return M
