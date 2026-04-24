#!/usr/bin/lua

local function usage()
  io.stderr:write([[
Usage:
  vless2json.sh -r <links_file> -t <template_file>

Description:
  Reads the first valid VLESS link from <links_file>, applies its values to the
  JSON/JSONC template from <template_file> and prints rendered JSON to stdout.
]])
end

local function read_file(path)
  local f, err = io.open(path, "rb")
  if not f then
    return nil, err
  end
  local data = f:read("*a")
  f:close()
  return data or ""
end

local function trim(s)
  return (tostring(s or ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", ""))
end

local function strip_json_comments(s)
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
        while i <= n and s:sub(i, i) ~= "\n" do
          i = i + 1
        end
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

local function urldecode(s)
  s = tostring(s or ""):gsub("+", " ")
  return (s:gsub("%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end))
end

local function split_csv(value)
  local out = {}
  value = trim(value)
  if value == "" then
    return out
  end
  for item in (value .. ","):gmatch("([^,]*),") do
    item = trim(item)
    if item ~= "" then
      out[#out + 1] = item
    end
  end
  return out
end

local function deepcopy(value)
  if type(value) ~= "table" then
    return value
  end
  local out = {}
  for k, v in pairs(value) do
    out[deepcopy(k)] = deepcopy(v)
  end
  return out
end

local function scalar_to_string(v)
  local tv = type(v)
  if tv == "string" then
    return v
  elseif tv == "number" or tv == "boolean" then
    return tostring(v)
  end
  return nil
end

local function replace_placeholders(node, placeholders)
  local t = type(node)
  if t == "table" then
    local out = {}
    local is_array = (#node > 0)
    if is_array then
      for i = 1, #node do
        out[i] = replace_placeholders(node[i], placeholders)
      end
    else
      for k, v in pairs(node) do
        out[k] = replace_placeholders(v, placeholders)
      end
    end
    return out
  elseif t == "string" then
    if placeholders[node] ~= nil then
      return deepcopy(placeholders[node])
    end
    local rendered = node
    for key, value in pairs(placeholders) do
      local sv = scalar_to_string(value)
      if sv ~= nil then
        rendered = rendered:gsub(key, sv)
      end
    end
    return rendered
  end
  return node
end

local function parse_query(query)
  local out = {}
  for pair in (query or ""):gmatch("([^&]+)") do
    local k, v = pair:match("^([^=]+)=(.*)$")
    if k then
      out[urldecode(k)] = urldecode(v)
    else
      out[urldecode(pair)] = ""
    end
  end
  return out
end

local function parse_link_line(line)
  local value = trim(line)
  if value == "" or value:match("^#") then
    return nil
  end

  local raw_link, external_comment = value, ""
  if value:find(" # ", 1, true) then
    raw_link = value:match("^(.-) # ") or value
    external_comment = trim(value:match(" # (.*)$") or "")
  end
  raw_link = trim(raw_link)
  if not raw_link:match("^vless://") then
    return nil
  end
  return {
    raw_link = raw_link,
    external_comment = external_comment
  }
end

local function parse_vless(link_data)
  local raw_link = link_data.raw_link
  local fragment = raw_link:match("#(.*)$") or ""
  local without_fragment = raw_link:gsub("#.*$", "")
  local base, query = without_fragment, ""
  if without_fragment:find("?", 1, true) then
    base = without_fragment:match("^(.-)%?") or without_fragment
    query = without_fragment:match("%?(.*)$") or ""
  end

  local auth = base:match("^vless://(.+)$")
  if not auth then
    return nil, "link does not start with vless://"
  end

  local userinfo, hostport = auth:match("^(.-)@(.+)$")
  if not userinfo or not hostport then
    return nil, "missing userinfo or host"
  end

  local address, port
  if hostport:match("^%[") then
    address, port = hostport:match("^%[([^%]]+)%]:(%d+)$")
  else
    address, port = hostport:match("^([^:]+):(%d+)$")
  end
  if not address or not port then
    return nil, "invalid host:port"
  end

  local params = parse_query(query)
  local remarks = urldecode(fragment)
  if remarks == "" then
    remarks = link_data.external_comment or ""
  end

  local network = trim(params.type ~= "" and params.type or params.network or "tcp")
  local security = trim(params.security or "none")
  local sni = trim(params.sni ~= "" and params.sni or params.serverName or params.host or "")
  local fingerprint = trim(params.fp ~= "" and params.fp or params.fingerprint or "")
  local public_key = trim(params.pbk ~= "" and params.pbk or params.publicKey or "")
  local short_id = trim(params.sid ~= "" and params.sid or params.shortId or "")
  local spider_x = trim(params.spx ~= "" and params.spx or params.spiderX or "/")
  local header_type = trim(params.headerType or "none")
  local flow = trim(params.flow or "")
  local encryption = trim(params.encryption ~= "" and params.encryption or "none")
  local allow_insecure = trim(params.allowinsecure or params.allowInsecure or "0")
  local ws_path = trim(params.path or "")
  local ws_host = trim(params.host or "")
  local authority = trim(params.authority or "")
  local service_name = trim(params.serviceName or "")
  local grpc_mode = trim(params.mode or "gun")
  local alpn = trim(params.alpn or "")

  local alpn_array = split_csv(alpn)
  local allow_insecure_bool = (allow_insecure == "1" or allow_insecure:lower() == "true")

  return {
    remarks = remarks,
    address = address,
    port = tonumber(port),
    uuid = trim(userinfo),
    encryption = encryption,
    flow = flow,
    network = network ~= "" and network or "tcp",
    security = security ~= "" and security or "none",
    server_name = sni,
    fingerprint = fingerprint,
    public_key = public_key,
    short_id = short_id,
    spider_x = spider_x ~= "" and spider_x or "/",
    header_type = header_type ~= "" and header_type or "none",
    path = ws_path,
    host_header = ws_host,
    authority = authority,
    service_name = service_name,
    grpc_mode = grpc_mode,
    allow_insecure = allow_insecure,
    allow_insecure_bool = allow_insecure_bool,
    alpn = alpn,
    alpn_array = alpn_array
  }
end

local function load_first_link(path)
  local text, err = read_file(path)
  if not text then
    return nil, "unable to read links file: " .. tostring(err)
  end
  for line in (text .. "\n"):gmatch("([^\n]*)\n") do
    local parsed = parse_link_line(line)
    if parsed then
      return parsed
    end
  end
  return nil, "no valid VLESS links found"
end

local function load_template(path)
  local text, err = read_file(path)
  if not text then
    return nil, "unable to read template file: " .. tostring(err)
  end
  local ok_jsonc, jsonc = pcall(require, "luci.jsonc")
  if not ok_jsonc or not jsonc then
    return nil, "luci.jsonc is required"
  end
  local cleaned = strip_json_comments(text)
  local parsed = jsonc.parse(cleaned)
  if parsed == nil then
    return nil, "template is not valid JSON/JSONC"
  end
  return parsed, jsonc
end

local function build_placeholders(link)
  local remarks = link.remarks ~= "" and link.remarks or link.address
  return {
    ["__REMARKS__"] = remarks,
    ["__ADDRESS__"] = link.address,
    ["__HOST__"] = link.address,
    ["__PORT__"] = link.port,
    ["__UUID__"] = link.uuid,
    ["__USER_ID__"] = link.uuid,
    ["__ENCRYPTION__"] = link.encryption,
    ["__FLOW__"] = link.flow,
    ["__NETWORK__"] = link.network,
    ["__TYPE__"] = link.network,
    ["__SECURITY__"] = link.security,
    ["__SERVER_NAME__"] = link.server_name,
    ["__SNI__"] = link.server_name,
    ["__FINGERPRINT__"] = link.fingerprint,
    ["__FP__"] = link.fingerprint,
    ["__PUBLIC_KEY__"] = link.public_key,
    ["__PBK__"] = link.public_key,
    ["__SHORT_ID__"] = link.short_id,
    ["__SID__"] = link.short_id,
    ["__SPIDER_X__"] = link.spider_x,
    ["__HEADER_TYPE__"] = link.header_type,
    ["__PATH__"] = link.path,
    ["__WS_PATH__"] = link.path,
    ["__HOST_HEADER__"] = link.host_header,
    ["__AUTHORITY__"] = link.authority,
    ["__SERVICE_NAME__"] = link.service_name,
    ["__MODE__"] = link.grpc_mode,
    ["__ALLOW_INSECURE__"] = link.allow_insecure,
    ["__ALLOW_INSECURE_BOOL__"] = link.allow_insecure_bool,
    ["__ALPN__"] = link.alpn,
    ["__ALPN_ARRAY__"] = link.alpn_array
  }
end

local function parse_args(argv)
  local args = { links_file = nil, template_file = nil }
  local i = 1
  while i <= #argv do
    local arg = argv[i]
    if arg == "-r" then
      i = i + 1
      args.links_file = argv[i]
    elseif arg == "-t" then
      i = i + 1
      args.template_file = argv[i]
    elseif arg == "-h" or arg == "--help" then
      usage()
      os.exit(0)
    else
      return nil, "unknown argument: " .. tostring(arg)
    end
    i = i + 1
  end
  if not args.links_file or not args.template_file then
    return nil, "both -r and -t are required"
  end
  return args
end

local args, arg_err = parse_args(arg or {})
if not args then
  io.stderr:write("vless2json: " .. arg_err .. "\n")
  usage()
  os.exit(1)
end

local link_line, link_err = load_first_link(args.links_file)
if not link_line then
  io.stderr:write("vless2json: " .. link_err .. "\n")
  os.exit(1)
end

local parsed_link, parse_err = parse_vless(link_line)
if not parsed_link then
  io.stderr:write("vless2json: invalid VLESS link: " .. parse_err .. "\n")
  os.exit(1)
end

local template, jsonc_or_err = load_template(args.template_file)
if not template then
  io.stderr:write("vless2json: " .. tostring(jsonc_or_err) .. "\n")
  os.exit(1)
end

local placeholders = build_placeholders(parsed_link)
local rendered = replace_placeholders(deepcopy(template), placeholders)
local jsonc = jsonc_or_err
local output = jsonc.stringify(rendered, true)
if not output or output == "" then
  io.stderr:write("vless2json: failed to render JSON\n")
  os.exit(1)
end

io.write(output)
io.write("\n")
