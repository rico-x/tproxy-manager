#!/usr/bin/lua

local jsonc = require "luci.jsonc"
local parse = require "tproxy_manager.proxy_parse"

local function usage()
  io.stderr:write([[
Usage:
  proxy2singbox.lua -r <links_file> --outbounds
  proxy2singbox.lua -r <links_file> --test --port <port>
  proxy2singbox.lua -r <links_file> --runtime --tproxy-port <port>
]])
end

local function name_for(link, idx)
  local name = parse.trim(link.remarks)
  if name == "" then name = link.protocol .. "-" .. tostring(idx) end
  return name:gsub("[\r\n\t]", " ")
end

local function vless_outbound(link, tag)
  local ob = {
    type = "vless",
    tag = tag,
    server = link.address,
    server_port = link.port,
    uuid = link.uuid,
    flow = link.flow ~= "" and link.flow or nil
  }
  if link.security == "tls" or link.security == "reality" then
    ob.tls = {
      enabled = true,
      server_name = link.sni ~= "" and link.sni or nil,
      insecure = link.allow_insecure or nil,
      utls = link.fp ~= "" and { enabled = true, fingerprint = link.fp } or nil,
      reality = link.security == "reality" and {
        enabled = true,
        public_key = link.pbk ~= "" and link.pbk or nil,
        short_id = link.sid ~= "" and link.sid or nil
      } or nil
    }
  end
  if link.network == "ws" then
    ob.transport = {
      type = "ws",
      path = link.path ~= "" and link.path or nil,
      headers = link.host ~= "" and { Host = link.host } or nil
    }
  elseif link.network == "grpc" then
    ob.transport = {
      type = "grpc",
      service_name = link.service_name ~= "" and link.service_name or nil
    }
  end
  return ob
end

local function unsupported_reason(link)
  if link.protocol ~= "vless" then return nil end
  local network = parse.trim(link.network ~= "" and link.network or "tcp"):lower()
  if network == "tcp" or network == "ws" or network == "grpc" then
    return nil
  end
  return "unsupported sing-box VLESS transport: " .. network
end

local function hy2_outbound(link, tag)
  local ob = {
    type = "hysteria2",
    tag = tag,
    server = link.address,
    server_port = link.port,
    password = link.auth,
    tls = {
      enabled = true,
      server_name = link.sni ~= "" and link.sni or nil,
      insecure = link.insecure or nil
    }
  }
  if link.obfs ~= "" then
    ob.obfs = { type = link.obfs, password = link.obfs_password ~= "" and link.obfs_password or nil }
  end
  return ob
end

local function outbound_for(link, tag)
  if link.protocol == "hy2" then return hy2_outbound(link, tag) end
  return vless_outbound(link, tag)
end

local function clean_nil(value)
  if type(value) ~= "table" then return value end
  local out = {}
  for k, v in pairs(value) do
    if v ~= nil then out[k] = clean_nil(v) end
  end
  return out
end

local function load(path)
  local links = parse.load_all(path)
  if #links == 0 then
    io.stderr:write("no supported proxy links found\n")
    os.exit(1)
  end
  -- Ссылки приходят из внешней подписки: одна нетипичная запись (например,
  -- VLESS с network=kcp/quic) раньше обрывала генерацию конфига целиком через
  -- os.exit(1), оставляя пользователя без прокси вообще — вместо того чтобы
  -- пропустить только эту запись, как делает proxy2mihomo.lua. Пропускаем и
  -- продолжаем; полностью останавливаемся только если валидных ссылок не осталось.
  local supported = {}
  for _, link in ipairs(links) do
    local reason = unsupported_reason(link)
    if reason then
      io.stderr:write("skipping link: " .. reason .. "\n")
    else
      supported[#supported + 1] = link
    end
  end
  if #supported == 0 then
    io.stderr:write("no supported proxy links found (all links were unsupported)\n")
    os.exit(1)
  end
  return supported
end

local function outbounds(links)
  local out = {}
  for i, link in ipairs(links) do
    out[#out + 1] = outbound_for(link, i == 1 and "proxy" or ("proxy-" .. tostring(i)))
  end
  out[#out + 1] = { type = "direct", tag = "direct" }
  out[#out + 1] = { type = "block", tag = "block" }
  return out
end

local function test_config(links, port)
  return {
    log = { level = "warn" },
    inbounds = {
      { type = "socks", tag = "socks-in", listen = "127.0.0.1", listen_port = port, users = {} }
    },
    outbounds = outbounds(links),
    route = {
      rules = {
        { inbound = { "socks-in" }, outbound = "proxy" }
      },
      final = "proxy"
    }
  }
end

local function supports_udp(link)
  if not link then return false end
  return link.protocol == "hy2"
end

local function runtime_config(links, port)
  local route_rules
  local final
  if supports_udp(links[1]) then
    route_rules = {
      { inbound = { "mixed-in", "tproxy-in" }, outbound = "proxy" }
    }
    final = "proxy"
  else
    route_rules = {
      { inbound = { "mixed-in", "tproxy-in" }, network = "tcp", outbound = "proxy" },
      { inbound = { "mixed-in", "tproxy-in" }, network = "udp", outbound = "direct" }
    }
    final = "direct"
  end

  return {
    log = { level = "warn" },
    inbounds = {
      { type = "mixed", tag = "mixed-in", listen = "127.0.0.1", listen_port = 10808 },
      { type = "tproxy", tag = "tproxy-in", listen = "::", listen_port = port, sniff = true }
    },
    outbounds = outbounds(links),
    route = {
      rules = route_rules,
      final = final
    }
  }
end

local args = { links_file = nil, mode = nil, port = nil }
local i = 1
while i <= #arg do
  local a = arg[i]
  if a == "-r" then i = i + 1; args.links_file = arg[i]
  elseif a == "--outbounds" then args.mode = "outbounds"
  elseif a == "--test" then args.mode = "test"
  elseif a == "--runtime" then args.mode = "runtime"
  elseif a == "--port" or a == "--tproxy-port" then i = i + 1; args.port = tonumber(arg[i])
  else usage(); os.exit(1) end
  i = i + 1
end

if not args.links_file or not args.mode then usage(); os.exit(1) end
local links = load(args.links_file)
local data
if args.mode == "outbounds" then
  data = outbounds(links)
elseif args.mode == "test" then
  data = test_config(links, args.port or 10881)
else
  data = runtime_config(links, args.port or 61219)
end
print(jsonc.stringify(clean_nil(data), true))
