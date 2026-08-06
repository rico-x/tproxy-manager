#!/usr/bin/lua

local parse = require "tproxy_manager.proxy_parse"

local function usage()
  io.stderr:write([[
Usage:
  proxy2mihomo.lua -r <links_file> --provider
  proxy2mihomo.lua -r <links_file> --test --port <port>
  proxy2mihomo.lua -r <links_file> --runtime --tproxy-port <port>
]])
end

local function q(value)
  value = tostring(value or "")
  if value == "" then return "''" end
  if value:match("^[A-Za-z0-9_./:@%-%+]+$") then return value end
  return "'" .. value:gsub("'", "''") .. "'"
end

local function bool(value)
  return value and "true" or "false"
end

local function proxy_name(link, idx)
  local name = parse.trim(link.remarks)
  if name == "" then name = link.protocol .. "-" .. tostring(idx) end
  name = name:gsub("[\r\n\t]", " ")
  return name
end

local function emit_vless(link, name)
  local out = {
    "  - name: " .. q(name),
    "    type: vless",
    "    server: " .. q(link.address),
    "    port: " .. tostring(link.port),
    "    uuid: " .. q(link.uuid),
    "    udp: true",
    "    network: " .. q(link.network ~= "" and link.network or "tcp"),
    "    tls: " .. bool(link.security == "tls" or link.security == "reality"),
  }
  -- allowInsecure из vless:// (proxy_parse.lua) — proxy2singbox.lua переносит
  -- его в tls.insecure, здесь этого не было: TLS-хендшейк с self-signed/reality
  -- сертификатом молча падал под Mihomo, хотя работал под sing-box/Xray.
  if link.allow_insecure then out[#out + 1] = "    skip-cert-verify: true" end
  if link.flow ~= "" then out[#out + 1] = "    flow: " .. q(link.flow) end
  if link.sni ~= "" then out[#out + 1] = "    servername: " .. q(link.sni) end
  if link.fp ~= "" then out[#out + 1] = "    client-fingerprint: " .. q(link.fp) end
  if link.security == "reality" then
    out[#out + 1] = "    reality-opts:"
    if link.pbk ~= "" then out[#out + 1] = "      public-key: " .. q(link.pbk) end
    if link.sid ~= "" then out[#out + 1] = "      short-id: " .. q(link.sid) end
  end
  if link.network == "ws" then
    out[#out + 1] = "    ws-opts:"
    if link.path ~= "" then out[#out + 1] = "      path: " .. q(link.path) end
    if link.host ~= "" then
      out[#out + 1] = "      headers:"
      out[#out + 1] = "        Host: " .. q(link.host)
    end
  elseif link.network == "grpc" then
    out[#out + 1] = "    grpc-opts:"
    if link.service_name ~= "" then out[#out + 1] = "      grpc-service-name: " .. q(link.service_name) end
  end
  return table.concat(out, "\n")
end

local function emit_hy2(link, name)
  local out = {
    "  - name: " .. q(name),
    "    type: hysteria2",
    "    server: " .. q(link.address),
    "    port: " .. tostring(link.port),
    "    password: " .. q(link.auth),
    "    udp: true",
  }
  if link.sni ~= "" then out[#out + 1] = "    sni: " .. q(link.sni) end
  if link.insecure then out[#out + 1] = "    skip-cert-verify: true" end
  if link.obfs ~= "" then out[#out + 1] = "    obfs: " .. q(link.obfs) end
  if link.obfs_password ~= "" then out[#out + 1] = "    obfs-password: " .. q(link.obfs_password) end
  return table.concat(out, "\n")
end

local function emit_proxy(link, idx)
  local name = proxy_name(link, idx)
  if link.protocol == "hy2" then return emit_hy2(link, name), name end
  return emit_vless(link, name), name
end

local function load(path)
  local links = parse.load_all(path)
  if #links == 0 then
    io.stderr:write("no supported proxy links found\n")
    os.exit(1)
  end
  return links
end

local function emit_provider(links)
  local out = { "proxies:" }
  for i, link in ipairs(links) do
    out[#out + 1] = emit_proxy(link, i)
  end
  print(table.concat(out, "\n") .. "\n")
end

local function emit_runtime(links, port, mode)
  local out = {
    "allow-lan: false",
    "bind-address: 127.0.0.1",
    "mode: global",
    "log-level: warning",
    "ipv6: true",
  }
  if mode == "test" then
    out[#out + 1] = "mixed-port: " .. tostring(port)
  else
    out[#out + 1] = "mixed-port: 10808"
    out[#out + 1] = "tproxy-port: " .. tostring(port)
  end
  out[#out + 1] = "proxies:"
  local names = {}
  for i, link in ipairs(links) do
    local block, name = emit_proxy(link, i)
    out[#out + 1] = block
    names[#names + 1] = name
  end
  out[#out + 1] = "proxy-groups:"
  out[#out + 1] = "  - name: TPROXY-MANAGER"
  out[#out + 1] = "    type: select"
  out[#out + 1] = "    proxies:"
  for _, name in ipairs(names) do out[#out + 1] = "      - " .. q(name) end
  out[#out + 1] = "rules:"
  out[#out + 1] = "  - MATCH,TPROXY-MANAGER"
  print(table.concat(out, "\n") .. "\n")
end

local args = { links_file = nil, mode = nil, port = nil }
local i = 1
while i <= #arg do
  local a = arg[i]
  if a == "-r" then i = i + 1; args.links_file = arg[i]
  elseif a == "--provider" then args.mode = "provider"
  elseif a == "--test" then args.mode = "test"
  elseif a == "--runtime" then args.mode = "runtime"
  elseif a == "--port" or a == "--tproxy-port" then i = i + 1; args.port = tonumber(arg[i])
  else usage(); os.exit(1) end
  i = i + 1
end

if not args.links_file or not args.mode then usage(); os.exit(1) end
local links = load(args.links_file)
if args.mode == "provider" then
  emit_provider(links)
else
  emit_runtime(links, args.port or 61219, args.mode)
end
