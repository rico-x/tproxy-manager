#!/usr/bin/lua

local jsonc = require "luci.jsonc"
local parse = require "tproxy_manager.proxy_parse"

local function usage()
  io.stderr:write([[
Usage:
  proxy2singbox.lua -r <links_file> --outbounds [outbound templates]
  proxy2singbox.lua -r <links_file> --test --port <port> [--template <file>] [outbound templates]
  proxy2singbox.lua -r <links_file> --batch --ports <file> [--template <file>] [outbound templates]
  proxy2singbox.lua -r <links_file> --runtime --tproxy-port <port> [outbound templates]

Outbound templates:
  --vless-template <file>  JSONC object merged into every generated VLESS outbound
  --hy2-template <file>    JSONC object merged into every generated Hysteria 2 outbound
]])
end

local render_template

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

local function is_array(value)
  if type(value) ~= "table" then return false end
  local count, max = 0, 0
  for key in pairs(value) do
    if type(key) ~= "number" or key < 1 or key % 1 ~= 0 then return false end
    count = count + 1
    if key > max then max = key end
  end
  return count > 0 and count == max
end

local function deep_copy(value)
  if type(value) ~= "table" then return value end
  local out = {}
  for key, item in pairs(value) do out[key] = deep_copy(item) end
  return out
end

-- Outbound templates are merge overlays, not probe layouts. The generated
-- native outbound remains the base, while every key supplied by the user wins;
-- nested objects merge recursively and arrays replace as a whole. This lets a
-- custom sing-box build add fields without having to duplicate every value that
-- comes from the subscription link.
local function deep_merge(base, patch)
  if type(patch) ~= "table" or is_array(patch) then return deep_copy(patch) end
  if type(base) ~= "table" or is_array(base) then base = {} end
  for key, value in pairs(patch) do
    if type(value) == "table" and not is_array(value)
      and type(base[key]) == "table" and not is_array(base[key]) then
      base[key] = deep_merge(base[key], value)
    else
      base[key] = deep_copy(value)
    end
  end
  return base
end

local function apply_outbound_template(path, link, tag, generated)
  if not path then return generated end
  local text = render_template(path, {
    GENERATED_OUTBOUND = jsonc.stringify(generated, true),
    PORT = tostring(link.port),
    TLS = generated.tls and jsonc.stringify(generated.tls, true) or "null",
    TRANSPORT = generated.transport and jsonc.stringify(generated.transport, true) or "null",
    OBFS = generated.obfs and jsonc.stringify(generated.obfs, true) or "null",
  }, {
    TAG = tag, ADDRESS = link.address, UUID = link.uuid or "", FLOW = link.flow or "",
    PASSWORD = link.auth or "", SERVER_NAME = link.sni or "",
  })
  local ok, overlay = pcall(jsonc.parse, text)
  if not ok or type(overlay) ~= "table" or is_array(overlay) then
    io.stderr:write("invalid sing-box outbound template " .. tostring(path) .. "\n")
    os.exit(1)
  end
  return deep_merge(generated, overlay)
end

local function outbound_for(link, tag, templates)
  templates = templates or {}
  if link.protocol == "hy2" then
    return apply_outbound_template(templates.hy2, link, tag, hy2_outbound(link, tag))
  end
  return apply_outbound_template(templates.vless, link, tag, vless_outbound(link, tag))
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
    -- Exit 3, not 1: the watchdog has to tell "this engine cannot run this link"
    -- from "generating the config failed". The first is a link the ACTIVE engine
    -- does not support and must be reported as such -- marking it dead puts it on
    -- cooldown and hides it, as if the server were down.
    os.exit(3)
  end
  return supported
end

local function outbounds(links, templates)
  local out = {}
  for i, link in ipairs(links) do
    out[#out + 1] = outbound_for(link, i == 1 and "proxy" or ("proxy-" .. tostring(i)), templates)
  end
  out[#out + 1] = { type = "direct", tag = "direct" }
  out[#out + 1] = { type = "block", tag = "block" }
  return out
end

local function test_config(links, port, templates)
  return {
    log = { level = "warn" },
    inbounds = {
      { type = "socks", tag = "socks-in", listen = "127.0.0.1", listen_port = port, users = {} }
    },
    outbounds = outbounds(links, templates),
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

local function runtime_config(links, port, templates)
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
    outbounds = outbounds(links, templates),
    route = {
      rules = route_rules,
      final = final
    }
  }
end

-- A template makes the layout the user's rather than ours; without one the
-- built-in one is used, exactly as before these settings became real.
--
-- sing-box configs are JSON, so a placeholder that stands for a whole array or a
-- number is written as a STRING in the template ("__OUTBOUNDS__") and the quotes
-- are replaced along with it. That is what keeps the template itself valid JSON
-- and editable in the UI's JSON editor.
render_template = function(path, structural, scalars)
  local fh = io.open(path, "r")
  if not fh then
    io.stderr:write("cannot read template " .. tostring(path) .. "\n")
    os.exit(1)
  end
  local text = fh:read("*a") or ""
  fh:close()
  for key, value in pairs(structural) do
    text = text:gsub('"__' .. key .. '__"', (tostring(value):gsub("%%", "%%%%")))
  end
  for key, value in pairs(scalars) do
    -- Through the JSON encoder, so a tag containing a quote cannot break out of
    -- its string and turn the config into something else.
    local encoded = jsonc.stringify(tostring(value))
    text = text:gsub('"__' .. key .. '__"', (encoded:gsub("%%", "%%%%")))
    text = text:gsub("__" .. key .. "__", (tostring(value):gsub("%%", "%%%%")))
  end
  return text
end

local function emit_rendered(text)
  io.write(text)
  if text:sub(-1) ~= "\n" then io.write("\n") end
end

-- One process, one inbound per link, each routed to its own outbound. Probing 60
-- links one process at a time is what made a full scan take minutes.
local function batch_config(items, templates)
  local ins, outs, rules = {}, {}, {}
  for _, item in ipairs(items) do
    local tag = "probe-" .. tostring(item.port)
    ins[#ins + 1] = {
      type = "mixed", tag = tag .. "-in", listen = "127.0.0.1", listen_port = item.port
    }
    outs[#outs + 1] = outbound_for(item.link, tag, templates)
    rules[#rules + 1] = { inbound = { tag .. "-in" }, outbound = tag }
  end
  outs[#outs + 1] = { type = "direct", tag = "direct" }
  outs[#outs + 1] = { type = "block", tag = "block" }
  return {
    log = { level = "warn" },
    inbounds = ins,
    outbounds = outs,
    -- Anything not matched by a rule goes DIRECT and fails the probe, rather than
    -- silently measuring a direct connection and reporting the link alive.
    route = { rules = rules, final = "direct" }
  }
end

-- TSV: port<TAB>link, one probe per line.
local function load_ports(path)
  local fh = io.open(path, "r")
  if not fh then
    io.stderr:write("cannot read ports file " .. tostring(path) .. "\n")
    os.exit(1)
  end
  local out = {}
  for line in fh:lines() do
    local port, raw = line:match("^(%d+)\t(.+)$")
    if port then
      local link = parse.parse(raw)
      -- The same transport gate the single-link path applies. Without it batch
      -- mode emitted an outbound with the transport silently dropped, and the
      -- probe then measured a connection sing-box could never actually make --
      -- it failed at runtime with "unknown version", reported as a dead server.
      local reason = link and unsupported_reason(link)
      if link and not reason then
        out[#out + 1] = { port = tonumber(port), link = link }
      elseif link then
        -- Machine-readable so the caller can mark exactly these links unsupported
        -- instead of failing the whole chunk.
        io.stderr:write("unsupported-port: " .. port .. " " .. reason .. "\n")
      end
    end
  end
  fh:close()
  if #out == 0 then
    io.stderr:write("no supported proxy links found (all links were unsupported)\n")
    os.exit(3)
  end
  return out
end

local args = {
  links_file = nil, mode = nil, port = nil, template = nil, ports_file = nil,
  vless_template = nil, hy2_template = nil,
}
local i = 1
while i <= #arg do
  local a = arg[i]
  if a == "-r" then i = i + 1; args.links_file = arg[i]
  elseif a == "--outbounds" then args.mode = "outbounds"
  elseif a == "--test" then args.mode = "test"
  elseif a == "--runtime" then args.mode = "runtime"
  elseif a == "--batch" then args.mode = "batch"
  elseif a == "--port" or a == "--tproxy-port" then i = i + 1; args.port = tonumber(arg[i])
  elseif a == "--template" then i = i + 1; args.template = arg[i]
  elseif a == "--vless-template" then i = i + 1; args.vless_template = arg[i]
  elseif a == "--hy2-template" then i = i + 1; args.hy2_template = arg[i]
  elseif a == "--ports" then i = i + 1; args.ports_file = arg[i]
  else usage(); os.exit(1) end
  i = i + 1
end

if not args.mode then usage(); os.exit(1) end
local outbound_templates = { vless = args.vless_template, hy2 = args.hy2_template }

if args.mode == "batch" then
  if not args.ports_file then usage(); os.exit(1) end
  local items = load_ports(args.ports_file)
  local data = batch_config(items, outbound_templates)
  if args.template then
    local ins, outs, rules = {}, {}, {}
    for _, entry in ipairs(data.inbounds) do ins[#ins + 1] = entry end
    for _, entry in ipairs(data.outbounds) do outs[#outs + 1] = entry end
    for _, entry in ipairs(data.route.rules) do rules[#rules + 1] = entry end
    emit_rendered(render_template(args.template, {
      BATCH_INBOUNDS = jsonc.stringify(clean_nil(ins), true),
      BATCH_OUTBOUNDS = jsonc.stringify(clean_nil(outs), true),
      BATCH_RULES = jsonc.stringify(clean_nil(rules), true),
    }, {}))
  else
    print(jsonc.stringify(clean_nil(data), true))
  end
  return
end

if not args.links_file then usage(); os.exit(1) end
local links = load(args.links_file)
if args.mode == "test" and args.template then
  emit_rendered(render_template(args.template, {
    OUTBOUNDS = jsonc.stringify(clean_nil(outbounds(links, outbound_templates)), true),
    TEST_PORT = tostring(args.port or 10881),
  }, {
    OUTBOUND_TAG = "proxy",
  }))
  return
end
local data
if args.mode == "outbounds" then
  data = outbounds(links, outbound_templates)
elseif args.mode == "test" then
  data = test_config(links, args.port or 10881, outbound_templates)
else
  data = runtime_config(links, args.port or 61219, outbound_templates)
end
print(jsonc.stringify(clean_nil(data), true))
