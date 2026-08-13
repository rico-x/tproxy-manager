#!/usr/bin/lua

local parse = require "tproxy_manager.proxy_parse"

local function usage()
  io.stderr:write([[
Usage:
  proxy2mihomo.lua -r <links_file> --provider [outbound templates]
  proxy2mihomo.lua -r <links_file> --test --port <port> [--template <file>] [outbound templates]
  proxy2mihomo.lua -r <links_file> --batch --ports <file> [--template <file>] [outbound templates]
  proxy2mihomo.lua -r <links_file> --runtime --tproxy-port <port> [outbound templates]

Outbound templates:
  --vless-template <file>  Native Mihomo YAML block for one VLESS proxy
  --hy2-template <file>    Native Mihomo YAML block for one Hysteria 2 proxy
]])
end

-- Always quoted. The old fast path emitted anything matching a "safe" character
-- class bare, and that class included "@" -- a YAML reserved indicator, so a remark
-- like "@home" produced `name: @home` and mihomo refused the file with "found
-- character that cannot start any token". Bare scalars also invite type coercion:
-- a name of "no" or "0755" would stop being a string.
--
-- A single-quoted YAML scalar can carry any printable text as long as "'" is
-- doubled, which is the one escape needed here. Control characters cannot appear
-- inside one at all, so they are folded to spaces before quoting.
local function q(value)
  value = tostring(value or ""):gsub("%c", " ")
  if value == "" then return "''" end
  return "'" .. value:gsub("'", "''") .. "'"
end

local function bool(value)
  return value and "true" or "false"
end

-- Mihomo keys proxies by name, so a name has to be unique within one config.
-- Remarks are not: two subscriptions routinely ship the same label, and mihomo
-- then rejects the whole file with "proxy ... is the duplicate name" -- every link
-- dead at once, including the ones with unique names.
--
-- The remark is still what the name is built from, because that is the string the
-- user recognises in mihomo's log and API. It is just no longer trusted to be
-- unique: a counter is appended until the name is free. Uniqueness therefore comes
-- from position in the list, which is stable across the provider, runtime, test and
-- batch renderings of the same list -- they must agree, since the group and the
-- listeners reference proxies by name.
--
-- One allocator per config, never a shared one: names only have to be unique
-- inside the file being written.
local function name_allocator()
  local used = {}
  return function(link, idx)
    -- Parenthesised: gsub returns the replacement count as a second value, and
    -- passing that straight into trim() hands it an argument it never asked for.
    local base = parse.trim((tostring(link.remarks or ""):gsub("%c", " ")))
    if base == "" then base = tostring(link.protocol or "proxy") .. "-" .. tostring(idx) end
    local name, n = base, 1
    -- Loops rather than appending once: "X" twice yields "X" and "X #2", and a
    -- third link legitimately named "X #2" then has to move as well.
    while used[name] do
      n = n + 1
      name = base .. " #" .. tostring(n)
    end
    used[name] = true
    return name
  end
end

-- Literal placeholder substitution is intentional: outbound templates are
-- native Mihomo YAML, not a second configuration language. Values that can come
-- from a proxy link are YAML-quoted before they reach this function.
local function render_template(path, values)
  local fh = io.open(path, "r")
  if not fh then return nil, "cannot read template " .. tostring(path) end
  local text = fh:read("*a") or ""
  fh:close()
  for key, value in pairs(values) do
    text = text:gsub("__" .. key .. "__", (tostring(value):gsub("%%", "%%%%")))
  end
  return text:gsub("%s+$", "")
end

local function rendered_or_exit(path, values)
  local text, err = render_template(path, values)
  if not text then
    io.stderr:write(tostring(err) .. "\n")
    os.exit(1)
  end
  return text
end

local function emit_vless(link, name, template)
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
  local generated = table.concat(out, "\n")
  if not template then return generated end

  local optional = {}
  if link.allow_insecure then optional[#optional + 1] = "    skip-cert-verify: true" end
  if link.flow ~= "" then optional[#optional + 1] = "    flow: " .. q(link.flow) end
  if link.sni ~= "" then optional[#optional + 1] = "    servername: " .. q(link.sni) end
  if link.fp ~= "" then optional[#optional + 1] = "    client-fingerprint: " .. q(link.fp) end
  local reality = ""
  if link.security == "reality" then
    local lines = { "    reality-opts:" }
    if link.pbk ~= "" then lines[#lines + 1] = "      public-key: " .. q(link.pbk) end
    if link.sid ~= "" then lines[#lines + 1] = "      short-id: " .. q(link.sid) end
    reality = table.concat(lines, "\n")
  end
  local transport = ""
  if link.network == "ws" then
    local lines = { "    ws-opts:" }
    if link.path ~= "" then lines[#lines + 1] = "      path: " .. q(link.path) end
    if link.host ~= "" then
      lines[#lines + 1] = "      headers:"
      lines[#lines + 1] = "        Host: " .. q(link.host)
    end
    transport = table.concat(lines, "\n")
  elseif link.network == "grpc" then
    local lines = { "    grpc-opts:" }
    if link.service_name ~= "" then lines[#lines + 1] = "      grpc-service-name: " .. q(link.service_name) end
    transport = table.concat(lines, "\n")
  end
  return rendered_or_exit(template, {
    GENERATED_OUTBOUND = generated,
    NAME = q(name), ADDRESS = q(link.address), PORT = tostring(link.port),
    UUID = q(link.uuid), NETWORK = q(link.network ~= "" and link.network or "tcp"),
    TLS = bool(link.security == "tls" or link.security == "reality"),
    OPTIONAL = table.concat(optional, "\n"), REALITY = reality, TRANSPORT = transport,
  })
end

local function emit_hy2(link, name, template)
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
  local generated = table.concat(out, "\n")
  if not template then return generated end
  local optional = {}
  if link.sni ~= "" then optional[#optional + 1] = "    sni: " .. q(link.sni) end
  if link.insecure then optional[#optional + 1] = "    skip-cert-verify: true" end
  if link.obfs ~= "" then optional[#optional + 1] = "    obfs: " .. q(link.obfs) end
  if link.obfs_password ~= "" then optional[#optional + 1] = "    obfs-password: " .. q(link.obfs_password) end
  return rendered_or_exit(template, {
    GENERATED_OUTBOUND = generated,
    NAME = q(name), ADDRESS = q(link.address), PORT = tostring(link.port),
    PASSWORD = q(link.auth), OPTIONAL = table.concat(optional, "\n"),
  })
end

local function emit_proxy(link, name, templates)
  templates = templates or {}
  if link.protocol == "hy2" then return emit_hy2(link, name, templates.hy2) end
  return emit_vless(link, name, templates.vless)
end

local function load(path)
  local links = parse.load_all(path)
  if #links == 0 then
    io.stderr:write("no supported proxy links found\n")
    -- Exit 3 means "the active engine cannot run these links", which the watchdog
    -- reports as unsupported rather than dead. Mihomo accepts every transport the
    -- parser produces, so in practice this only fires on an empty or unparsable
    -- list -- but the contract is the same for all three engines.
    os.exit(3)
  end
  return links
end

local function emit_provider(links, templates)
  local out = { "proxies:" }
  local allocate = name_allocator()
  for i, link in ipairs(links) do
    out[#out + 1] = emit_proxy(link, allocate(link, i), templates)
  end
  print(table.concat(out, "\n") .. "\n")
end

local function emit_runtime(links, port, mode, templates)
  local out = {
    "allow-lan: false",
    "bind-address: 127.0.0.1",
    -- rule, not global: in global mode Mihomo ignores `rules` entirely and sends
    -- everything through its built-in GLOBAL selector, whose default selection is
    -- DIRECT. The MATCH,TPROXY-MANAGER rule below was therefore dead, and both the
    -- probe and the live engine passed traffic straight out instead of through the
    -- proxy -- which made every link "fail" its check while sites reachable
    -- directly appeared to work.
    "mode: rule",
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
  local allocate = name_allocator()
  for i, link in ipairs(links) do
    local name = allocate(link, i)
    out[#out + 1] = emit_proxy(link, name, templates)
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

-- A probe template makes the service-only layout the package's explicit input.
-- layout below is used, which is what every install had before the four
-- watchdog_*_test_template_file settings became more than decoration.
--
-- Placeholders are substituted literally; a YAML block keeps its own indentation,
-- so a placeholder standing on its own line is replaced by the whole block.
local function emit_test(links, port, template, templates)
  if not template then return nil end
  local blocks, names = {}, {}
  local allocate = name_allocator()
  for i, link in ipairs(links) do
    local name = allocate(link, i)
    blocks[#blocks + 1] = emit_proxy(link, name, templates)
    names[#names + 1] = name
  end
  local text, err = render_template(template, {
    TEST_PORT = tostring(port),
    PROXIES = table.concat(blocks, "\n"),
    PROXY_NAME = q(names[1] or "proxy"),
  })
  if not text then
    io.stderr:write(tostring(err) .. "\n")
    os.exit(1)
  end
  io.write(text)
  if text:sub(-1) ~= "\n" then io.write("\n") end
  return true
end

-- One process, one listener per link, each listener pinned to its own proxy. The
-- point of batch mode: probing 60 links one process at a time is what made a full
-- scan take minutes.
local function emit_batch(links_by_port, template, templates)
  local listeners, proxies = {}, {}
  local allocate = name_allocator()
  for _, item in ipairs(links_by_port) do
    local name = allocate(item.link, item.index)
    proxies[#proxies + 1] = emit_proxy(item.link, name, templates)
    -- Listener-level `proxy:` is what binds a port to one outbound. Verified on a
    -- router: two listeners in one process exited through two different servers.
    listeners[#listeners + 1] = string.format(
      "  - name: probe-%d\n    type: mixed\n    port: %d\n    listen: 127.0.0.1\n    proxy: %s",
      item.port, item.port, q(name))
  end
  -- The rule set is a single DIRECT default, so a listener whose binding is not
  -- honoured goes out directly and FAILS its probe, rather than quietly measuring
  -- a direct connection and reporting the link alive -- the exact way mode: global
  -- used to make every link look broken while sites reachable directly worked.
  local rules = { "  - MATCH,DIRECT" }
  if template then
    local text, err = render_template(template, {
      BATCH_INBOUNDS = table.concat(listeners, "\n"),
      BATCH_PROXIES = table.concat(proxies, "\n"),
      BATCH_RULES = table.concat(rules, "\n"),
    })
    if not text then
      io.stderr:write(tostring(err) .. "\n")
      os.exit(1)
    end
    io.write(text)
    if text:sub(-1) ~= "\n" then io.write("\n") end
    return
  end
  local out = {
    "allow-lan: false",
    "bind-address: 127.0.0.1",
    "mode: rule",
    "log-level: warning",
    "ipv6: true",
    "listeners:",
    table.concat(listeners, "\n"),
    "proxies:",
    table.concat(proxies, "\n"),
    "rules:",
    "  - MATCH,DIRECT",
  }
  print(table.concat(out, "\n") .. "\n")
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
      if link then
        out[#out + 1] = { port = tonumber(port), link = link, index = #out + 1 }
      end
    end
  end
  fh:close()
  if #out == 0 then
    io.stderr:write("no supported proxy links found\n")
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
  elseif a == "--provider" then args.mode = "provider"
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
  emit_batch(load_ports(args.ports_file), args.template, outbound_templates)
  return
end
if not args.links_file then usage(); os.exit(1) end
local links = load(args.links_file)
if args.mode == "provider" then
  emit_provider(links, outbound_templates)
elseif args.mode == "test" and args.template then
  emit_test(links, args.port or 10881, args.template, outbound_templates)
else
  emit_runtime(links, args.port or 61219, args.mode, outbound_templates)
end
