module("luci.controller.tproxy_manager", package.seeall)

local fs = require "nixio.fs"
local http = require "luci.http"
local uci = require("luci.model.uci").cursor()
local _ = require "luci.model.cbi.tproxy_manager.i18n"
local share = require "tproxy_manager.subscription_share"

local PKG = "tproxy-manager"
local DEFAULT_LINKS_FILE = "/etc/tproxy-manager/watchdog.links"
local DEFAULT_SHARE_FILE = "/etc/tproxy-manager/watchdog-share.json"

local function trim(value)
    return tostring(value or ""):gsub("\r", ""):gsub("^%s+", ""):gsub("%s+$", "")
end

local function header_name(env_name)
    local name = env_name:gsub("^HTTP_", ""):gsub("_", " "):lower()
    name = name:gsub("(%S+)", function(part)
        return part:sub(1, 1):upper() .. part:sub(2)
    end)
    return name:gsub(" ", "-")
end

local function request_env()
    local ok, env = pcall(http.getenv)
    if ok and type(env) == "table" then
        env = env
    else
        env = {}
    end
    local keys = {
        "REQUEST_METHOD", "REQUEST_URI", "SERVER_PROTOCOL", "REMOTE_ADDR",
        "CONTENT_TYPE", "CONTENT_LENGTH", "HTTP_HOST", "HTTP_USER_AGENT",
        "HTTP_ACCEPT", "HTTP_ACCEPT_LANGUAGE", "HTTP_ACCEPT_ENCODING",
        "HTTP_CONNECTION", "HTTP_X_DEVICE_OS", "HTTP_X_DEVICE_LOCALE",
        "HTTP_X_DEVICE_MODEL", "HTTP_X_VER_OS", "HTTP_X_HWID",
        "HTTP_X_REAL_IP", "HTTP_X_FORWARDED_FOR",
    }
    for _, key in ipairs(keys) do
        local value = http.getenv(key)
        if value and env[key] == nil then env[key] = value end
    end
    return env
end

local function request_body()
    if type(http.content) == "function" then
        local ok, body = pcall(http.content)
        if ok and body then return body end
    end
    return ""
end

function action_happ_capture()
    local disp = require "luci.dispatcher"
    local token = trim((disp.context.requestpath or {})[3])
    local enabled = uci:get(PKG, "main", "watchdog_happ_capture_enabled") == "1"
    local expected = trim(uci:get(PKG, "main", "watchdog_happ_capture_token"))
    local until_ts = tonumber(uci:get(PKG, "main", "watchdog_happ_capture_until") or "0") or 0
    local log_path = trim(uci:get(PKG, "main", "watchdog_happ_capture_log"))
    if log_path == "" then log_path = "/tmp/tproxy-manager-happ-capture.log" end

    http.prepare_content("text/plain; charset=utf-8")
    if not enabled or token == "" or expected == "" or token ~= expected or os.time() > until_ts then
        if http.status then http.status(403, "Forbidden") end
        http.write("capture endpoint is disabled or token expired\n")
        return
    end

    local env = request_env()
    local method = env.REQUEST_METHOD or http.getenv("REQUEST_METHOD") or "-"
    local uri = env.REQUEST_URI or http.getenv("REQUEST_URI") or "-"
    local proto = env.SERVER_PROTOCOL or http.getenv("SERVER_PROTOCOL") or "HTTP/1.1"
    local lines = {
        string.format("[%s]", os.date("!%Y-%m-%dT%H:%M:%SZ")),
        string.format("%s %s %s", method, uri, proto),
        "",
        "HTTP HEADERS:",
    }

    local keys = {}
    for key in pairs(env) do
        if key:match("^HTTP_") or key == "CONTENT_TYPE" or key == "CONTENT_LENGTH" then
            keys[#keys + 1] = key
        end
    end
    table.sort(keys)
    for _, key in ipairs(keys) do
        local name = key
        if key:match("^HTTP_") then
            name = header_name(key)
        elseif key == "CONTENT_TYPE" then
            name = "Content-Type"
        elseif key == "CONTENT_LENGTH" then
            name = "Content-Length"
        end
        lines[#lines + 1] = name .. ": " .. tostring(env[key])
    end
    lines[#lines + 1] = ""
    lines[#lines + 1] = "REQUEST BODY:"
    lines[#lines + 1] = request_body()
    lines[#lines + 1] = ""

    local dir = log_path:match("^(.*)/[^/]+$")
    if dir and dir ~= "" then fs.mkdirr(dir) end
    fs.writefile(log_path, table.concat(lines, "\n"))
    http.write("OK\n")
end

local function write_not_found()
    if http.status then http.status(404, "Not Found") end
    http.prepare_content("text/plain; charset=utf-8")
    http.write("not found\n")
end

function action_subscription_share()
    local disp = require "luci.dispatcher"
    local path = disp.context.requestpath or {}
    local variant = trim(path[3]):lower()

    if not share.is_variant(variant) then
        write_not_found()
        return
    end

    if uci:get(PKG, "main", "watchdog_share_enabled") ~= "1" then
        write_not_found()
        return
    end

    local links_path = trim(uci:get(PKG, "main", "watchdog_links_file"))
    local share_file = trim(uci:get(PKG, "main", "watchdog_share_file"))
    if links_path == "" then links_path = DEFAULT_LINKS_FILE end
    if share_file == "" then share_file = DEFAULT_SHARE_FILE end

    local config = share.read_config(share_file)
    local entries = share.selected_entries(share.parse_links_file(links_path), config)
    local payload = share.render_payload(entries, variant)

    if http.header then
        http.header("Cache-Control", "no-store")
        http.header("Content-Disposition", string.format('inline; filename="tproxy-manager-subscription-%s.txt"', variant))
    end
    http.prepare_content("text/plain; charset=utf-8")
    http.write(payload)
end

function index()
    if not fs.access("/etc/config/tproxy-manager") then
        entry({"admin","network","tproxy_manager"}, firstchild(), _("TPROXY Manager"), 90)
    end
    -- Use "form" action because the model returns a SimpleForm
    entry({"admin","network","tproxy_manager"}, form("tproxy_manager/manage"), _("TPROXY Manager"), 90).leaf = true
    entry({"tproxy-manager","happ-capture"}, call("action_happ_capture"), nil).leaf = true
    entry({"tproxy-manager","subscription"}, call("action_subscription_share"), nil).leaf = true
end
