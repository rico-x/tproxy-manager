module("luci.controller.tproxy_manager", package.seeall)

local fs = require "nixio.fs"
local sys = require "luci.sys"
local http = require "luci.http"
local uci = require("luci.model.uci").cursor()
local xml = require "luci.xml"
local _ = require "luci.model.cbi.tproxy_manager.i18n"
local share = require "tproxy_manager.subscription_share"
local utils = require "luci.model.cbi.tproxy_manager.utils" -- also seeds math.random() on load

local pcdata = xml.pcdata

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
    for __, key in ipairs(keys) do
        local value = http.getenv(key)
        if value and env[key] == nil then env[key] = value end
    end
    return env
end

-- const_time_eq: compares strings without an early exit on the first
-- mismatching byte (unlike "a ~= b", which on most Lua runtimes falls
-- through to a C-level memcmp with an early exit). This is the only
-- authorization check for this HTTP endpoint, which is reachable without
-- a LuCI login, so it's worth closing the timing leak of the matching
-- token prefix length here.
local function const_time_eq(a, b)
    a = tostring(a or "")
    b = tostring(b or "")
    if #a ~= #b then return false end
    local diff = 0
    for i = 1, #a do
        if a:byte(i) ~= b:byte(i) then diff = diff + 1 end
    end
    return diff == 0
end

-- action_happ_capture is a token-gated but pre-login (public) endpoint that
-- writes whatever body it receives straight to a log file - bound what
-- actually lands on disk regardless of what the caller sends.
local MAX_CAPTURE_BODY_BYTES = 64 * 1024

local function request_body()
    if type(http.content) == "function" then
        local ok, body = pcall(http.content)
        if ok and body then
            if #body > MAX_CAPTURE_BODY_BYTES then
                return body:sub(1, MAX_CAPTURE_BODY_BYTES) ..
                    string.format("\n... [truncated, request body exceeded %d bytes]", MAX_CAPTURE_BODY_BYTES)
            end
            return body
        end
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
    if not enabled or token == "" or expected == "" or not const_time_eq(token, expected) or os.time() > until_ts then
        if http.status then http.status(403, "Forbidden") end
        http.write("capture endpoint is disabled or token expired\n")
        return
    end

    -- Body size is gated on the DECLARED Content-Length before http.content()
    -- is ever called, so an oversized request is never buffered in memory.
    -- A body-bearing request without a declared length (chunked) is refused
    -- with 411 rather than read blindly - the capture flow only ever sees
    -- small, well-formed subscription requests from a real client app.
    -- Any Transfer-Encoding is refused outright, even alongside a
    -- Content-Length: a chunked body's real size is unknown until it has
    -- been read, and accepting both invites request-smuggling style
    -- disagreements about which one wins. Real Happ clients always send a
    -- plain, length-declared request.
    if trim(http.getenv("HTTP_TRANSFER_ENCODING")) ~= "" then
        if http.status then http.status(411, "Length Required") end
        http.write("chunked transfer encoding is not accepted\n")
        return
    end

    local method_now = http.getenv("REQUEST_METHOD") or "GET"
    local raw_len = trim(http.getenv("CONTENT_LENGTH"))
    local declared_len = nil
    if raw_len ~= "" then
        -- Must be a plain non-negative integer: tonumber() alone would
        -- happily accept "-5", "1.5", "0x10" or " 12 ", and a negative or
        -- fractional length would slip past a naive `> MAX` comparison.
        if not raw_len:match("^%d+$") then
            if http.status then http.status(400, "Bad Request") end
            http.write("malformed Content-Length\n")
            return
        end
        declared_len = tonumber(raw_len)
    end

    local body_bearing = (method_now == "POST" or method_now == "PUT" or method_now == "PATCH")
    if body_bearing and declared_len == nil then
        if http.status then http.status(411, "Length Required") end
        http.write("request must declare Content-Length\n")
        return
    end
    -- Method-independent on purpose: a GET carrying an oversized body must
    -- not slip through just because GET is not normally body-bearing.
    if declared_len and declared_len > MAX_CAPTURE_BODY_BYTES then
        if http.status then http.status(413, "Payload Too Large") end
        http.write("request body too large\n")
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
    for __, key in ipairs(keys) do
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
    local payload = table.concat(lines, "\n")
    -- secure_write: exclusive O_CREAT|O_EXCL temp at 0600, checked write and
    -- promote. A pre-planted symlink at the log path can no longer make this
    -- root process overwrite someone else's file.
    local wrote = utils.secure_write(log_path, payload)
    -- Only report success if the log actually landed: the whole point of
    -- this endpoint is that the user then reads the captured request back
    -- in LuCI, and an "OK" over a failed write would send them looking for
    -- data that was never stored.
    local st = fs.stat(log_path)
    if not wrote or not st or st.type ~= "reg" or (st.size or 0) ~= #payload then
        if http.status then http.status(500, "Internal Server Error") end
        http.write("failed to store the captured request\n")
        return
    end
    http.write("OK\n")
end

local function write_not_found()
    if http.status then http.status(404, "Not Found") end
    http.prepare_content("text/plain; charset=utf-8")
    http.write("not found\n")
end

-- action_backup_export / action_backup_upload live under the "admin"
-- dispatcher prefix (see index()) so they inherit LuCI's normal session
-- auth, unlike action_happ_capture/action_subscription_share above which
-- are deliberately public and gate themselves with their own token.

function action_backup_export()
    local disp = require "luci.dispatcher"
    local backup = require "tproxy_manager.backup"
    local archive, err = backup.export()
    if not archive then
        if http.status then http.status(500, "Internal Server Error") end
        http.prepare_content("text/plain; charset=utf-8")
        http.write("backup export failed: " .. tostring(err) .. "\n")
        return
    end

    local data = fs.readfile(archive) or ""
    -- Removes the exclusive directory the archive lives in, not just the file.
    backup.discard_export(archive)
    local fname = string.format("tproxy-manager-backup-%s.tar.gz", os.date("%Y%m%d-%H%M%S"))

    if http.header then
        http.header("Content-Disposition", string.format('attachment; filename="%s"', fname))
        http.header("Cache-Control", "no-store")
    end
    http.prepare_content("application/gzip")
    http.write(data)
end

-- LuCI's own CSRF token, already issued per session by the dispatcher for
-- every authenticated admin request (luci.dispatcher.test_post_security()
-- checks the same field) - confirmed non-empty on a real session on this
-- router rather than assumed. Reusing it means this endpoint rides the same
-- mechanism as the rest of LuCI instead of a second, home-grown one.
local function csrf_token()
    local disp = require "luci.dispatcher"
    return tostring((disp.context and disp.context.authtoken) or "")
end

-- Renders the standalone upload form. Deliberately a plain, self-contained
-- HTML page (not the LuCI CBI theme) - this endpoint has to control the
-- exact moment the multipart body is parsed (see action_backup_upload), so
-- it cannot be folded into the tproxy_manager CBI page: that page's model
-- (manage.lua) already calls http.formvalue() before any tab module runs,
-- which would parse the body without our file handler in place first.
local function render_backup_upload_form(err_msg)
    local disp = require "luci.dispatcher"
    http.prepare_content("text/html; charset=utf-8")
    local msg_html = ""
    if err_msg and err_msg ~= "" then
        msg_html = "<div style='padding:.6rem 1rem;margin-bottom:1rem;border:1px solid #fecaca;" ..
            "background:#fef2f2;color:#b91c1c;border-radius:.4rem'>" .. pcdata(err_msg) .. "</div>"
    end
    http.write(([[<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>%s</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:sans-serif;max-width:560px;margin:3rem auto;padding:0 1rem;color:#111}
.cbi-button{padding:.45rem 1rem;border-radius:.4rem;border:1px solid #999;background:#f3f4f6;cursor:pointer;font-size:1rem}
input[type=file]{margin:1rem 0;display:block}
a{color:#2563eb}
</style></head>
<body>
<h3>%s</h3>
%s
<form method="post" enctype="multipart/form-data">
<input type="hidden" name="backup_submit" value="1">
<input type="hidden" name="token" value="%s">
<input type="file" name="backup_file" accept=".gz,.tgz" required>
<button class="cbi-button" type="submit">%s</button>
</form>
<p><a href="%s">%s</a></p>
</body></html>]]):format(
        pcdata(_("Restore tproxy-manager backup")),
        pcdata(_("Restore tproxy-manager backup")),
        msg_html,
        pcdata(csrf_token()),
        pcdata(_("Upload and show changes")),
        disp.build_url("admin", "network", "tproxy_manager") .. "?tab=tproxy",
        pcdata(_("Cancel"))
    ))
end

function action_backup_upload()
    local disp = require "luci.dispatcher"
    -- Loaded before setfilehandler purely for its MAX_ARCHIVE_BYTES constant
    -- and extract_pending() later - require() itself only defines functions,
    -- it never touches http.formvalue()/http.content(), so it is safe to do
    -- before the file handler registration below.
    local backup = require "tproxy_manager.backup"

    -- Must be the very first thing that can trigger body parsing: once any
    -- http.formvalue()/http.content() call happens without this handler in
    -- place, the multipart body is already consumed and a file part's
    -- content is lost for good.
    -- Prefix comes from backup.lua so cleanup_stale() reliably sweeps these
    -- if the client aborts mid-upload and this handler never reaches its
    -- own cleanup.
    -- Method is checked FIRST: the private upload directory used to be
    -- created before this point, so every GET that merely rendered the form
    -- left an empty directory behind in /tmp.
    local method = http.getenv("REQUEST_METHOD") or "GET"
    if method ~= "POST" then
        render_backup_upload_form(nil)
        return
    end

    -- The upload lands inside an exclusively-created 0700 directory: /tmp is
    -- world-writable, so a plain io.open() on a predictable path could be
    -- redirected through a pre-planted symlink, or the file swapped between
    -- our writes. Inside a private directory nobody else can look it up.
    local upload_dir = utils.private_tmpdir("/tmp/" .. backup.UPLOAD_PREFIX .. "x")
    if not upload_dir then
        if http.status then http.status(500, "Internal Server Error") end
        render_backup_upload_form(_("Failed to process the uploaded backup."))
        return
    end
    local upload_path = upload_dir .. "/upload.tar.gz"
    local fh, received, written, oversize = nil, false, 0, false
    http.setfilehandler(function(field, chunk, eof)
        if not field or field.name ~= "backup_file" then return end
        if not fh then fh = utils.create_exclusive(upload_path) end
        if fh and chunk and not oversize then
            written = written + #chunk
            if written > backup.MAX_ARCHIVE_BYTES then
                -- Stop writing further chunks once the limit is crossed; the
                -- client's upload still finishes (the multipart parser has
                -- to consume the rest of the body regardless), but nothing
                -- more is spent writing it to tmpfs, and the partial file
                -- is discarded below without ever reaching extract_pending().
                oversize = true
                fh:close()
                fh = nil
                fs.remove(upload_path)  -- inside our private dir; removed with it in finish()
            else
                fh:write(chunk)
                received = true
            end
        end
        if eof and fh then fh:close(); fh = nil end
    end)


    -- Forces the body (and therefore our file handler) to run now.
    http.formvalue("backup_submit")
    if fh then fh:close() end

    -- Single cleanup point covering every exit path below: wrong/expired
    -- token, empty file, oversized upload, a failed extract_pending(), and
    -- the success path itself all remove the raw upload the same way -
    -- nothing is left behind on tmpfs regardless of which branch returns.
    local STATUS_TEXT = { [403] = "Forbidden", [413] = "Payload Too Large" }
    local function finish(render_err, status_code)
        sys.call("rm -rf " .. utils.shellescape(upload_dir) .. " >/dev/null 2>&1")
        if render_err ~= nil then
            if status_code and http.status then http.status(status_code, STATUS_TEXT[status_code] or "Error") end
            render_backup_upload_form(render_err)
        end
    end

    local expected_token = csrf_token()
    if expected_token == "" or http.formvalue("token") ~= expected_token then
        finish(_("Session validation failed, please reload this page and try again."), 403)
        return
    end

    if oversize then
        finish(string.format(_("Backup file is too large (max %d MiB)."), backup.MAX_ARCHIVE_BYTES / 1024 / 1024), 413)
        return
    end

    if not received or not fs.access(upload_path) then
        finish(_("Please choose a backup file to upload."))
        return
    end

    sys.call("chmod 0600 " .. utils.shellescape(upload_path) .. " >/dev/null 2>&1")

    local token, err = backup.extract_pending(upload_path)
    if not token then
        finish(err or _("Failed to process the uploaded backup."), err and err:find("too large", 1, true) and 413 or nil)
        return
    end

    finish(nil)
    http.redirect(disp.build_url("admin", "network", "tproxy_manager") ..
        "?tab=tproxy&backup_token=" .. http.urlencode(token))
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

    -- FAIL CLOSED. This used to require a token only when auth_mode was
    -- literally "token": an absent or unrecognised value fell through to a
    -- public endpoint, so a config predating the auth-mode option served the
    -- whole proxy list to anyone who found the URL. The only value that ever
    -- disables the check is an explicit "public".
    local auth_mode = trim(uci:get(PKG, "main", "watchdog_share_auth_mode"))
    if auth_mode ~= "public" then
        local expected = trim(uci:get(PKG, "main", "watchdog_share_token"))
        local given = trim(path[4])
        -- const_time_eq (defined above for happ_capture) avoids leaking the
        -- token's length/prefix through response-time differences, same
        -- reasoning as that endpoint.
        if expected == "" or not const_time_eq(given, expected) then
            write_not_found()
            return
        end
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
    entry({"admin","network","tproxy_manager_backup_export"}, call("action_backup_export"), nil).leaf = true
    entry({"admin","network","tproxy_manager_backup_upload"}, call("action_backup_upload"), nil).leaf = true
    entry({"tproxy-manager","happ-capture"}, call("action_happ_capture"), nil).leaf = true
    entry({"tproxy-manager","subscription"}, call("action_subscription_share"), nil).leaf = true
end
