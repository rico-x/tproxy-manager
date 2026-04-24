module("luci.controller.tproxy_manager", package.seeall)

function index()
    if not nixio.fs.access("/etc/config/tproxy-manager") then
        entry({"admin","network","tproxy_manager"}, firstchild(), _("TPROXY Manager"), 90)
    end
    -- Use "form" action because the model returns a SimpleForm
    entry({"admin","network","tproxy_manager"}, form("tproxy_manager/manage"), _("TPROXY Manager"), 90).leaf = true
end