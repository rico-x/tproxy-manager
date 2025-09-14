module("luci.controller.xray_tproxy", package.seeall)

function index()
	entry(
		{"admin", "network", "xray_tproxy"},
		form("xray_tproxy/manage"),
		_("TPROXY Manager"), 60
	).dependent = true
end
