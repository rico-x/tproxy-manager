local i18n = require "luci.i18n"

if i18n.loadc then
  pcall(i18n.loadc, "tproxy-manager")
end

return i18n.translate or function(s)
  return s
end
