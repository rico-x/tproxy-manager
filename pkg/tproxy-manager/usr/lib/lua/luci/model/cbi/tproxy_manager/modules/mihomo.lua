local cbi = require "luci.cbi"
local SimpleSection, DummyValue, Button = cbi.SimpleSection, cbi.DummyValue, cbi.Button

-- ===== Mihomo-специфика локально =====
local fs   = require "nixio.fs"
local sys  = require "luci.sys"
local http = require "luci.http"
local disp = require "luci.dispatcher"
local xml  = require "luci.xml"
local pcdata = xml.pcdata

local MIHOMO_DIR      = "/etc/mihomo"
local MIHOMO_TEST_LOG = "/tmp/tproxy_manager_mihomo_test.log"

local function get_mihomo_bin()
  if fs.access("/usr/bin/mihomo") then return "/usr/bin/mihomo"
  elseif fs.access("/usr/sbin/mihomo") then return "/usr/sbin/mihomo"
  else return "mihomo" end
end
local MIHOMO_BIN = get_mihomo_bin()

local function atomic_write(path, data)
  data = (data or ""):gsub("\r\n","\n")
  local dir, base = path:match("^(.*)/([^/]+)$")
  local tmpdir = dir and dir or "/tmp"
  if dir and not fs.access(dir) then
    sys.call("mkdir -p '"..dir:gsub("'", "'\\''").."'")
  end
  local tmp = string.format("%s/.%s.%d.tmp", tmpdir, base or "tmp", math.random(1, 10^9))
  fs.writefile(tmp, data)
  fs.rename(tmp, path)
end

local function read_file(p)  return fs.readfile(p) or "" end
local function write_file(p, s) atomic_write(p, s or "") end

-- Только *.yaml (никаких *.yml)
local function list_yaml(dir)
  local t, it = {}, fs.dir(dir)
  if it then
    for name in it do
      if name:match("%.yaml$") then t[#t+1] = name end
    end
  end
  table.sort(t)
  return t
end

-- ensure Mihomo dir exists
do
  local st = fs.stat(MIHOMO_DIR)
  if not (st and st.type == "directory") then fs.mkdir(MIHOMO_DIR) end
end
-- ===== конец Mihomo-специфики =====

local function render(ctx)
  local m = ctx.m
  local fval, fval_last = ctx.fval, ctx.fval_last
  local self_url, redirect_here = ctx.self_url, ctx.redirect_here
  local combined_log, set_err, get_err, set_info, get_info =
    ctx.combined_log, ctx.set_err, ctx.get_err, ctx.set_info, ctx.get_info
  local service_block = ctx.service_block

  -- Toolbar handlers
  if http.formvalue("_refreshlog_mihomo") then set_err(nil); redirect_here("mihomo"); return m end
  if http.formvalue("_clearlog_mihomo") then
    sys.call("/etc/init.d/log restart >/dev/null 2>&1")
    set_err(nil); redirect_here("mihomo"); return m
  end
  if http.formvalue("_test_mihomo") then
    local config_file = fval_last("mihomo_file") or "config.yaml"
    sys.call(string.format("%s -t -f %q >%s 2>&1", MIHOMO_BIN, MIHOMO_DIR.."/"..config_file, MIHOMO_TEST_LOG))
    set_err(nil); redirect_here("mihomo"); return m
  end
  if http.formvalue("_clearlog_mihomo_config") then
    write_file(MIHOMO_TEST_LOG, ""); set_err(nil); redirect_here("mihomo"); return m
  end

  -- Статус Mihomo
  do
    local ss = m:section(SimpleSection, "Статус и управление сервисом Mihomo")
    service_block(ss, "mihomo", "Mihomo", "mihomo")
  end

  -- Combined log
  do
    local sl = m:section(SimpleSection)
    local log = sl:option(DummyValue, "_log_mihomo"); log.rawhtml = true
    function log.cfgvalue()
      return "<details><summary><strong>Общий лог (logread)</strong></summary>" ..
             "<div class='box editor-wrap'><pre style='white-space:pre-wrap;max-height:30rem;overflow:auto'>" ..
             pcdata(combined_log()) .. "</pre>" ..
             "<div style='margin-top:.5rem'><button class='cbi-button cbi-button-action small-btn' style='margin-right:4px; padding:0; border:0' name='_refreshlog_mihomo' value='1'>Обновить</button> " ..
             "<button class='cbi-button cbi-button-remove small-btn' style='padding:0; border:0' name='_clearlog_mihomo' value='1'>Очистить</button></div>" ..
             "</div></details>"
    end
  end

  -- Mihomo config editor
  do
    local sx = m:section(SimpleSection, "Mihomo (конфигурационные файлы в /etc/mihomo)")

    local config_files = list_yaml(MIHOMO_DIR)
    local chosen = fval("mihomo_file")
    local found=false; for _,f in ipairs(config_files) do if f==chosen then found=true; break end end
    if not found then chosen = config_files[1] end

    -- create/delete
    if http.formvalue("_mihomo_create") == "1" then
      local name = (http.formvalue("new_mihomo_name") or ""):gsub("^%s+",""):gsub("%s+$","")
      if name ~= "" and not name:find("[/\\]") and name:match("%.yaml$") then
        local path = MIHOMO_DIR .. "/" .. name
        if not fs.access(path) then write_file(path, "# Mihomo configuration\n\n") end
        set_err(nil)
        http.redirect(self_url({ tab="mihomo", mihomo_file=name }))
      else
        set_err("Некорректное имя файла. Требуется *.yaml без слэшей.")
        redirect_here("mihomo")
      end
      return m
    end

    if http.formvalue("_mihomo_delete") == "1" then
      local cf = fval_last("mihomo_file") or ""
      if cf ~= "" then fs.remove(MIHOMO_DIR .. "/" .. cf) end
      set_err(nil); redirect_here("mihomo"); return m
    end

    -- selector box
    do
      local url = disp.build_url("admin","network","tproxy_manager")
      local buf = {}
      buf[#buf+1] = "<div class='box editor-wrap editor-680' id='mihomo-editor'>"
      buf[#buf+1] = [[
    <div class="inline-row" style="margin:.3rem 0;">
        <span>Новый файл:</span>
        <input type="text" name="new_mihomo_name" placeholder="config.yaml" style="width:200px">
        <button class="cbi-button cbi-button-apply" name="_mihomo_create" value="1">Создать</button>
    </div>
    <div style="color:#6b7280;margin-top:.2rem">Имя должно соответствовать шаблону <code>*.yaml</code>, без слэшей.</div>
    <hr style="border:none;border-top:1px solid #e5e7eb;margin:.5rem 0"/>]]
      buf[#buf+1] = "<label>Файл для редактирования</label>"
      buf[#buf+1] = "<select name='mihomo_file'>"
      for _, f in ipairs(config_files) do
        local sel = (f==chosen) and " selected" or ""
        buf[#buf+1] = string.format("<option value=\"%s\"%s>%s</option>", pcdata(f), sel, pcdata(f))
      end
      buf[#buf+1] = "</select>"
      buf[#buf+1] = [[
<script>
(function(){
    var sel = document.querySelector('#mihomo-editor select[name="mihomo_file"]');
    if (!sel) return;
    sel.addEventListener('change', function(){
        if (window.__xray_guard && !window.__xray_guard()) {
          this.value = this.getAttribute('data-prev') || this.value; return;
        }
        var base = ']] .. pcdata(url) .. [[';
        var target = base + "?tab=mihomo&mihomo_file="+encodeURIComponent(sel.value);
        location.href = target;
    });
    sel.setAttribute('data-prev', sel.value);
})();
</script>]]
      buf[#buf+1] = [[
<button class="cbi-button cbi-button-remove" name="_mihomo_delete" value="1"
    onclick="return confirm('Удалить выбранный файл?')">Удалить</button>]]
      buf[#buf+1] = "</div><div style='height:5px'></div>"
      local dvsel = sx:option(DummyValue, "_selector_mihomo"); dvsel.rawhtml=true
      function dvsel.cfgvalue() return table.concat(buf) end
    end

    if chosen then
      local cedit = sx:option(DummyValue, "_mihomo_area"); cedit.rawhtml = true
      function cedit.cfgvalue()
        local content = read_file(MIHOMO_DIR .. "/" .. chosen)
        return [[
<textarea name="mihomo_text" rows="22" style="width:650px" spellcheck="false">]] .. pcdata(content) .. [[</textarea>
<div style="height:5px"></div>]]
      end

      local bsave = sx:option(Button, "_savemihomo"); bsave.title = ""; bsave.inputtitle = "Сохранить"
      bsave.inputstyle = "apply"
      function bsave.write(self, section)
        if not self.map:formvalue(self:cbid(section)) then return end
        local new = http.formvalue("mihomo_text") or ""
        local cf = fval_last("mihomo_file") or chosen
        write_file(MIHOMO_DIR .. "/" .. cf, new)
        set_err(nil); set_info("Конфиг Mihomo сохранён: "..cf)
        redirect_here("mihomo")
      end
    end

    local dout = sx:option(DummyValue, "_testout_mihomo"); dout.rawhtml = true; dout.title = ""
    function dout.cfgvalue()
      local out = read_file(MIHOMO_TEST_LOG)
      return "<details><summary>Результат последней проверки</summary>" ..
             "<div class='box editor-wrap editor-680'><pre style='white-space:pre-wrap'>" ..
             pcdata(out ~= "" and out or "(ещё не запускалось)") .. "</pre>" ..
             "<div style='margin-top:.5rem'><button class='cbi-button cbi-button-action small-btn' style='margin-right:4px; padding:0; border:0' name='_test_mihomo' value='1'>Проверить конфигурацию</button> " ..
             "<button class='cbi-button cbi-button-remove small-btn' style='padding:0; border:0' name='_clearlog_mihomo_config' value='1'>Очистить</button></div>" ..
             "</div></details>"
    end

    local msg = sx:option(DummyValue, "_mihomo_msgs"); msg.rawhtml = true; msg.title = ""
    function msg.cfgvalue()
      local e = get_err(); local i = get_info()
      local out = {}
      if e ~= "" then out[#out+1] = "<div class='msg err'>"..pcdata(e).."</div>" end
      if i ~= "" then out[#out+1] = "<div class='msg info'>"..pcdata(i).."</div>" end
      if i ~= "" then set_info(nil) end
      return table.concat(out)
    end
  end
end

return { render = render }
