local cbi = require "luci.cbi"
local SimpleSection, DummyValue, Button = cbi.SimpleSection, cbi.DummyValue, cbi.Button

local function render(ctx)
  local m, http, sys, fs, disp = ctx.m, ctx.http, ctx.sys, ctx.fs, ctx.disp
  local pcdata, fval, fval_last = ctx.pcdata, ctx.fval, ctx.fval_last
  local self_url, redirect_here = ctx.self_url, ctx.redirect_here
  local combined_log, set_err, get_err, set_info, get_info = ctx.combined_log, ctx.set_err, ctx.get_err, ctx.set_info, ctx.get_info
  local write_file, read_file = ctx.write_file, ctx.read_file
  local CLASH_DIR, CLASH_BIN, CLASH_TEST_LOG = ctx.CLASH_DIR, ctx.CLASH_BIN, ctx.CLASH_TEST_LOG

  -- Toolbar handlers
  if http.formvalue("_refreshlog_clash") then set_err(nil); redirect_here("clash"); return m end
  if http.formvalue("_clearlog_clash") then
    sys.call("/etc/init.d/log restart >/dev/null 2>&1")
    set_err(nil)
    redirect_here("clash"); return m
  end
  if http.formvalue("_test_clash") then
    local config_file = fval_last("clash_file") or "config.yaml"
    sys.call(string.format("%s -t -f %s/%s >%s 2>&1", CLASH_BIN, CLASH_DIR, config_file, CLASH_TEST_LOG))
    set_err(nil)
    redirect_here("clash"); return m
  end
  if http.formvalue("_clearlog_clash_config") then
    write_file(CLASH_TEST_LOG, "")
    set_err(nil)
    redirect_here("clash"); return m
  end

  -- Статус Clash
  do
    local ss = m:section(SimpleSection, "Статус и управление сервисом Clash")
    ctx.service_block(ss, "clash", "Clash", "clash")
  end

  -- Combined log
  do
    local sl = m:section(SimpleSection)
    local log = sl:option(DummyValue, "_log_clash"); log.rawhtml = true
    function log.cfgvalue()
      return "<details><summary><strong>Общий лог (logread)</strong></summary>" ..
             "<div class='box editor-wrap'><pre style='white-space:pre-wrap;max-height:30rem;overflow:auto'>" ..
             pcdata(combined_log()) .. "</pre>" ..
             "<div style='margin-top:.5rem'><button class='cbi-button cbi-button-action small-btn' style='margin-right:4px; padding:0; border:0' name='_refreshlog_clash' value='1'>Обновить</button> " ..
             "<button class='cbi-button cbi-button-remove small-btn' style='padding:0; border:0' name='_clearlog_clash' value='1'>Очистить</button></div>" ..
             "</div></details>"
    end
  end

  -- Clash config editor
  do
    local sx = m:section(SimpleSection, "Clash (конфигурационные файлы в /etc/clash)")
    local function list_config_files(dir)
      local t, it = {}, fs.dir(dir)
      if it then for name in it do if name:match("%.yaml$") or name:match("%.yml$") then t[#t+1] = name end end end
      table.sort(t); return t
    end
    local config_files = list_config_files(CLASH_DIR)
    local chosen = fval("clash_file")
    local found=false; for _,f in ipairs(config_files) do if f==chosen then found=true; break end end
    if not found then chosen = config_files[1] end

    -- create/delete
    if http.formvalue("_clash_create") == "1" then
      local name = (http.formvalue("new_clash_name") or ""):gsub("^%s+",""):gsub("%s+$","")
      if name ~= "" and not name:find("[/\\]") and (name:match("%.yaml$") or name:match("%.yml$")) then
        local path = CLASH_DIR .. "/" .. name
        if not fs.access(path) then write_file(path, "# Clash configuration\n\n") end
        set_err(nil)
        http.redirect(self_url({tab="clash", clash_file=name, list_file=fval_last("list_file"), json_file=fval_last("json_file"), port_mode=fval("tpx_port_mode"), src_mode=fval("tpx_src_mode")}))
      else
        set_err("Некорректное имя файла. Требуется *.yaml или *.yml без слэшей.")
        redirect_here("clash")
      end
      return m
    end

    if http.formvalue("_clash_delete") == "1" then
      local cf = fval_last("clash_file") or ""
      if cf ~= "" then fs.remove(CLASH_DIR .. "/" .. cf) end
      set_err(nil)
      redirect_here("clash"); return m
    end

    -- selector box
    do
      local buf = {}
      buf[#buf+1] = "<div class='box editor-wrap editor-680' id='clash-editor'>"
      buf[#buf+1] = [[
    <div class="inline-row" style="margin:.3rem 0;">
        <span>Новый файл:</span>
        <input type="text" name="new_clash_name" placeholder="config.yaml" style="width:200px">
        <button class="cbi-button cbi-button-apply" name="_clash_create" value="1">Создать</button>
    </div>
    <div style="color:#6b7280;margin-top:.2rem">Имя должно соответствовать шаблону <code>*.yaml</code> или <code>*.yml</code>, без слэшей.</div>
    <hr style="border:none;border-top:1px solid #e5e7eb;margin:.5rem 0"/>]]
      buf[#buf+1] = "<label>Файл для редактирования</label>"
      buf[#buf+1] = "<select name='clash_file'>"
      for _, f in ipairs(config_files) do
        local sel = (f==chosen) and " selected" or ""
        buf[#buf+1] = string.format("<option value=\"%s\"%s>%s</option>", pcdata(f), sel, pcdata(f))
      end
      buf[#buf+1] = "</select>"
      buf[#buf+1] = [[
<script>
(function(){
    function qs(s){ return document.querySelector(s) }
    var sel = document.querySelector('#clash-editor select[name="clash_file"]');
    if (!sel) return;
    sel.addEventListener('change', function(){
        if (window.__xray_guard && !window.__xray_guard()) { this.value = this.getAttribute('data-prev') || this.value; return; }
        var base = ']] .. pcdata(disp.build_url("admin","network","tproxy_manager")) .. [[';
        var pm = (qs('select[name="tpx_port_mode"]')||{}).value || '';
        var sm = (qs('#tpx_src_mode')||{}).value || '';
        var lf = (qs('#unified-editor select[name="list_file"]')||{}).value || '';
        var jf = (qs('#json-editor select[name="json_file"]')||{}).value || '';
        var target = base + "?tab=clash&tpx_port_mode="+encodeURIComponent(pm)+"&tpx_src_mode="+encodeURIComponent(sm)+"&list_file="+encodeURIComponent(lf)+"&json_file="+encodeURIComponent(jf)+"&clash_file="+encodeURIComponent(sel.value);
        location.href = target;
    });
    sel.setAttribute('data-prev', sel.value);
})();
</script>]]
      buf[#buf+1] = [[
<button class="cbi-button cbi-button-remove" name="_clash_delete" value="1"
    onclick="return confirm('Удалить выбранный файл?')">Удалить</button>]]
      buf[#buf+1] = "</div><div style='height:5px'></div>"
      local dvsel = sx:option(DummyValue, "_selector_clash"); dvsel.rawhtml=true
      function dvsel.cfgvalue() return table.concat(buf) end
    end

    if chosen then
      local cedit = sx:option(DummyValue, "_clash_area"); cedit.rawhtml = true
      function cedit.cfgvalue()
        local content = read_file(CLASH_DIR .. "/" .. chosen)
        return [[
<textarea name="clash_text" rows="22" style="width:650px" spellcheck="false">]] .. pcdata(content) .. [[</textarea>
<div style="height:5px"></div>]]
      end

      local bsave = sx:option(Button, "_saveclash"); bsave.title = ""; bsave.inputtitle = "Сохранить"
      bsave.inputstyle = "apply"
      function bsave.write(self, section)
        if not self.map:formvalue(self:cbid(section)) then return end
        local new = http.formvalue("clash_text") or ""
        local cf = fval_last("clash_file") or chosen
        write_file(CLASH_DIR .. "/" .. cf, new)
        set_err(nil); set_info("Конфиг Clash сохранён: "..cf)
        redirect_here("clash")
      end
    end

    local dout = sx:option(DummyValue, "_testout_clash"); dout.rawhtml = true; dout.title = ""
    function dout.cfgvalue()
      local out = read_file(CLASH_TEST_LOG)
      return "<details><summary>Результат последней проверки</summary>" ..
             "<div class='box editor-wrap editor-680'><pre style='white-space:pre-wrap'>" .. pcdata(out ~= "" and out or "(ещё не запускалось)") .. "</pre>" ..
             "<div style='margin-top:.5rem'><button class='cbi-button cbi-button-action small-btn' style='margin-right:4px; padding:0; border:0' name='_test_clash' value='1'>Проверить конфигурацию</button> " ..
             "<button class='cbi-button cbi-button-remove small-btn' style='padding:0; border:0' name='_clearlog_clash_config' value='1'>Очистить</button></div>" ..
             "</div></details>"
    end

    local msg = sx:option(DummyValue, "_clash_msgs"); msg.rawhtml = true; msg.title = ""
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