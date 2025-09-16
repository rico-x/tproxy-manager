local cbi = require "luci.cbi"
local SimpleSection, DummyValue, Button = cbi.SimpleSection, cbi.DummyValue, cbi.Button

local function render(ctx)
  local m, http, sys, fs, disp = ctx.m, ctx.http, ctx.sys, ctx.fs, ctx.disp
  local pcdata, fval, fval_last = ctx.pcdata, ctx.fval, ctx.fval_last
  local self_url, redirect_here = ctx.self_url, ctx.redirect_here
  local combined_log, set_err, get_err, set_info, get_info = ctx.combined_log, ctx.set_err, ctx.get_err, ctx.set_info, ctx.get_info
  local write_file, read_file, write_json_file = ctx.write_file, ctx.read_file, ctx.write_json_file
  local XRAY_DIR, XRAY_BIN, LOG_TEST = ctx.XRAY_DIR, ctx.XRAY_BIN, ctx.LOG_TEST

  -- Toolbar handlers
  if http.formvalue("_refreshlog") then set_err(nil); redirect_here("xray"); return m end
  if http.formvalue("_clearlog") then
    sys.call("/etc/init.d/log restart >/dev/null 2>&1")
    set_err(nil)
    redirect_here("xray"); return m
  end
  if http.formvalue("_test") then
    sys.call(string.format("%s -test -format json -confdir %q >%s 2>&1", XRAY_BIN, XRAY_DIR, LOG_TEST))
    set_err(nil)
    redirect_here("xray"); return m
  end
  if http.formvalue("_clearlog_json") then
    write_file(LOG_TEST, "")
    set_err(nil)
    redirect_here("xray"); return m
  end

  -- Статус Xray
  do
    local ss = m:section(SimpleSection, "Статус и управление сервисом Xray")
    ctx.service_block(ss, "xray", "Xray", "xray")
  end

  -- Combined log
  do
    local sl  = m:section(SimpleSection)
    local log = sl:option(DummyValue, "_log"); log.rawhtml = true
    function log.cfgvalue()
      return "<details><summary><strong>Общий лог (logread)</strong></summary>" ..
             "<div class='box editor-wrap'><pre style='white-space:pre-wrap;max-height:30rem;overflow:auto'>" ..
             pcdata(combined_log()) .. "</pre>" ..
             "<div style='margin-top:.5rem'><button class='cbi-button cbi-button-action small-btn' style='margin-right:4px; padding:0; border:0' name='_refreshlog' value='1'>Обновить</button> " ..
             "<button class='cbi-button cbi-button-remove small-btn' style='padding:0; border:0' name='_clearlog' value='1'>Очистить</button></div>" ..
             "</div></details>"
    end
    local rfr = sl:option(Button, "_refreshlog"); rfr.title = ""; rfr.inputtitle = "Refresh"
    rfr.inputstyle = "action"; function rfr.render() end
    function rfr.write(self, section) if not self.map:formvalue(self:cbid(section)) then return end; redirect_here("xray") end
    local clr = sl:option(Button, "_clearlog"); clr.title = ""; clr.inputtitle = "Clear log"
    clr.inputstyle = "remove"; function clr.render() end
    function clr.write(self, section) if not self.map:formvalue(self:cbid(section)) then return end; sys.call("/etc/init.d/log restart >/dev/null 2>&1"); redirect_here("xray") end
  end

  -- XRAY JSON editor
  do
    local sx = m:section(SimpleSection, "Xray (JSON-файлы в /etc/xray)")
    local function list_json(dir)
      local t, it = {}, fs.dir(dir)
      if it then for name in it do if name:match("%.json$") then t[#t+1] = name end end end
      table.sort(t); return t
    end
    local json_files = list_json(XRAY_DIR)
    local chosen = fval("json_file")
    local found=false; for _,f in ipairs(json_files) do if f==chosen then found=true; break end end
    if not found then chosen = json_files[1] end

    -- create/delete
    if http.formvalue("_json_create") == "1" then
      local name = (http.formvalue("new_json_name") or ""):gsub("^%s+",""):gsub("%s+$","")
      if name ~= "" and not name:find("[/\\]") and name:match("%.json$") then
        local path = XRAY_DIR .. "/" .. name
        if not fs.access(path) then write_file(path, "{\n}\n") end
        set_err(nil)
        http.redirect(self_url({tab="xray", json_file=name, list_file=fval_last("list_file"), clash_file=fval_last("clash_file"), port_mode=fval("tpx_port_mode"), src_mode=fval("tpx_src_mode")}))
      else
        set_err("Некорректное имя файла. Требуется *.json без слэшей.")
        redirect_here("xray")
      end
      return m
    end

    if http.formvalue("_json_delete") == "1" then
      local jf = fval_last("json_file") or ""
      if jf ~= "" then fs.remove(XRAY_DIR .. "/" .. jf) end
      set_err(nil)
      redirect_here("xray"); return m
    end

    -- selector box
    do
      local url = disp.build_url("admin","network","tproxy_manager")
      local buf = {}
      buf[#buf+1] = "<div class='box editor-wrap editor-680' id='json-editor'>"
      buf[#buf+1] = [[
  <div class="inline-row" style="margin:.3rem 0;">
    <span>Новый файл:</span>
    <input type="text" name="new_json_name" placeholder="01_example.json" style="width:200px">
    <button class="cbi-button cbi-button-apply" name="_json_create" value="1">Создать</button>
  </div>
  <div style="color:#6b7280;margin-top:.2rem">Имя должно соответствовать шаблону <code>*.json</code>, без слэшей.</div>
  <hr style="border:none;border-top:1px solid #e5e7eb;margin:.5rem 0"/>]]
      buf[#buf+1] = "<label>Файл для редактирования</label>"
      buf[#buf+1] = "<select name='json_file'>"
      for _, f in ipairs(json_files) do
        local sel = (f==chosen) and " selected" or ""
        buf[#buf+1] = string.format("<option value=\"%s\"%s>%s</option>", pcdata(f), sel, pcdata(f))
      end
      buf[#buf+1] = "</select>"
      buf[#buf+1] = [[
<script>
(function(){
  function qs(s){ return document.querySelector(s) }
  var sel = document.querySelector('#json-editor select[name="json_file"]');
  if (!sel) return;
  sel.addEventListener('change', function(){
    if (window.__xray_guard && !window.__xray_guard()) { this.value = this.getAttribute('data-prev') || this.value; return; }
    var base = ']] .. pcdata(url) .. [[';
    var pm = (qs('select[name="tpx_port_mode"]')||{}).value || '';
    var sm = (qs('#tpx_src_mode')||{}).value || '';
    var lf = (qs('#unified-editor select[name="list_file"]')||{}).value || '';
    var cf = (qs('#clash-editor select[name="clash_file"]')||{}).value || '';
    var target = base + "?tab=xray&tpx_port_mode="+encodeURIComponent(pm)+"&tpx_src_mode="+encodeURIComponent(sm)+"&list_file="+encodeURIComponent(lf)+"&clash_file="+encodeURIComponent(cf)+"&json_file="+encodeURIComponent(sel.value);
    location.href = target;
  });
  sel.setAttribute('data-prev', sel.value);
})();
</script>]]
      buf[#buf+1] = [[
<button class="cbi-button cbi-button-remove" name="_json_delete" value="1"
  onclick="return confirm('Удалить выбранный файл?')">Удалить</button>]]
      buf[#buf+1] = "</div><div style='height:5px'></div>"
      local dvsel = sx:option(DummyValue, "_selector"); dvsel.rawhtml=true
      function dvsel.cfgvalue() return table.concat(buf) end
    end

    if chosen then
      local jedit = sx:option(DummyValue, "_json_area"); jedit.rawhtml = true
      function jedit.cfgvalue()
        local content = read_file(XRAY_DIR .. "/" .. chosen)
        return [[
<textarea name="json_text" rows="22" style="width:650px" spellcheck="false">]] .. pcdata(content) .. [[</textarea>
<div style="height:5px"></div>
<div class="box editor-wrap editor-680" id="json-status-box">
  <div id="json_status" style="margin:.08rem 0 .14rem 0; font-weight:600"></div>
</div>
<script>
(function(){
  function stripJsonComments(str){
    var out = '', i = 0, n = str.length, inStr = false, esc = false;
    while (i < n) {
      var c = str[i], d = str[i+1];
      if (inStr){ out+=c; if(esc){esc=false}else if(c==='\\'){esc=true}else if(c==='"'){inStr=false} i++; continue; }
      if (c==='"'){ inStr=true; out+=c; i++; continue; }
      if (c==='/' && d=== '/') { i+=2; while(i<n && str[i] !== '\n') i++; continue; }
      if (c==='/' && d==='*') { i+=2; while(i<n-1 && !(str[i]==='*' && str[i+1]==='/')) i++; i+=2; continue; }
      out+=c; i++;
    } return out;
  }
  var ta=document.querySelector('textarea[name="json_text"]'), badge=document.getElementById('json_status');
  function debounce(fn,ms){var t;return function(){clearTimeout(t);t=setTimeout(fn,ms)}}
  function validate(){ if(!ta||!badge)return; try{ JSON.parse(stripJsonComments(ta.value)); badge.textContent='JSONC валиден (комментарии разрешены)'; badge.style.color='#16a34a'; }catch(e){ badge.textContent='Ошибка JSON: '+e.message; badge.style.color='#dc2626'; } }
  if(ta){ ta.addEventListener('input', debounce(validate,250)); validate();

    var key = 'json:' + (document.querySelector('#json-editor select[name="json_file"]')||{}).value;
    try{
      var st = JSON.parse(localStorage.getItem(key)||'{}');
      if(typeof st.scroll === 'number') ta.scrollTop = st.scroll;
      if(typeof st.selStart === 'number' && typeof st.selEnd === 'number'){
        ta.selectionStart = st.selStart; ta.selectionEnd = st.selEnd;
      }
      function savePos(){
        try{ localStorage.setItem(key, JSON.stringify({scroll: ta.scrollTop, selStart: ta.selectionStart||0, selEnd: ta.selectionEnd||0})); }catch(e){}
      }
      ta.addEventListener('scroll', savePos);
      ta.addEventListener('keyup', savePos);
      ta.addEventListener('blur', savePos);
    }catch(e){}
  }
})();
</script>
]]
      end

      local bsave = sx:option(Button, "_savejson"); bsave.title = ""; bsave.inputtitle = "Сохранить"
      bsave.inputstyle = "apply"
      function bsave.write(self, section)
        if not self.map:formvalue(self:cbid(section)) then return end
        local new = http.formvalue("json_text") or ""
        local jf  = fval_last("json_file") or chosen
        local ok, err = write_json_file(XRAY_DIR .. "/" .. jf, new)
        if not ok then set_err(err or "save error")
        else set_err(nil); set_info("JSON сохранён: "..jf) end
        redirect_here("xray")
      end
    end

    local dout = sx:option(DummyValue, "_testout"); dout.rawhtml = true; dout.title = ""
    function dout.cfgvalue()
      local out = read_file(LOG_TEST)
      return "<details><summary>Результат последней проверки</summary>" ..
             "<div class='box editor-wrap editor-680'><pre style='white-space:pre-wrap'>" .. pcdata(out ~= "" and out or "(ещё не запускалось)") .. "</pre>" ..
             "<div style='margin-top:.5rem'><button class='cbi-button cbi-button-action small-btn' style='margin-right:4px; padding:0; border:0' name='_test' value='1'>Проверить конфигурацию</button> " ..
             "<button class='cbi-button cbi-button-remove small-btn' style='padding:0; border:0' name='_clearlog_json' value='1'>Очистить</button></div>" ..
             "</div></details>"
    end

    local btest = sx:option(Button, "_test"); btest.title = ""; btest.inputtitle = "Validate directory"
    btest.inputstyle = "action"; function btest.render() end
    function btest.write(self, section)
      if not self.map:formvalue(self:cbid(section)) then return end
      sys.call(string.format("%s -test -format json -confdir %q >%s 2>&1", XRAY_BIN, XRAY_DIR, LOG_TEST))
      redirect_here("xray")
    end

    local clrj = sx:option(Button, "_clearlog_json"); clrj.title = ""; clrj.inputtitle = "Clear log"
    clrj.inputstyle = "remove"; function clrj.render() end
    function clrj.write(self, section)
      if not self.map:formvalue(self:cbid(section)) then return end
      write_file(LOG_TEST, "")
      redirect_here("xray")
    end

    local msg = sx:option(DummyValue, "_xray_msgs"); msg.rawhtml = true; msg.title = ""
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