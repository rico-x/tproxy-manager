local cbi = require "luci.cbi"
local SimpleSection, DummyValue, Button = cbi.SimpleSection, cbi.DummyValue, cbi.Button

local function render(ctx)
  local m, uci, http, sys, fs, disp = ctx.m, ctx.uci, ctx.http, ctx.sys, ctx.fs, ctx.disp
  local pcdata, fval, fval_last, pick_form_or_uci = ctx.pcdata, ctx.fval, ctx.fval_last, ctx.pick_form_or_uci
  local self_url, redirect_here = ctx.self_url, ctx.redirect_here
  local service_block, set_err, get_err, set_info, get_info = ctx.service_block, ctx.set_err, ctx.get_err, ctx.set_info, ctx.get_info
  local write_file, read_file, is_port, append_line_unique = ctx.write_file, ctx.read_file, ctx.is_port, ctx.append_line_unique
  local netm_init = ctx.netm_init
  local PKG = ctx.PKG

  do
    local ss = m:section(SimpleSection, "Статус и управление сервисом TPROXY")
    service_block(ss, "tproxy-manager", "TPROXY", "tproxy")
  end

  do
    local top = m:section(SimpleSection, ""); top.anonymous = true
    local dv = top:option(DummyValue, "_pretitle_restart"); dv.rawhtml = true
function dv.cfgvalue()
  return [[
<style>
  /* тонкая кнопка как у остальных, ширина по тексту */
  .tpx-btn-slim{ 
    display:inline-block !important;
    padding:.25rem .6rem !important;
    line-height:1.15 !important;
    height:auto !important;
    width:auto !important;
    min-width:unset !important;
    white-space:nowrap !important;
  }
  .tpx-btn-slim > span{
    color:#16a34a;          /* зелёный текст */
    font-weight:700;        /* жирный */
  }
</style>
<div class="inline-row" style="margin:.25rem 0 .25rem 0">
  <button class="cbi-button cbi-button-reload tpx-btn-slim"
          name="_tproxy_restart" value="1"
          title="Сохранить и перезапустить TPROXY">
    <span>Перезагрузка</span>
  </button>
</div>
<script>
(function(){
  // На «Перезагрузка» — сохраняем и UCI, и редактор
  var rb = document.querySelector('button[name="_tproxy_restart"]');
  if (rb) rb.addEventListener('click', function(){
    var form = this.form || document.querySelector('form'); if(!form) return;
    var s1 = form.querySelector('input[name="_save_tproxy_main"]');
    if(!s1){ s1 = document.createElement('input'); s1.type='hidden'; s1.name='_save_tproxy_main'; form.appendChild(s1); }
    s1.value = '1';
    var s2 = form.querySelector('input[name="_uniedit_save"]');
    if(!s2){ s2 = document.createElement('input'); s2.type='hidden'; s2.name='_uniedit_save'; form.appendChild(s2); }
    s2.value = '1';
  }, {passive:true});
})();
</script>]]
end
  end

  local main_s = m:section(SimpleSection, "TPROXY — основные настройки")

  -- Interfaces (left col)
  do
    local dv = main_s:option(DummyValue, "_ifaces"); dv.rawhtml = true
    function dv.cfgvalue()
      local current = (uci:get(PKG,"main","ifaces") or ""):gsub(","," "):gsub("%s+"," ")
      local set = {}; for w in current:gmatch("(%S+)") do set[w]=true end

      local exclude = {}
      uci:foreach("firewall", "zone", function(s)
        if (s.name == "wwan") then
          local secname = s[".name"]
          local nets = uci:get_list("firewall", secname, "network") or {}
          local devs = uci:get_list("firewall", secname, "device") or {}
          for _, d in ipairs(devs) do exclude[d] = true end
          local nm = netm_init
          if nm then
            for _, n in ipairs(nets) do
              local iface = nm:get_interface(n)
              if iface then
                if iface.get_device then
                  local d = iface:get_device()
                  if d and d.name then exclude[d:name()] = true end
                end
                if iface.get_devices then
                  local ds = iface:get_devices()
                  if ds then
                    for _, dv in ipairs(ds) do
                      if dv and dv.name then exclude[dv:name()] = true end
                    end
                  end
                end
                if iface.ifname then
                  local ifn = iface:ifname()
                  if ifn then exclude[ifn] = true end
                end
              end
            end
          end
        end
      end)

      local ipv6 = uci:get(PKG,"main","ipv6_enabled") or ""
      local buf = {}
      buf[#buf+1] = string.format(
        "<div class='box'><div style='display:flex;align-items:center;gap:.6rem;margin-bottom:.4rem'>"
          .. "<label style='margin-right:.8rem'><input type='checkbox' name='tpx_ipv6_enabled' value='1' %s/> IPv6</label>"
          .. "<strong>Интерфейсы</strong></div>",
        (ipv6=="1") and "checked" or ""
      )

      for _,d in ipairs((sys.net and sys.net.devices and sys.net.devices()) or {}) do
        if d ~= "lo" and not d:match("^wwan") and not exclude[d] then
          local chk = set[d] and "checked" or ""
          buf[#buf+1] = string.format(
            '<label style="display:inline-block;margin-right:.5rem"><input type="checkbox" name="tpx_if_%s" value="1" %s/> %s</label>',
            pcdata(d), chk, pcdata(d)
          )
        end
      end
      buf[#buf+1] = "</div>"
      local out = {}
      out[#out+1] = "<div class='tpx-two'><div class='col'>"
      out[#out+1] = table.concat(buf)
      out[#out+1] = "</div>"
      return table.concat(out)
    end
  end

  -- Ports (right col)
  do
    local dv = main_s:option(DummyValue, "_ports"); dv.rawhtml = true
    function dv.cfgvalue()
      local u_p_all = uci:get(PKG,"main","tproxy_port") or ""
      local u_p_tcp = uci:get(PKG,"main","tproxy_port_tcp") or ""
      local u_p_udp = uci:get(PKG,"main","tproxy_port_udp") or ""
      local f_p_all = http.formvalue("tpx_port") or ""
      local f_p_tcp = http.formvalue("tpx_port_tcp") or ""
      local f_p_udp = http.formvalue("tpx_port_udp") or ""
      local f_split = http.formvalue("tpx_split") ~= nil

      local p_all = (f_p_all ~= "" and f_p_all) or u_p_all
      local p_tcp = (f_p_tcp ~= "" and f_p_tcp) or u_p_tcp
      local p_udp = (f_p_udp ~= "" and f_p_udp) or u_p_udp

      local uci_split = (u_p_tcp ~= "" or u_p_udp ~= "") and not (u_p_tcp == u_p_all and u_p_udp == u_p_all)
      local split_on = f_split or uci_split

      local eff_tcp = (p_tcp ~= "" and p_tcp or p_all)
      local eff_udp = (p_udp ~= "" and p_udp or p_all)

      local right = ([[<div class="box">
        <div class="inline-row"><label><input type="checkbox" id="tpx_split" name="tpx_split" value="1" %s/> Разделить TCP/UDP</label></div>
        <div id="p_all_row" style="margin-top:.25rem"><label>Порт:</label>
          <input type="number" id="tpx_port" name="tpx_port" value="%s" min="1" max="65535" step="1" style="width:120px">
        </div>
        <div id="p_tcp_row" style="display:none;margin-top:.25rem"><label>Порт TCP:</label>
          <input type="number" id="tpx_port_tcp" name="tpx_port_tcp" value="%s" min="1" max="65535" step="1" style="width:120px">
        </div>
        <div id="p_udp_row" style="display:none;margin-top:.25rem"><label>Порт UDP:</label>
          <input type="number" id="tpx_port_udp" name="tpx_port_udp" value="%s" min="1" max="65535" step="1" style="width:120px">
        </div>
        <script>
          (function(){
            var form = document.querySelector('form'); if(form){ form.setAttribute('novalidate','novalidate'); }
            var split=document.getElementById('tpx_split');
            var allr=document.getElementById('p_all_row'), t=document.getElementById('p_tcp_row'), u=document.getElementById('p_udp_row');
            var ipAll=document.getElementById('tpx_port'), ipT=document.getElementById('tpx_port_tcp'), ipU=document.getElementById('tpx_port_udp');
            function upd(){
              var on = split && split.checked;
              allr.style.display = on ? 'none' : 'block';
              t.style.display = on ? 'block' : 'none';
              u.style.display = on ? 'block' : 'none';
              if(on){
                ipAll.disabled = true; ipAll.required = false;
                ipT.disabled = false;  ipU.disabled = false;
                ipT.required = true;   ipU.required = true;
              }else{
                ipAll.disabled = false; ipAll.required = true;
                ipT.disabled = true;    ipU.disabled = true;
                ipT.required = false;   ipU.required = false;
                ipT.value=''; ipU.value='';
              }
            }
            if(split){ split.addEventListener('change',function(){
              if (window.__xray_dirty && !confirm('Есть несохранённые изменения. Перейти без сохранения?')) { split.checked = !split.checked; return; }
              upd();
            }); }
            upd();
          })();
        </script>
      </div>]]):format(
        split_on and "checked" or "",
        pcdata(p_all), pcdata(eff_tcp), pcdata(eff_udp)
      )
      return "<div class='col'>" .. right .. "</div></div>"
    end
  end

  -- Modes
  do
    local dv = main_s:option(DummyValue, "_modes"); dv.rawhtml = true
    function dv.cfgvalue()
      local pm = pick_form_or_uci(fval("tpx_port_mode"), uci:get(PKG,"main","port_mode"))
      local sm = pick_form_or_uci(fval("tpx_src_mode"),  uci:get(PKG,"main","src_mode"))
      local function opt(val, cur, title)
        return string.format('<option value="%s"%s>%s</option>', val, (val==cur) and " selected" or "", title)
      end
      return ([[<div class="box">
        <div class="inline-row"><label>Режим по портам:</label>
          <select name="tpx_port_mode">%s%s</select>
        </div>
        <div class="inline-row" style="margin-top:.25rem"><label>Режим по источникам:</label>
          <select id="tpx_src_mode" name="tpx_src_mode">%s%s%s</select>
        </div>
        <script>
        (function(){
          function qs(s){ return document.querySelector(s) }
          function buildUrl(){
            var base = ']].. pcdata(disp.build_url("admin","network","tproxy_manager").."?tab=tproxy") ..[[';
            var pm = (qs('select[name="tpx_port_mode"]')||{}).value || '';
            var sm = (qs('#tpx_src_mode')||{}).value || '';
            var lf = (qs('#unified-editor select[name="list_file"]')||{}).value || '';
            var jf = (qs('#json-editor select[name="json_file"]')||{}).value || '';
            var cf = (qs('#clash-editor select[name="clash_file"]')||{}).value || '';
            var url = base + '&tpx_port_mode=' + encodeURIComponent(pm) + '&tpx_src_mode=' + encodeURIComponent(sm);
            if (lf) url += '&list_file=' + encodeURIComponent(lf);
            if (jf) url += '&json_file=' + encodeURIComponent(jf);
            if (cf) url += '&clash_file=' + encodeURIComponent(cf);
            return url;
          }
          var pmSelect = qs('select[name="tpx_port_mode"]');
          var smSelect = qs('#tpx_src_mode');
          function go(){ if (!window.__xray_guard || window.__xray_guard()) location.href = buildUrl(); }
          if (pmSelect) pmSelect.addEventListener('change', go);
          if (smSelect) pmSelect && smSelect.addEventListener('change', go);
        })();
        </script>
      </div>]]):format(
        opt("bypass",pm,"bypass"),
        opt("only",pm,"only"),
        opt("off",sm,"off"),
        opt("only",sm,"only"),
        opt("bypass",sm,"bypass")
      )
    end
  end

  -- Unified editor + DHCP picker
  do
    local se = m:section(SimpleSection, "")
    local dv = se:option(DummyValue, "_uniedit"); dv.rawhtml = true
    function dv.cfgvalue()
      local function getu(k) return uci:get(PKG,"main",k) or "" end

      local pmode_form = fval("tpx_port_mode")
      local smode      = pick_form_or_uci(fval("tpx_src_mode"),  uci:get(PKG,"main","src_mode"))
      local pmode      = pick_form_or_uci(pmode_form, uci:get(PKG,"main","port_mode"))

      local ports = getu("ports_file")
      local bv4   = getu("bypass_v4_file")
      local bv6   = getu("bypass_v6_file")
      local so4   = getu("src_only_v4_file")
      local so6   = getu("src_only_v6_file")
      local sb4   = getu("src_bypass_v4_file")
      local sb6   = getu("src_bypass_v6_file")

      local options = {}
      if ports ~= "" then options[#options+1] = {ports, "Порты ("..((pmode and pmode~="") and pmode or "?")..")", "none"} end
      if bv4   ~= "" then options[#options+1] = {bv4,   "bypass IPv4", "none"} end
      if bv6   ~= "" then options[#options+1] = {bv6,   "bypass IPv6", "none"} end
      if so4   ~= "" then options[#options+1] = {so4,   "src only IPv4", "only"} end
      if so6   ~= "" then options[#options+1] = {so6,   "src only IPv6", "only"} end
      if sb4   ~= "" then options[#options+1] = {sb4,   "src bypass IPv4", "bypass"} end
      if sb6   ~= "" then options[#options+1] = {sb6,   "src bypass IPv6", "bypass"} end

      if #options == 0 then
        return "<div class='box editor-wrap' style='color:#6b7280'>В UCI ("..PKG..") не заданы пути файлов списков. Укажите пути в «Дополнительных настройках».</div>"
      end

      local chosen = fval("list_file")
      local found=false; for _,o in ipairs(options) do if o[1]==chosen then found=true end end
      if not found then chosen = options[1][1] end

      local function visible_for_mode(kind, sm)
        if kind=="none" then return true end
        if sm=="only"  and kind=="only"  then return true end
        if sm=="bypass" and kind=="bypass" then return true end
        return false
      end
      local chosen_kind = "none"
      for _,o in ipairs(options) do if o[1]==chosen then chosen_kind=o[3] end end
      if not visible_for_mode(chosen_kind, smode) then
        for _,o in ipairs(options) do if visible_for_mode(o[3], smode) then chosen = o[1]; break end end
      end

      local content = read_file(chosen)

      local desc = ""
      if chosen == ports then
        if     pmode == "bypass" then desc = "Трафик на перечисленные порты идёт напрямую (остальные через прокси)."
        elseif pmode == "only"   then desc = "Трафик на перечисленные порты идёт через прокси (остальные напрямую)."
        else desc = "Файл с портами; текущий режим по портам в UCI не задан." end
      elseif chosen == bv4 then desc = "IPv4 адреса/сети, которые не будут проксироваться."
      elseif chosen == bv6 then desc = "IPv6 адреса/сети, которые не будут проксироваться."
      elseif chosen == so4 then desc = "IPv4 источники, которые будут идти через прокси."
      elseif chosen == so6 then desc = "IPv6 источники, которые будут идти через прокси."
      elseif chosen == sb4 then desc = "IPv4 источники, которые будут идти напрямую."
      elseif chosen == sb6 then desc = "IPv6 источники, которые будут идти напрямую." end

      local sel = {}
      sel[#sel+1] = "<div id='unified-editor' class='editor-wrap editor-wide'>"
      sel[#sel+1] = "<div class='inline-row'><label>Файл для редактирования:</label><select name='list_file'>"
      for _,o in ipairs(options) do
        local path, label, kind = o[1], o[2], o[3]
        local selattr = (path == chosen) and " selected" or ""
        local show = (kind=='none') or (smode=='only' and kind=='only') or (smode=='bypass' and kind=='bypass')
        local style = show and "" or " style=\"display:none\""
        sel[#sel+1] = string.format("<option value=\"%s\" data-src-kind=\"%s\"%s%s>%s — %s</option>",
          pcdata(path), pcdata(kind), selattr, style, pcdata(path), pcdata(label))
      end
      sel[#sel+1] = "</select><button class=\"cbi-button cbi-button-apply small-btn\" name=\"_uniedit_save\" value=\"1\">Сохранить файл</button></div>"
      sel[#sel+1] = "<div style='margin:.2rem 0 .5rem 0; color:#6b7280'>" .. pcdata(desc) .. "</div>"

      sel[#sel+1] = string.format("<textarea name='uniedit_text' rows='16' spellcheck='false'>%s</textarea>", pcdata(content))

      sel[#sel+1] = string.format([[
<div id="uniedit_hint" style="margin-top:.35rem; color:#9ca3af"></div>
<script>
(function(){
  function qs(s){ return document.querySelector(s) }
  var ta = qs('textarea[name="uniedit_text"]');
  var fileSel = qs('#unified-editor select[name="list_file"]');
  var hint = qs('#uniedit_hint');
  var key = 'uniedit:' + (fileSel ? fileSel.value : '');
  var portsPath = %q; // UCI: main.ports_file

  function isIPv4(s){
    var m = s.match(/^(\d{1,3})(?:\.(\d{1,3})){3}$/); if(!m) return false;
    return s.split('.').every(function(n){ n=+n; return n>=0 && n<=255; });
  }
  function isIPv4CIDR(s){
    var m = s.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d|[1-2]\d|3[0-2])$/);
    return !!(m && isIPv4(m[1]));
  }
  function isIPv6(s){ return /:/.test(s); }
  function isIPv6CIDR(s){ return /:/.test(s) && /\/(\d|[1-9]\d|1[01]\d|12[0-8])$/.test(s); }

  function isPortLine(ln){
    var m = ln.match(/^(?:(tcp|udp|both):)?(\d{1,5})(?:-(\d{1,5}))?$/i);
    if(!m) return false;
    var from = +m[2], to = m[3] ? +m[3] : from;
    if(!(from >= 1 && from <= 65535)) return false;
    if(!(to   >= 1 && to   <= 65535)) return false;
    if(from > to) return false;
    return true;
  }

  function validate(){
    if(!ta||!hint) return;
    var bad = [], portsMode = (fileSel && fileSel.value === portsPath);
    var lines = ta.value.split(/\r?\n/);
    for(var i=0;i<lines.length;i++){
      var ln = (lines[i]||'').trim();
      if(!ln || ln[0]=='#' || ln[0]==';') continue;
      var ok = portsMode ? isPortLine(ln) : (isIPv4(ln) || isIPv4CIDR(ln) || isIPv6(ln) || isIPv6CIDR(ln));
      if(!ok) bad.push((i+1)+': '+ln);
    }
    if(bad.length){
      hint.style.color = '#b45309';
      hint.innerHTML = (portsMode
        ? 'Подозрительные строки для файла портов ('+bad.length+'):<br><code style="white-space:pre-wrap">'+bad.slice(0,10).join('\\n')+(bad.length>10?'\\n…':'')+'</code><br>Ожидается: <code>80</code>, <code>tcp:443</code>, <code>udp:53</code>, <code>both:123</code>, <code>1000-2000</code>, <code>udp:6000-7000</code>.'
        : 'Подозрительные строки ('+bad.length+'):<br><code style="white-space:pre-wrap">'+bad.slice(0,10).join('\\n')+(bad.length>10?'\\n…':'')+'</code>');
      ta.style.outline = '2px solid #f59e0b';
    }else{
      hint.style.color = '#9ca3af';
      hint.textContent = portsMode
        ? 'Формат портов корректен: порт/диапазон, опционально с префиксом tcp:/udp:/both:.'
        : 'Похоже корректно: IPv4/IPv6 (возможен CIDR). Строки с #/; игнорируются.';
      ta.style.outline = '';
    }
  }

  function savePos(){
    try{
      var st = { scroll: ta.scrollTop, selStart: ta.selectionStart||0, selEnd: ta.selectionEnd||0 };
      localStorage.setItem(key, JSON.stringify(st));
    }catch(e){}
  }
  function restorePos(){
    try{
      var st = JSON.parse(localStorage.getItem(key)||'{}');
      if(typeof st.scroll === 'number') ta.scrollTop = st.scroll;
      if(typeof st.selStart === 'number' && typeof st.selEnd === 'number'){
        ta.selectionStart = st.selStart; ta.selectionEnd = st.selEnd;
      }
    }catch(e){}
  }

  if(ta){
    restorePos();
    ta.addEventListener('input', function(){ window.__xray_dirty = true; validate(); savePos(); });
    ta.addEventListener('scroll', savePos);
    ta.addEventListener('keyup', savePos);
    validate();
  }

  var sel = document.querySelector('#unified-editor select[name="list_file"]');
  if (!sel) return;
  sel.addEventListener('change', function(){
    if (window.__xray_guard && !window.__xray_guard()) { this.value = this.getAttribute('data-prev') || this.value; return; }
    var base = ']] .. pcdata(disp.build_url("admin","network","tproxy_manager").."?tab=tproxy") .. [[';
    var pm = (document.querySelector('select[name="tpx_port_mode"]')||{}).value || '';
    var sm = (document.querySelector('#tpx_src_mode')||{}).value || '';
    var jf = (document.querySelector('#json-editor select[name="json_file"]')||{}).value || '';
    var cf = (document.querySelector('#clash-editor select[name="clash_file"]')||{}).value || '';
    var url = base + '&tpx_port_mode=' + encodeURIComponent(pm) + '&tpx_src_mode=' + encodeURIComponent(sm);
    if (jf) url += '&json_file=' + encodeURIComponent(jf);
    if (cf) url += '&clash_file=' + encodeURIComponent(cf);
    url += '&list_file=' + encodeURIComponent(sel.value);
    location.href = url;
  });
  sel.setAttribute('data-prev', sel.value);

  // На «Сохранить настройки TPROXY» — также сохранить текстовый файл редактора (как Перезагрузка, но без рестарта)
  (function(){
    var saveBtn = document.querySelector('button[name="_save_tproxy_main"]');
    if(!saveBtn) return;
    saveBtn.addEventListener('click', function(){
      var form = this.form || document.querySelector('form'); if(!form) return;
      // Явно проставим оба поля, как у «Перезагрузка»
      var a = form.querySelector('input[name="_save_tproxy_main"]');
      if(!a){ a = document.createElement('input'); a.type='hidden'; a.name='_save_tproxy_main'; form.appendChild(a); }
      a.value = '1';
      var b = form.querySelector('input[name="_uniedit_save"]');
      if(!b){ b = document.createElement('input'); b.type='hidden'; b.name='_uniedit_save'; form.appendChild(b); }
      b.value = '1';
    }, {passive:true});
  })();

})();
</script>]], ports)

      -- DHCP leases picker
      local leases = {}
      for line in (read_file("/tmp/dhcp.leases").."\n"):gmatch("([^\n]*)\n") do
        local ts, mac, ip, host = line:match("^(%d+)%s+(%S+)%s+(%S+)%s+(%S+)")
        if ip and ip:match("^%d+%.%d+%.%d+%.%d+$") then
          leases[#leases+1] = { ip = ip, mac = mac, host = (host and host ~= "*" and host) or "" }
        end
      end
      sel[#sel+1] = "<details style='margin-top:.6rem'><summary style='cursor:pointer;font-weight:600'>DHCP аренды (быстро добавить в src only/bypass v4)</summary>"
      sel[#sel+1] = "<div class='box' style='margin-top:.4rem'>"
      if #leases == 0 then
        sel[#sel+1] = "<div style='color:#6b7280'>Нет активных аренд.</div>"
      else
        sel[#sel+1] = "<table class='leases-table'><colgroup><col class='col-ip'><col class='col-host'><col class='col-mac'><col class='col-act'></colgroup><thead><tr><th>IP</th><th>Имя</th><th>MAC</th><th>Действия</th></tr></thead><tbody>"
        for _, r in ipairs(leases) do
          sel[#sel+1] = string.format(
            "<tr><td><code>%s</code></td><td>%s</td><td><code>%s</code></td>" ..
            "<td>" ..
            "<button class='cbi-button cbi-button-apply small-btn' name='_dhcp_add_only' value='%s'>+ only</button> " ..
            "<button class='cbi-button cbi-button-action small-btn' name='_dhcp_add_bypass' value='%s'>+ bypass</button>" ..
            "</td></tr>",
            pcdata(r.ip), pcdata(r.host or ""), pcdata(r.mac or ""), pcdata(r.ip), pcdata(r.ip)
          )
        end
        sel[#sel+1] = "</tbody></table>"
      end
      sel[#sel+1] = "</div></details>"

      sel[#sel+1] = "</div>"
      return table.concat(sel, "\n")
    end
  end

  -- Advanced
  do
    local dv = m:section(SimpleSection, "Дополнительные настройки (свернутая панель)"):option(DummyValue, "_advanced")
    dv.rawhtml = true
    function dv.cfgvalue()
      local function getu(k) return uci:get(PKG,"main",k) or "" end
      local nft = getu("nft_table")
      local fwt = getu("fwmark_tcp")
      local fwu = getu("fwmark_udp")
      local rtt = getu("rttab_tcp")
      local rtu = getu("rttab_udp")

      local ports_file   = getu("ports_file")
      local bypass_v4    = getu("bypass_v4_file")
      local bypass_v6    = getu("bypass_v6_file")
      local src_o4       = getu("src_only_v4_file")
      local src_o6       = getu("src_only_v6_file")
      local src_b4       = getu("src_bypass_v4_file")
      local src_b6       = getu("src_bypass_v6_file")
      local loge         = getu("log_enabled")

      return ([[<div id="adv-wrap"><details>
        <summary><strong>Развернуть/свернуть дополнительные параметры</strong></summary>
        <div style="display:grid;grid-template-columns:minmax(220px, 360px) 1fr;gap:.35rem .6rem;align-items:center">
          <label>Логирование</label><input type="checkbox" name="tpx_log_enabled" value="1" %s>

          <label>nft_table</label><input type="text" name="tpx_nft_table" value="%s">
          <label>fwmark_tcp</label><input type="text" name="tpx_fwmark_tcp" value="%s">
          <label>fwmark_udp</label><input type="text" name="tpx_fwmark_udp" value="%s">
          <label>rttab_tcp</label><input type="text" name="tpx_rttab_tcp" value="%s">
          <label>rttab_udp</label><input type="text" name="tpx_rttab_udp" value="%s">

          <label>ports_file</label><input type="text" name="tpx_ports_file" value="%s">
          <label>bypass_v4_file</label><input type="text" name="tpx_bypass_v4_file" value="%s">
          <label>bypass_v6_file</label><input type="text" name="tpx_bypass_v6_file" value="%s">

          <label>src_only_v4_file</label><input type="text" name="tpx_src_only_v4_file" value="%s">
          <label>src_only_v6_file</label><input type="text" name="tpx_src_only_v6_file" value="%s">
          <label>src_bypass_v4_file</label><input type="text" name="tpx_src_bypass_v4_file" value="%s">
          <label>src_bypass_v6_file</label><input type="text" name="tpx_src_bypass_v6_file" value="%s">
        </div>
      </details></div]]):format(
        (loge=="1") and "checked" or "",
        pcdata(nft), pcdata(fwt), pcdata(fwu), pcdata(rtt), pcdata(rtu),
        pcdata(ports_file), pcdata(bypass_v4), pcdata(bypass_v6),
        pcdata(src_o4), pcdata(src_o6), pcdata(src_b4), pcdata(src_b6)
      )
    end
  end

  -- Save handlers (TPROXY) + DHCP info + сообщения
  local function save_tproxy_main()
    -- DHCP quick add
    local ip_only  = http.formvalue("_dhcp_add_only")
    local ip_bypass= http.formvalue("_dhcp_add_bypass")
    if ip_only and ip_only ~= "" then
      local path = uci:get(PKG,"main","src_only_v4_file") or ""
      if path ~= "" then
        append_line_unique(path, ip_only)
        set_info(string.format("Добавлено %s → src_only_v4_file: %s", ip_only, path))
        set_err(nil)
      end
      redirect_here("tproxy"); return
    end
    if ip_bypass and ip_bypass ~= "" then
      local path = uci:get(PKG,"main","src_bypass_v4_file") or ""
      if path ~= "" then
        append_line_unique(path, ip_bypass)
        set_info(string.format("Добавлено %s → src_bypass_v4_file: %s", ip_bypass, path))
        set_err(nil)
      end
      redirect_here("tproxy"); return
    end

    local want_save    = http.formvalue("_save_tproxy_main") == "1"
    -- Сохраняем файл и при нажатии «Сохранить настройки», даже если _uniedit_save не пришёл
    local want_file    = (http.formvalue("_uniedit_save") == "1") or (http.formvalue("_save_tproxy_main") == "1")
    local want_restart = http.formvalue("_tproxy_restart") == "1"

    if want_save then
      local split = http.formvalue("tpx_split") ~= nil
      if split then
        local pt = http.formvalue("tpx_port_tcp") or ""
        local pu = http.formvalue("tpx_port_udp") or ""
        if not (is_port(pt) and is_port(pu)) then
          set_err("Включен режим разделения TCP/UDP: требуется указать оба порта в диапазоне 1..65535.")
          return
        end
      else
        local p = http.formvalue("tpx_port") or ""
        if not is_port(p) then
          set_err("Нужно указать общий порт (1..65535).")
          return
        end
      end

      set_err(nil)

      uci:section(PKG,"main","main",{})
      uci:set(PKG,"main","log_enabled", http.formvalue("tpx_log_enabled") and "1" or "0")

      local selected = {}
      for _,d in ipairs((sys.net and sys.net.devices and sys.net.devices()) or {}) do
        if d ~= "lo" and not d:match("^wwan") and http.formvalue("tpx_if_"..d) then selected[#selected+1]=d end
      end
      if #selected > 0 then uci:set(PKG,"main","ifaces", table.concat(selected," ")) else uci:delete(PKG,"main","ifaces") end
      uci:set(PKG,"main","ipv6_enabled", http.formvalue("tpx_ipv6_enabled") and "1" or "0")

      if split then
        local pt = http.formvalue("tpx_port_tcp")
        local pu = http.formvalue("tpx_port_udp")
        uci:set(PKG,"main","tproxy_port_tcp", pt)
        uci:set(PKG,"main","tproxy_port_udp", pu)
        local p = http.formvalue("tpx_port")
        if p and p~="" then uci:set(PKG,"main","tproxy_port", p) end
      else
        local p = http.formvalue("tpx_port")
        uci:set(PKG,"main","tproxy_port", p)
        uci:delete(PKG,"main","tproxy_port_tcp")
        uci:delete(PKG,"main","tproxy_port_udp")
      end

      local pm = fval("tpx_port_mode")
      if pm == "bypass" or pm == "only" then uci:set(PKG,"main","port_mode", pm) else uci:delete(PKG,"main","port_mode") end

      local sm = fval("tpx_src_mode")
      if sm == "off" or sm == "only" or sm == "bypass" then uci:set(PKG,"main","src_mode", sm) else uci:delete(PKG,"main","src_mode") end

      local function S(k,v) if v and v~="" then uci:set(PKG,"main",k,v) else uci:delete(PKG,"main",k) end end
      S("nft_table", http.formvalue("tpx_nft_table"))
      S("fwmark_tcp", http.formvalue("tpx_fwmark_tcp"))
      S("fwmark_udp", http.formvalue("tpx_fwmark_udp"))
      S("rttab_tcp",  http.formvalue("tpx_rttab_tcp"))
      S("rttab_udp",  http.formvalue("tpx_rttab_udp"))
      S("ports_file",        http.formvalue("tpx_ports_file"))
      S("bypass_v4_file",    http.formvalue("tpx_bypass_v4_file"))
      S("bypass_v6_file",    http.formvalue("tpx_bypass_v6_file"))
      S("src_only_v4_file",  http.formvalue("tpx_src_only_v4_file"))
      S("src_only_v6_file",  http.formvalue("tpx_src_only_v6_file"))
      S("src_bypass_v4_file",http.formvalue("tpx_src_bypass_v4_file"))
      S("src_bypass_v6_file",http.formvalue("tpx_src_bypass_v6_file"))

      uci:commit(PKG)
      set_info("Настройки TPROXY сохранены")
    end

    if want_file then
      -- Берём текущий выбор из формы; если его нет — берём последний из истории
      local path = http.formvalue("list_file") or fval_last("list_file")
      if path and path ~= "" then
        local text = http.formvalue("uniedit_text") or ""
        write_file(path, text)
        set_info("Файл списка сохранён: " .. path)
        set_err(nil)
      end
    end

    if want_restart then
      sys.call("/etc/init.d/tproxy-manager stop >/dev/null 2>&1")
      sys.call("/etc/init.d/tproxy-manager start >/dev/null 2>&1")
      set_info("TPROXY: сервис перезапущен")
      redirect_here("tproxy"); return
    end
  end
  save_tproxy_main()

  -- Save/Cancel row
  do
    local ss = m:section(SimpleSection)
    local dv = ss:option(DummyValue, "_savecancel_row"); dv.rawhtml = true
    function dv.cfgvalue()
      return [[
<div class="inline-row">
  <button class="cbi-button cbi-button-apply" name="_save_tproxy_main" value="1">Сохранить настройки TPROXY</button>
  <button class="cbi-button cbi-button-reset" name="_cancel_tproxy_main" value="1">Отменить изменения</button>
</div>]]
    end
    local b  = ss:option(Button, "_save_tproxy_main"); b.title=""; b.inputtitle="Save"; b.inputstyle="apply"
    function b.render() end
    function b.write(self, section)
      if not http.formvalue("_save_tproxy_main") then return end
      redirect_here("tproxy")
    end
    local cancel = ss:option(Button, "_cancel_tproxy_main"); cancel.title = ""; cancel.inputtitle = "Cancel"; cancel.inputstyle = "reset"
    function cancel.render() end
    function cancel.write(self, section)
      if not http.formvalue("_cancel_tproxy_main") then return end
      redirect_here("tproxy")
    end
  end

  -- Сообщения
  do
    local msg = m:section(SimpleSection); local dv = msg:option(DummyValue, "_tpx_msgs"); dv.rawhtml = true
    function dv.cfgvalue()
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