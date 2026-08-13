#!/bin/sh
#
# Проверяет, что примеры конфигов из документации живые.
#
# Runs ON THE ROUTER: каждый набор скармливается СВОЕМУ ядру его же средством
# проверки. Документация, которая не проходит проверку, хуже отсутствующей:
# пользователь копирует набор, получает отказ ядра и не понимает, он ошибся или
# пример.
#
# Safe on a live router: всё происходит во временном каталоге набора, ни один
# рабочий конфиг и ни один сервис не затрагивается.

set -u

BASE="${TPM_TEST_BASE:-/tmp/tpm-config-examples-test}"
EXAMPLES="${TPM_STAGE_EXAMPLES:-}"

rm -rf "$BASE"
mkdir -p "$BASE" || exit 1

pass=0
fail=0
skipped=0
failures=""

check() {
    _name="$1"; _got="$2"; _want="$3"
    if [ "$_got" = "$_want" ]; then
        pass=$((pass + 1)); printf '  PASS %s\n' "$_name"
    else
        fail=$((fail + 1))
        failures="$failures
  - $_name (got '$_got', want '$_want')"
        printf '  FAIL %s  <- got %s, want %s\n' "$_name" "'$_got'" "'$_want'"
    fi
}

group() { printf '\n== %s ==\n' "$1"; }

if [ -z "$EXAMPLES" ] || [ ! -d "$EXAMPLES" ]; then
    printf '(примеры не разложены на устройстве, набор пропущен)\n'
    printf '\n0 passed, 0 failed, 1 skipped\n'
    exit 0
fi

printf '(примеры под проверкой: %s)\n' "$EXAMPLES"

##########################################################################
group "РОЛИ: номера и имена одинаковы у всех ядер"
##########################################################################
# Расхождение в нумерации меняет порядок загрузки, а от него зависит, чей outbound
# окажется первым в собранном массиве.
for engine in xray mihomo sing-box; do
    dir="$EXAMPLES/$engine"
    [ -d "$dir" ] || { skipped=$((skipped + 1)); printf '  SKIP %s: примеров нет\n' "$engine"; continue; }
    roles="$(find "$dir" -maxdepth 1 -type f | sed 's|.*/||; s|\..*$||' | sort | tr '\n' ' ')"
    case "$engine" in
        xray) want="01-log 02-inbounds 03-outbounds-user 04-outbounds-managed 05-routing 06-policy " ;;
        *)    want="00-general 01-log 02-inbounds 03-outbounds-user 04-outbounds-managed 05-routing " ;;
    esac
    check "$engine: роли и их номера" "$roles" "$want"
done

##########################################################################
group "ДЕФОЛТЫ: примеры совпадают с тем, что сеет пакет"
##########################################################################
# Порты в примерах должны быть теми же, что в uci-defaults, иначе скопированный
# набор не совпадёт с настройками TPROXY и трафик не пойдёт.
# Комментарии этих же примеров упоминают порты в прозе, поэтому строки
# комментариев отбрасываются: считаем настройку, а не документацию к ней.
config_only() { grep -vE '^[[:space:]]*(//|#)' "$1"; }

check "socks-порт 10808 во входящих Xray" \
    "$(config_only "$EXAMPLES/xray/02-inbounds.json" | grep -c '10808')" "1"
check "TPROXY-порт 61219 во входящих Xray" \
    "$(config_only "$EXAMPLES/xray/02-inbounds.json" | grep -c '61219')" "2"
check "socks-порт 10808 во входящих Mihomo" \
    "$(config_only "$EXAMPLES/mihomo/02-inbounds.yaml" | grep -c '10808')" "1"
check "TPROXY-порт 61219 во входящих Mihomo" \
    "$(config_only "$EXAMPLES/mihomo/02-inbounds.yaml" | grep -c '61219')" "1"
check "socks-порт 10808 во входящих sing-box" \
    "$(config_only "$EXAMPLES/sing-box/02-inbounds.json" | grep -c '10808')" "1"
check "TPROXY-порт 61219 во входящих sing-box" \
    "$(config_only "$EXAMPLES/sing-box/02-inbounds.json" | grep -c '61219')" "1"

# Завершающее правило обязательно, и цель у всех одна.
check "Xray: завершающее правило ведёт в proxy" \
    "$(grep -c '"outboundTag": "proxy"' "$EXAMPLES/xray/05-routing.json")" "1"
check "Mihomo: завершающее правило ведёт в proxy" \
    "$(grep -c '^  - MATCH,proxy$' "$EXAMPLES/mihomo/05-routing.yaml")" "1"
check "sing-box: завершающее правило ведёт в proxy" \
    "$(grep -c '"final": "proxy"' "$EXAMPLES/sing-box/05-routing.json")" "1"

# Провайдер Mihomo должен указывать на тот файл, который пишет пакет.
check "Mihomo: провайдер ссылается на управляемый файл" \
    "$(config_only "$EXAMPLES/mihomo/04-outbounds-managed.yaml" | grep -c 'tproxy-manager-proxies.yaml')" "1"

# Ни одной текстовой заглушки: примеры должны проходить проверку как есть.
check "нет нерабочих заглушек ни в одном примере" \
    "$(grep -rlE 'ЗАМЕНИТЕ_НА|ЗАПОЛНЯЕТСЯ_ИЗ|your-server' "$EXAMPLES" 2>/dev/null | wc -l | tr -d ' ')" "0"

##########################################################################
group "ЯДРА: каждый набор принят своим ядром"
##########################################################################
XRAY="$(command -v xray || echo /usr/bin/xray)"
MIHOMO="$(command -v mihomo || echo /usr/bin/mihomo)"
SINGBOX="$(command -v sing-box || echo /usr/bin/sing-box)"

if [ -x "$XRAY" ]; then
    "$XRAY" -test -confdir "$EXAMPLES/xray" >"$BASE/xray.log" 2>&1
    check "xray -test принимает каталог примеров" "$?" "0"
    [ -s "$BASE/xray.log" ] && grep -qi "Configuration OK" "$BASE/xray.log" \
        && check "  и говорит Configuration OK" "yes" "yes"
else
    skipped=$((skipped + 2)); printf '  SKIP xray не установлен\n'
fi

if [ -x "$SINGBOX" ]; then
    "$SINGBOX" check -C "$EXAMPLES/sing-box" >"$BASE/singbox.log" 2>&1
    check "sing-box check принимает каталог примеров" "$?" "0"
else
    skipped=$((skipped + 1)); printf '  SKIP sing-box не установлен\n'
fi

if [ -x "$MIHOMO" ]; then
    # Mihomo читает один файл, поэтому фрагменты склеиваются -- ровно так же, как
    # это делает assemble-config на живой системе.
    cat "$EXAMPLES"/mihomo/*.yaml > "$BASE/config.yaml"
    # Рабочим каталогом берём каталог ядра: там уже лежат GeoIP.dat и GeoSite.dat,
    # и туда же разрешается относительный путь провайдера. Копировать их в /tmp
    # (21 МБ) во время общего прогона стоило ядру убийства по памяти.
    home="$(dirname "${MIHOMO_HOME:-/etc/mihomo/x}")"
    [ -d "$home" ] || home=/etc/mihomo
    if [ -f "$home/tproxy-manager-proxies.yaml" ] && [ -f "$home/GeoIP.dat" ]; then
        "$MIHOMO" -d "$home" -t -f "$BASE/config.yaml" >"$BASE/mihomo.log" 2>&1
        check "mihomo -t принимает собранные примеры" "$?" "0"
    else
        skipped=$((skipped + 1))
        printf '  SKIP mihomo: в %s нет управляемого файла или гео-баз\n' "$home"
    fi

    # Пересечение верхнеуровневых ключей ломает склейку молча, поэтому его тоже
    # проверяем: при дубле последний фрагмент затирает предыдущий.
    dups="$(grep -hE '^[a-z][a-z0-9_-]*:' "$EXAMPLES"/mihomo/*.yaml | sed 's/:.*/:/' | sort | uniq -d | tr '\n' ' ')"
    check "  ключи фрагментов Mihomo не пересекаются" "$dups" ""
else
    skipped=$((skipped + 2)); printf '  SKIP mihomo не установлен\n'
fi

rm -rf "$BASE"

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skipped"
if [ "$fail" -gt 0 ]; then
    printf 'failures:%s\n' "$failures"
    exit 1
fi
exit 0
