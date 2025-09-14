#!/bin/sh
# Xray TPROXY via nftables (IPv4+IPv6, multi-iface, SRC only/bypass) — OpenWrt friendly
#
# Описание:
#   Скрипт настраивает прозрачное проксирование (TPROXY) трафика через nftables
#   для IPv4/IPv6 на OpenWrt с nft v1.1.1. Работает идемпотентно: перед стартом
#   очищает созданные им правила маршрутизации и nft-таблицу.
#
# Возможности:
# - Несколько интерфейсов-источников (LAN_IFACES), по умолчанию br-lan; можно перечислять: "br-lan wg0 tun0".
# - Режим портов: "bypass" (исключить перечисленные) | "only" (проксировать ТОЛЬКО перечисленные).
# - Режимы по источникам (SRC_MODE): off | only | bypass.
# - Исключения по dst (приватные/пользовательские/on-link/порты) применяются в любом SRC_MODE.
# - Совместимо с nft v1.1.1: без auto-merge и без "return invert".
# - Идемпотентно: перед start чистим свои ip rule/route и nft-таблицу.
# - Полное отключение IPv6 по флагу ENV IPV6_ENABLED=0 или UCI option ipv6_enabled '0'.
#
# --------------------------- UCI КОНФИГ (опционально) ---------------------------
#   config main 'main'
#     option log_enabled '1'
#     option nft_table    'xray'
#     option ifaces       'br-lan wg0'
#     option ipv6_enabled '1'
#     option tproxy_port      '61219'
#     option tproxy_port_tcp  '61219'
#     option tproxy_port_udp  '61219'
#     option fwmark_tcp  '0x1'
#     option fwmark_udp  '0x2'
#     option rttab_tcp   '100'
#     option rttab_udp   '101'
#     option port_mode   'bypass'    # bypass|only
#     option ports_file  '/etc/xray/xray-tproxy.ports'
#     option bypass_v4_file '/etc/xray/xray-tproxy.v4'
#     option bypass_v6_file '/etc/xray/xray-tproxy.v6'
#     option src_mode          'off' # off|only|bypass
#     option src_only_v4_file  '/etc/xray/xray-tproxy.src4.only'
#     option src_only_v6_file  '/etc/xray/xray-tproxy.src6.only'
#     option src_bypass_v4_file '/etc/xray/xray-tproxy.src4.bypass'
#     option src_bypass_v6_file '/etc/xray/xray-tproxy.src6.bypass'
#
# ПОРТ-ФАЙЛ (пример):
#   80
#   tcp:443
#   udp:53
#   both:123
#   1000-2000
#   udp:6000-7000
#
# Запуск:
#   xray-tproxy start [-q] [bypass|only]
#   xray-tproxy restart [-q] [bypass|only]
#   xray-tproxy stop|status|diag [-q]

set -eu
# set -e : падать при ошибке любой команды
# set -u : падать при обращении к несуществующим переменным

# ===== ДЕФОЛТЫ (ENV/UCI могут перекрыть) =====
# Базовые параметры TPROXY-портов, меток и таблиц маршрутизации
TPORT_DEFAULT="${TPORT_DEFAULT:-61219}"
TPORT_TCP="${TPORT_TCP:-$TPORT_DEFAULT}"
TPORT_UDP="${TPORT_UDP:-$TPORT_DEFAULT}"

FWMARK_TCP="${FWMARK_TCP:-0x1}"
FWMARK_UDP="${FWMARK_UDP:-0x2}"
RTTAB_TCP="${RTTAB_TCP:-100}"
RTTAB_UDP="${RTTAB_UDP:-101}"

# Настраиваемые приоритеты ip rule
RULE_PRIO_TCP="${RULE_PRIO_TCP:-10000}"
RULE_PRIO_UDP="${RULE_PRIO_UDP:-10001}"

# Имя nft-таблицы и список интерфейсов источника
NFT_TABLE="${NFT_TABLE:-xray}"
LAN_IFACES="${LAN_IFACES:-br-lan}"

# Файлы с исключениями/портами
BYPASS_V4_FILE="${BYPASS_V4_FILE:-/etc/xray/xray-tproxy.v4}"
BYPASS_V6_FILE="${BYPASS_V6_FILE:-/etc/xray/xray-tproxy.v6}"
BYPASS_PORTS_FILE="${BYPASS_PORTS_FILE:-/etc/xray/xray-tproxy.ports}"

# Режимы по источникам: off|only|bypass и файлы для них
SRC_MODE="${SRC_MODE:-off}"  # off|only|bypass
SRC_ONLY_V4_FILE="${SRC_ONLY_V4_FILE:-/etc/xray/xray-tproxy.src4.only}"
SRC_ONLY_V6_FILE="${SRC_ONLY_V6_FILE:-/etc/xray/xray-tproxy.src6.only}"
SRC_BYPASS_V4_FILE="${SRC_BYPASS_V4_FILE:-/etc/xray/xray-tproxy.src4.bypass}"
SRC_BYPASS_V6_FILE="${SRC_BYPASS_V6_FILE:-/etc/xray/xray-tproxy.src6.bypass}"

# Режим портов по умолчанию
PORT_MODE_DEFAULT="${PORT_MODE_DEFAULT:-bypass}"  # bypass|only

# Встроенные приватные сети (v4/v6), не отправляем в прокси
BYPASS_CIDRS4_DEFAULT="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8 169.254.0.0/16 224.0.0.0/4 240.0.0.0/4 100.64.0.0/10"
BYPASS_CIDRS6_DEFAULT="::1/128 fc00::/7 fe80::/10 ff00::/8"

# Логирование
LOGGER_TAG="${LOGGER_TAG:-xray-tproxy}"
LOG_ENABLED="${LOG_ENABLED:-1}"
QUIET="${QUIET:-0}"

# Включение IPv6
IPV6_ENABLED="${IPV6_ENABLED:-1}"

# ===== ХЕЛПЕРЫ =====
# say/log: единая точка вывода в stdout/syslog
say(){ [ "$QUIET" -eq 1 ] && return 0; echo "$*"; }
log(){ [ "$LOG_ENABLED" -eq 1 ] && logger -t "$LOGGER_TAG" -- "$*"; [ "$QUIET" -eq 1 ] || echo "$LOGGER_TAG: $*"; }

# preflight: проверка наличия необходимых утилит (BusyBox)
preflight(){
  for b in nft ip awk sed grep mktemp tr cut sort xargs; do
    command -v "$b" >/dev/null 2>&1 || { say "missing binary: $b"; exit 1; }
  done
}

# usage: краткая справка по CLI
usage(){
  cat <<EOF
Usage: $0 [-q] {start|stop|restart|status|diag} [bypass|only]
Flags:
  -q, --quiet      Quiet mode.

ENV:
  IPV6_ENABLED=0   Disable IPv6 completely.
  RULE_PRIO_TCP / RULE_PRIO_UDP  (defaults: 10000 / 10001)

Ports file ($BYPASS_PORTS_FILE) examples:
  80
  tcp:443
  udp:53
  1000-2000
  udp:6000-7000
EOF
}

# parse_args: разбор аргументов команды и режима портов
parse_args(){
  QUIET=0; CMD=""; MODE_ARG=""
  while [ $# -gt 0 ]; do
    case "$1" in
      -q|--quiet) QUIET=1; shift ;;
      start|stop|restart|status|diag) CMD="$1"; shift; case "${1:-}" in bypass|only) MODE_ARG="$1"; shift ;; esac ;;
      bypass|only) MODE_ARG="$1"; shift ;;
      *) usage; exit 1 ;;
    esac
  done
  [ -n "$CMD" ] || { usage; exit 1; }
  SET_CMD="$CMD"; SET_MODE="${MODE_ARG:-$PORT_MODE_DEFAULT}"
}

# ===== UCI =====
# load_uci: подстановка конфигурации из UCI (если есть секция xray-proxy.main)
load_uci(){
  u_table="$(uci -q get xray-proxy.main.nft_table 2>/dev/null || echo "")"
  u_ifaces="$(uci -q get xray-proxy.main.ifaces 2>/dev/null || echo "")"
  u_log="$(uci -q get xray-proxy.main.log_enabled 2>/dev/null || echo "")"
  u_ipv6="$(uci -q get xray-proxy.main.ipv6_enabled 2>/dev/null || echo "")"
  [ -n "$u_table" ]  && NFT_TABLE="$u_table"
  [ -n "$u_ifaces" ] && LAN_IFACES="$u_ifaces"
  case "$u_log" in 0|1) LOG_ENABLED="$u_log" ;; esac
  case "$u_ipv6" in 0|1) IPV6_ENABLED="$u_ipv6" ;; esac

  u_tport="$(uci -q get xray-proxy.main.tproxy_port 2>/dev/null || echo "")"
  u_tport_tcp="$(uci -q get xray-proxy.main.tproxy_port_tcp 2>/dev/null || echo "")"
  u_tport_udp="$(uci -q get xray-proxy.main.tproxy_port_udp 2>/dev/null || echo "")"
  if [ -n "$u_tport" ]; then TPORT_TCP="$u_tport"; TPORT_UDP="$u_tport"; fi
  [ -n "$u_tport_tcp" ] && TPORT_TCP="$u_tport_tcp"
  [ -n "$u_tport_udp" ] && TPORT_UDP="$u_tport_udp"

  u_fwmark_tcp="$(uci -q get xray-proxy.main.fwmark_tcp 2>/dev/null || echo "")"
  u_fwmark_udp="$(uci -q get xray-proxy.main.fwmark_udp 2>/dev/null || echo "")"
  u_rttab_tcp="$(uci -q get xray-proxy.main.rttab_tcp 2>/dev/null || echo "")"
  u_rttab_udp="$(uci -q get xray-proxy.main.rttab_udp 2>/dev/null || echo "")"
  [ -n "$u_fwmark_tcp" ] && FWMARK_TCP="$u_fwmark_tcp"
  [ -n "$u_fwmark_udp" ] && FWMARK_UDP="$u_fwmark_udp"
  [ -n "$u_rttab_tcp" ] && RTTAB_TCP="$u_rttab_tcp"
  [ -n "$u_rttab_udp" ] && RTTAB_UDP="$u_rttab_udp"

  u_mode="$(uci -q get xray-proxy.main.port_mode 2>/dev/null || echo "")"
  u_ports_file="$(uci -q get xray-proxy.main.ports_file 2>/dev/null || echo "")"
  case "$u_mode" in bypass|only) PORT_MODE_DEFAULT="$u_mode" ;; esac
  [ -n "$u_ports_file" ] && BYPASS_PORTS_FILE="$u_ports_file"

  u_bypass_v4="$(uci -q get xray-proxy.main.bypass_v4_file 2>/dev/null || echo "")"
  u_bypass_v6="$(uci -q get xray-proxy.main.bypass_v6_file 2>/dev/null || echo "")"
  [ -n "$u_bypass_v4" ] && BYPASS_V4_FILE="$u_bypass_v4"
  [ -n "$u_bypass_v6" ] && BYPASS_V6_FILE="$u_bypass_v6"

  u_srcmode="$(uci -q get xray-proxy.main.src_mode 2>/dev/null || echo "")"
  u_src_only4="$(uci -q get xray-proxy.main.src_only_v4_file 2>/dev/null || echo "")"
  u_src_only6="$(uci -q get xray-proxy.main.src_only_v6_file 2>/dev/null || echo "")"
  u_src_byp4="$(uci -q get xray-proxy.main.src_bypass_v4_file 2>/dev/null || echo "")"
  u_src_byp6="$(uci -q get xray-proxy.main.src_bypass_v6_file 2>/dev/null || echo "")"
  case "$u_srcmode" in off|only|bypass) SRC_MODE="$u_srcmode" ;; esac
  [ -n "$u_src_only4" ] && SRC_ONLY_V4_FILE="$u_src_only4"
  [ -n "$u_src_only6" ] && SRC_ONLY_V6_FILE="$u_src_only6"
  [ -n "$u_src_byp4" ]  && SRC_BYPASS_V4_FILE="$u_src_byp4"
  [ -n "$u_src_byp6" ]  && SRC_BYPASS_V6_FILE="$u_src_byp6"
}

# ===== IO/ПАРСИНГ =====
# read_lines_file: читает файл, убирая CR, комментарии, хвостовые пробелы и пустые строки
read_lines_file(){ [ -f "$1" ] || return 0; sed -e 's/\r$//' -e 's/#.*$//' -e 's/[[:space:]]\+$//' -e '/^[[:space:]]*$/d' "$1"; }

# detect_lan4_all/detect_lan6_all: собирают все адреса из указанных интерфейсов
detect_lan4_all(){
  for i in $LAN_IFACES; do
    ip -4 -o addr show "$i" 2>/dev/null | awk '{print $4}'
  done
}
detect_lan6_all(){
  [ "$IPV6_ENABLED" -eq 1 ] || return 0
  for i in $LAN_IFACES; do
    ip -6 -o addr show "$i" 2>/dev/null | awk '{print $4}' | grep -v '^fe80' || true
  done
}

# collect_direct4/6: on-link маршруты только по LAN_IFACES
collect_direct4(){
  for i in $LAN_IFACES; do
    ip -4 -o route show scope link dev "$i" 2>/dev/null | awk '{print $1}'
  done | grep -vE '^(default|0\.0\.0\.0/0)$' | sort -u || true
}
collect_direct6(){
  [ "$IPV6_ENABLED" -eq 1 ] || return 0
  for i in $LAN_IFACES; do
    ip -6 -o route show scope link dev "$i" 2>/dev/null | awk '{print $1}'
  done | grep -vE '^(default|::/0|fe80::/64)$' | sort -u || true
}

# join_commas: преобразует список в формат "a, b, c"
join_commas(){ [ $# -eq 0 ] && return 0; printf "%s" "$1"; shift; for x in "$@"; do printf ", %s" "$x"; done; }

# ===== ДОП. ВАЛИДАЦИИ (п.4 и п.8) =====
# valid_port: 1..65535
valid_port(){ p="$1"; [ "$p" -ge 1 ] && [ "$p" -le 65535 ]; }

# validate_marks: защита от пересечения битов меток и нулевых значений
validate_marks(){
  mt=$((FWMARK_TCP))
  mu=$((FWMARK_UDP))
  [ "$mt" -ne 0 ] && [ "$mu" -ne 0 ] || { say "error: fwmark must be non-zero"; exit 1; }
  [ $(( mt & mu )) -eq 0 ] || { say "error: fwmark bits overlap"; exit 1; }
}

# validate_tports: проверка валидности TPROXY-портов
validate_tports(){
  for p in "$TPORT_TCP" "$TPORT_UDP"; do
    printf "%s" "$p" | grep -Eq '^[0-9]{1,5}$' && [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || {
      say "error: invalid TPROXY port: $p"; exit 1; }
  done
}

# ===== МАРШРУТИЗАЦИЯ =====
# apply_iprules: создаёт ip rule и локальные маршруты для TPROXY (v4/v6)
apply_iprules(){
  ip    rule add fwmark "$FWMARK_TCP/$FWMARK_TCP" lookup "$RTTAB_TCP" priority "$RULE_PRIO_TCP" 2>/dev/null || true
  ip    route add local 0.0.0.0/0 dev lo table "$RTTAB_TCP" 2>/dev/null || true
  if [ "$IPV6_ENABLED" -eq 1 ]; then
    ip -6 rule add fwmark "$FWMARK_TCP/$FWMARK_TCP" lookup "$RTTAB_TCP" priority "$RULE_PRIO_TCP" 2>/dev/null || true
    ip -6 route add local ::/0       dev lo table "$RTTAB_TCP" 2>/dev/null || true
  fi

  ip    rule add fwmark "$FWMARK_UDP/$FWMARK_UDP" lookup "$RTTAB_UDP" priority "$RULE_PRIO_UDP" 2>/dev/null || true
  ip    route add local 0.0.0.0/0 dev lo table "$RTTAB_UDP" 2>/dev/null || true
  if [ "$IPV6_ENABLED" -eq 1 ]; then
    ip -6 rule add fwmark "$FWMARK_UDP/$FWMARK_UDP" lookup "$RTTAB_UDP" priority "$RULE_PRIO_UDP" 2>/dev/null || true
    ip -6 route add local ::/0       dev lo table "$RTTAB_UDP" 2>/dev/null || true
  fi
}

# remove_iprules: удаляет ранее созданные ip rule и чистит таблицы маршрутов
remove_iprules(){
  ip    rule del fwmark "$FWMARK_TCP/$FWMARK_TCP" lookup "$RTTAB_TCP" priority "$RULE_PRIO_TCP" 2>/dev/null || true
  ip    rule del fwmark "$FWMARK_UDP/$FWMARK_UDP" lookup "$RTTAB_UDP" priority "$RULE_PRIO_UDP" 2>/dev/null || true
  ip    route flush table "$RTTAB_TCP" 2>/dev/null || true
  ip    route flush table "$RTTAB_UDP" 2>/dev/null || true
  if [ "$IPV6_ENABLED" -eq 1 ]; then
    ip -6 rule del fwmark "$FWMARK_TCP/$FWMARK_TCP" lookup "$RTTAB_TCP" priority "$RULE_PRIO_TCP" 2>/dev/null || true
    ip -6 rule del fwmark "$FWMARK_UDP/$FWMARK_UDP" lookup "$RTTAB_UDP" priority "$RULE_PRIO_UDP" 2>/dev/null || true
    ip -6 route flush table "$RTTAB_TCP" 2>/dev/null || true
    ip -6 route flush table "$RTTAB_UDP" 2>/dev/null || true
  fi
}

# emit_set_block: утилита для декларации nft-сетов
emit_set_block(){ # $1 name, $2 type, $3 flags, $4 elements
  echo "  set $1 {"
  echo "    type $2;"
  [ -n "${3:-}" ] && echo "    $3"
  [ -n "${4:-}" ] && echo "    elements = { $4 }"
  echo "  }"
}

# ===== ПОРТЫ (bypass/only) =====
# parse_ports_file: читает файл портов и формирует два набора (TCP/UDP)
parse_ports_file(){
  TCP_PORTS=""; UDP_PORTS=""
  PORTS_TCP_FLAGS=""; PORTS_UDP_FLAGS=""
  [ -f "$BYPASS_PORTS_FILE" ] || { PORTS_TCP_SET=""; PORTS_UDP_SET=""; return 0; }

  while IFS= read -r raw; do
    line="${raw%%#*}"; line="$(printf "%s" "$line" | tr -d '\r')"
    line="$(printf "%s" "$line" | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
    [ -z "$line" ] && continue
    proto="both"; spec="$line"
    case "$line" in
      tcp:*)  proto="tcp";  spec="${line#tcp:}";;
      udp:*)  proto="udp";  spec="${line#udp:}";;
      both:*) proto="both"; spec="${line#both:}";;
      *) : ;;
    esac
    spec="$(printf "%s" "$spec" | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
    # (п.1) Более строгая проверка формата портов/диапазонов
    printf "%s" "$spec" | grep -Eq '^[0-9]{1,5}(-[0-9]{1,5})?$' || continue
    # (п.1) Числовая валидация диапазона и портов (1..65535, L<=R)
    case "$spec" in
      *-*)
        L="${spec%-*}"; R="${spec#*-}"
        if ! valid_port "$L" || ! valid_port "$R" || [ "$L" -gt "$R" ]; then
          continue
        fi
        ;;
      *)
        if ! valid_port "$spec"; then
          continue
        fi
        ;;
    esac
    case "$proto" in
      tcp)  TCP_PORTS="$TCP_PORTS $spec" ;;
      udp)  UDP_PORTS="$UDP_PORTS $spec" ;;
      both) TCP_PORTS="$TCP_PORTS $spec"; UDP_PORTS="$UDP_PORTS $spec" ;;
    esac
  done < "$BYPASS_PORTS_FILE"

  # (п.2) Включаем flags interval, если в списках есть диапазоны
  printf "%s" " $TCP_PORTS " | grep -q -- '-' && PORTS_TCP_FLAGS="flags interval;"
  printf "%s" " $UDP_PORTS " | grep -q -- '-' && PORTS_UDP_FLAGS="flags interval;"

  PORTS_TCP_SET="$( [ -n "$TCP_PORTS" ] && join_commas $TCP_PORTS || printf "" )"
  PORTS_UDP_SET="$( [ -n "$UDP_PORTS" ] && join_commas $UDP_PORTS || printf "" )"
}

# ===== СБОР СЕТОВ =====
# build_sets: формирует наборы исключений/адресов/портов на основе дефолтов и файлов
build_sets(){
  # v4 dst bypass
  CIDR4_LIST="$BYPASS_CIDRS4_DEFAULT"; HOST4_LIST=""
  if [ -f "$BYPASS_V4_FILE" ]; then
    while IFS= read -r it; do
      it="${it%%#*}"
      it="$(printf "%s" "$it" | tr -d '\r' | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
      [ -z "$it" ] && continue
      case "$it" in */*) CIDR4_LIST="$CIDR4_LIST $it";; *) HOST4_LIST="$HOST4_LIST $it";; esac
    done < "$BYPASS_V4_FILE"
  fi
  # Дедуп v4
  CIDR4_LIST="$(printf "%s\n" $CIDR4_LIST | awk 'NF' | sort -u | xargs || true)"
  HOST4_LIST="$(printf "%s\n" $HOST4_LIST | awk 'NF' | sort -u | xargs || true)"
  BYPASS_CIDR4_SET="$( [ -n "${CIDR4_LIST:-}" ] && join_commas $CIDR4_LIST || printf "" )"
  BYPASS_HOST4_SET="$( [ -n "${HOST4_LIST:-}" ] && join_commas $HOST4_LIST || printf "" )"

  # v6 dst bypass
  CIDR6_LIST=""; HOST6_LIST=""
  if [ "$IPV6_ENABLED" -eq 1 ]; then
    CIDR6_LIST="$BYPASS_CIDRS6_DEFAULT"
    if [ -f "$BYPASS_V6_FILE" ]; then
      while IFS= read -r it; do
        it="${it%%#*}"
        it="$(printf "%s" "$it" | tr -d '\r' | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
        [ -z "$it" ] && continue
        case "$it" in */*) CIDR6_LIST="$CIDR6_LIST $it";; *) HOST6_LIST="$HOST6_LIST $it";; esac
      done < "$BYPASS_V6_FILE"
    fi
    # Дедуп v6
    CIDR6_LIST="$(printf "%s\n" $CIDR6_LIST | awk 'NF' | sort -u | xargs || true)"
    HOST6_LIST="$(printf "%s\n" $HOST6_LIST | awk 'NF' | sort -u | xargs || true)"
  fi
  BYPASS_CIDR6_SET="$( [ -n "${CIDR6_LIST:-}" ] && join_commas $CIDR6_LIST || printf "" )"
  BYPASS_HOST6_SET="$( [ -n "${HOST6_LIST:-}" ] && join_commas $HOST6_LIST || printf "" )"

  # direct (on-link)
  DIRECT4_LIST="$(collect_direct4)"
  DIRECT6_LIST="$(collect_direct6)"
  DIRECT4_SET="$( [ -n "${DIRECT4_LIST:-}" ] && join_commas $DIRECT4_LIST || printf "" )"
  DIRECT6_SET="$( [ -n "${DIRECT6_LIST:-}" ] && join_commas $DIRECT6_LIST || printf "" )"

  # ports
  parse_ports_file

  # SRC only/bypass lists
  SRC_ONLY4_LIST=""; SRC_ONLY6_LIST=""; SRC_BYP4_LIST=""; SRC_BYP6_LIST=""
  if [ -f "$SRC_ONLY_V4_FILE" ]; then
    while IFS= read -r it; do
      it="${it%%#*}"; it="$(printf "%s" "$it" | tr -d '\r' | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
      [ -z "$it" ] || SRC_ONLY4_LIST="$SRC_ONLY4_LIST $it"
    done < "$SRC_ONLY_V4_FILE"
  fi
  if [ "$IPV6_ENABLED" -eq 1 ] && [ -f "$SRC_ONLY_V6_FILE" ]; then
    while IFS= read -r it; do
      it="${it%%#*}"; it="$(printf "%s" "$it" | tr -d '\r' | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
      [ -z "$it" ] || SRC_ONLY6_LIST="$SRC_ONLY6_LIST $it"
    done < "$SRC_ONLY_V6_FILE"
  fi
  if [ -f "$SRC_BYPASS_V4_FILE" ]; then
    while IFS= read -r it; do
      it="${it%%#*}"; it="$(printf "%s" "$it" | tr -d '\r' | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
      [ -z "$it" ] || SRC_BYP4_LIST="$SRC_BYP4_LIST $it"
    done < "$SRC_BYPASS_V4_FILE"
  fi
  if [ "$IPV6_ENABLED" -eq 1 ] && [ -f "$SRC_BYPASS_V6_FILE" ]; then
    while IFS= read -r it; do
      it="${it%%#*}"; it="$(printf "%s" "$it" | tr -d '\r' | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
      [ -z "$it" ] || SRC_BYP6_LIST="$SRC_BYP6_LIST $it"
    done < "$SRC_BYPASS_V6_FILE"
  fi
  # Дедуп SRC-листов
  SRC_ONLY4_LIST="$(printf "%s\n" $SRC_ONLY4_LIST | awk 'NF' | sort -u | xargs || true)"
  SRC_ONLY6_LIST="$(printf "%s\n" $SRC_ONLY6_LIST | awk 'NF' | sort -u | xargs || true)"
  SRC_BYP4_LIST="$( printf "%s\n" $SRC_BYP4_LIST  | awk 'NF' | sort -u | xargs || true)"
  SRC_BYP6_LIST="$( printf "%s\n" $SRC_BYP6_LIST  | awk 'NF' | sort -u | xargs || true)"

  SRC_ONLY4_SET="$( [ -n "${SRC_ONLY4_LIST:-}" ] && join_commas $SRC_ONLY4_LIST || printf "" )"
  SRC_ONLY6_SET="$( [ -n "${SRC_ONLY6_LIST:-}" ] && join_commas $SRC_ONLY6_LIST || printf "" )"
  SRC_BYP4_SET="$(  [ -n "${SRC_BYP4_LIST:-}"  ] && join_commas $SRC_BYP4_LIST  || printf "" )"
  SRC_BYP6_SET="$(  [ -n "${SRC_BYP6_LIST:-}"  ] && join_commas $SRC_BYP6_LIST  || printf "" )"
}

# LAN-сеты по всем интерфейсам (для фильтрации источников по их подсетям)
emit_lan_sets(){
  HAVE_LAN4=0; HAVE_LAN6=0
  LAN4_ELEMS="$(detect_lan4_all | awk '{printf "%s, ", $1}' | sed 's/, $//')"
  [ -n "$LAN4_ELEMS" ] && { emit_set_block "lan_saddr4" "ipv4_addr" "flags interval;" "$LAN4_ELEMS"; HAVE_LAN4=1; }
  if [ "$IPV6_ENABLED" -eq 1 ]; then
    LAN6_ELEMS="$(detect_lan6_all | awk '{printf "%s, ", $1}' | sed 's/, $//')"
    [ -n "$LAN6_ELEMS" ] && { emit_set_block "lan_saddr6" "ipv6_addr" "flags interval;" "$LAN6_ELEMS"; HAVE_LAN6=1; }
  fi
}

# ===== NFT APPLY =====
# apply_nft: строит конфиг nft из временного файла и атомарно применяет его
apply_nft(){
  build_sets

  PORT_MODE="${1:-$PORT_MODE_DEFAULT}"  # bypass|only
  nft delete table inet "$NFT_TABLE" >/dev/null 2>&1 || true

  # атомарная подмена: сначала пишем в tmp, затем --check и применение
  tmpfile="$(mktemp)"
  trap 'rm -f "$tmpfile"' EXIT INT TERM
  {
    echo "table inet $NFT_TABLE {"
    emit_lan_sets
    emit_set_block "bypass_cidrs"  "ipv4_addr" "flags interval;" "$BYPASS_CIDR4_SET"
    emit_set_block "bypass_hosts"  "ipv4_addr" ""                "$BYPASS_HOST4_SET"
    if [ "$IPV6_ENABLED" -eq 1 ]; then
      emit_set_block "bypass_cidrs6" "ipv6_addr" "flags interval;" "$BYPASS_CIDR6_SET"
      emit_set_block "bypass_hosts6" "ipv6_addr" ""                "$BYPASS_HOST6_SET"
    fi
    emit_set_block "direct_cidrs"  "ipv4_addr" "flags interval;" "$DIRECT4_SET"
    [ "$IPV6_ENABLED" -eq 1 ] && emit_set_block "direct_cidrs6" "ipv6_addr" "flags interval;" "$DIRECT6_SET"
    # (п.2) Сеты портов с условным flags interval;
    emit_set_block "ports_tcp"     "inet_service" "$PORTS_TCP_FLAGS" "$PORTS_TCP_SET"
    emit_set_block "ports_udp"     "inet_service" "$PORTS_UDP_FLAGS" "$PORTS_UDP_SET"
    emit_set_block "src_only4"     "ipv4_addr" "flags interval;" "$SRC_ONLY4_SET"
    [ "$IPV6_ENABLED" -eq 1 ] && emit_set_block "src_only6"     "ipv6_addr" "flags interval;" "$SRC_ONLY6_SET"
    emit_set_block "src_bypass4"   "ipv4_addr" "flags interval;" "$SRC_BYP4_SET"
    [ "$IPV6_ENABLED" -eq 1 ] && emit_set_block "src_bypass6"   "ipv6_addr" "flags interval;" "$SRC_BYP6_SET"

    echo "  chain prerouting {"
    # ВАЖНО: приоритет не меняем (как вы просили), оставляем alias 'filter'
    echo "    type filter hook prerouting priority filter; policy accept;"

    # (п.3) Ранний отсев не-TCP/UDP
    echo "    meta l4proto != { tcp, udp } return"

    # Уже помеченный трафик — не трогаем (исключаем повторную обработку)
    echo "    meta l4proto tcp meta mark & $FWMARK_TCP == $FWMARK_TCP return"
    echo "    meta l4proto udp meta mark & $FWMARK_UDP == $FWMARK_UDP return"

    # Локальные/мультикаст/бродкаст — пропускаем
    echo "    fib daddr type { local, multicast, broadcast } return"

    # Гейт по LAN-подсетям (обрабатываем только трафик из нужных внутренних сетей)
    [ "${HAVE_LAN4:-0}" -eq 1 ] && echo "    ip  saddr != @lan_saddr4 return"
    if [ "$IPV6_ENABLED" -eq 1 ]; then
      [ "${HAVE_LAN6:-0}" -eq 1 ] && echo "    ip6 saddr != @lan_saddr6 return"
    fi

    # SRC режимы: only/bypass по спискам источников
    case "$SRC_MODE" in
      only)
        [ -n "$SRC_ONLY4_SET" ] && echo "    ip  saddr != @src_only4 return"
        if [ "$IPV6_ENABLED" -eq 1 ]; then
          [ -n "$SRC_ONLY6_SET" ] && echo "    ip6 saddr != @src_only6 return"
        fi
        ;;
      bypass)
        [ -n "$SRC_BYP4_SET" ]  && echo "    ip  saddr @src_bypass4 return"
        if [ "$IPV6_ENABLED" -eq 1 ]; then
          [ -n "$SRC_BYP6_SET" ]  && echo "    ip6 saddr @src_bypass6 return"
        fi
        ;;
      *) : ;;
    esac

    # Исключить on-link (dst)
    echo "    ip  daddr @direct_cidrs  return"
    [ "$IPV6_ENABLED" -eq 1 ] && echo "    ip6 daddr @direct_cidrs6 return"

    # Исключить приватные/пользовательские dst сети/хосты
    echo "    ip  daddr @bypass_cidrs  return"
    echo "    ip  daddr @bypass_hosts  return"
    if [ "$IPV6_ENABLED" -eq 1 ]; then
      echo "    ip6 daddr @bypass_cidrs6 return"
      echo "    ip6 daddr @bypass_hosts6 return"
    fi

    # --- Портовая логика ---
    if [ "$PORT_MODE" = "bypass" ]; then
      # В режиме bypass перечисленные порты пропускаются мимо прокси
      [ -n "$PORTS_TCP_SET" ] && echo "    tcp dport @ports_tcp return"
      [ -n "$PORTS_UDP_SET" ] && echo "    udp dport @ports_udp return"
      # Всё остальное — в TPROXY (v4/v6)
      echo "    meta l4proto tcp meta mark set $FWMARK_TCP tproxy ip  to 127.0.0.1:$TPORT_TCP accept"
      echo "    meta l4proto udp meta mark set $FWMARK_UDP tproxy ip  to 127.0.0.1:$TPORT_UDP accept"
      if [ "$IPV6_ENABLED" -eq 1 ]; then
        echo "    ip6 nexthdr tcp meta mark set $FWMARK_TCP tproxy ip6 to :$TPORT_TCP accept"
        echo "    ip6 nexthdr udp meta mark set $FWMARK_UDP tproxy ip6 to :$TPORT_UDP accept"
      fi
    else
      # В режиме only — проксируем ТОЛЬКО перечисленные порты
      [ -n "$PORTS_TCP_SET" ] && echo "    meta l4proto tcp tcp dport @ports_tcp meta mark set $FWMARK_TCP tproxy ip  to 127.0.0.1:$TPORT_TCP accept"
      [ -n "$PORTS_UDP_SET" ] && echo "    meta l4proto udp udp dport @ports_udp meta mark set $FWMARK_UDP tproxy ip  to 127.0.0.1:$TPORT_UDP accept"
      if [ "$IPV6_ENABLED" -eq 1 ]; then
        [ -n "$PORTS_TCP_SET" ] && echo "    ip6 nexthdr tcp tcp dport @ports_tcp meta mark set $FWMARK_TCP tproxy ip6 to :$TPORT_TCP accept"
        [ -n "$PORTS_UDP_SET" ] && echo "    ip6 nexthdr udp udp dport @ports_udp meta mark set $FWMARK_UDP tproxy ip6 to :$TPORT_UDP accept"
      fi
      echo "    return"
    fi

    echo "  }" # prerouting
    echo "}"   # table
  } >"$tmpfile"

  if nft --check -f "$tmpfile"; then
    nft -f "$tmpfile"
  else
    say "nft validation failed"
    exit 1
  fi
  rm -f "$tmpfile"; trap - EXIT INT TERM
}

# remove_nft: удаление таблицы inet $NFT_TABLE (если есть)
remove_nft(){ nft delete table inet "$NFT_TABLE" 2>/dev/null || true; }

# diag: человекочитаемая диагностика текущей конфигурации/правил
diag(){
  # Обновим парсинг портов для корректного вывода
  parse_ports_file

  say "=== XRAY/TPROXY DIAG ==="
  say "[ifaces]        $LAN_IFACES"
  say "[src_mode]      $SRC_MODE"
  say "[port_mode]     ${SET_MODE:-$PORT_MODE_DEFAULT}"
  say "[IPv6]          $( [ "$IPV6_ENABLED" -eq 1 ] && echo enabled || echo disabled )"

  say "[LAN v4 subnets]"
  detect_lan4_all | sed 's/^/  /' || true
  if [ "$IPV6_ENABLED" -eq 1 ]; then
    say "[LAN v6 subnets]"
    detect_lan6_all | sed 's/^/  /' || true
  fi

  say "[ip rule]";    ip rule | grep -E "lookup ($RTTAB_TCP|$RTTAB_UDP)" || say "No IPv4 fwmark rules"
  if [ "$IPV6_ENABLED" -eq 1 ]; then
    say "[ip -6 rule]"; ip -6 rule | grep -E "lookup ($RTTAB_TCP|$RTTAB_UDP)" || say "No IPv6 fwmark rules"
  else
    say "[ip -6 rule]    IPv6 disabled"
  fi
  say "[route tables]"
  say "[IPv4 table $RTTAB_TCP]"; ip route show table "$RTTAB_TCP" || true
  say "[IPv4 table $RTTAB_UDP]"; ip route show table "$RTTAB_UDP" || true
  if [ "$IPV6_ENABLED" -eq 1 ]; then
    say "[IPv6 table $RTTAB_TCP]"; ip -6 route show table "$RTTAB_TCP" || true
    say "[IPv6 table $RTTAB_UDP]"; ip -6 route show table "$RTTAB_UDP" || true
  else
    say "[IPv6 tables]   IPv6 disabled"
  fi
  say "[nft $NFT_TABLE]"; nft -a list table inet "$NFT_TABLE" 2>/dev/null || say "No table inet $NFT_TABLE"
  say "--- Port file parsed ---"
  say "TCP ports: ${PORTS_TCP_SET:-<none>}"
  say "UDP ports: ${PORTS_UDP_SET:-<none>}"
  say "--- SRC files ---"
  say "[only v4]   $SRC_ONLY_V4_FILE:";   read_lines_file "$SRC_ONLY_V4_FILE"   | sed 's/^/  /' || true
  if [ "$IPV6_ENABLED" -eq 1 ]; then
    say "[only v6]   $SRC_ONLY_V6_FILE:";   read_lines_file "$SRC_ONLY_V6_FILE"   | sed 's/^/  /' || true
  else
    say "[only v6]   IPv6 disabled"
  fi
  say "[bypass v4] $SRC_BYPASS_V4_FILE:"; read_lines_file "$SRC_BYPASS_V4_FILE" | sed 's/^/  /' || true
  if [ "$IPV6_ENABLED" -eq 1 ]; then
    say "[bypass v6] $SRC_BYPASS_V6_FILE:"; read_lines_file "$SRC_BYPASS_V6_FILE" | sed 's/^/  /' || true
  else
    say "[bypass v6] IPv6 disabled"
  fi
  say "--- DST bypass files ---"
  say "[v4] $BYPASS_V4_FILE:"; read_lines_file "$BYPASS_V4_FILE" | sed 's/^/  /' || true
  if [ "$IPV6_ENABLED" -eq 1 ]; then
    say "[v6] $BYPASS_V6_FILE:"; read_lines_file "$BYPASS_V6_FILE" | sed 's/^/  /' || true
  else
    say "[v6] IPv6 disabled"
  fi
  say "[ports] $BYPASS_PORTS_FILE:"; read_lines_file "$BYPASS_PORTS_FILE" | sed 's/^/  /' || true
  say "========================"
}

# has_prerouting_chain: проверка наличия цепочки prerouting в нашей таблице
# Без 'nft -j' (JSON), т.к. в nft v1.1.1 этой опции ещё не было.
has_prerouting_chain(){
  nft list chain inet "$NFT_TABLE" prerouting >/dev/null 2>&1
}

# status: компактная проверка "жив/не жив" по ключевым артефактам
status(){
  if ! has_prerouting_chain; then
    say "inactive (nft: no prerouting)"; exit 1
  fi
  miss=0
  ip rule   | grep -q "fwmark $FWMARK_TCP" || { say "degraded (no IPv4 rule TCP)"; miss=1; }
  ip rule   | grep -q "fwmark $FWMARK_UDP" || { say "degraded (no IPv4 rule UDP)"; miss=1; }
  if [ "$IPV6_ENABLED" -eq 1 ]; then
    ip -6 rule| grep -q "fwmark $FWMARK_TCP" || { say "degraded (no IPv6 rule TCP)"; miss=1; }
    ip -6 rule| grep -q "fwmark $FWMARK_UDP" || { say "degraded (no IPv6 rule UDP)"; miss=1; }
  fi
  if [ "$miss" -eq 0 ]; then
    [ "$IPV6_ENABLED" -eq 1 ] && say "running" || say "running (IPv6 disabled)"
    exit 0
  else
    exit 1
  fi
}

# ===== Основные команды =====
# start: полный цикл применения — очистка, правила маршрутизации, nft и диагностика
start(){
  MODE="${1:-$PORT_MODE_DEFAULT}" # bypass|only
  case "$MODE" in bypass|only) ;; *) say "invalid port mode: $MODE (use bypass|only)"; exit 1;; esac
  preflight
  validate_marks     # (п.4)
  validate_tports    # (п.8)
  remove_nft
  remove_iprules
  apply_iprules
  apply_nft "$MODE"
  diag
}

# stop: полная деинициализация и диагностика остаточного состояния
stop(){ remove_nft; remove_iprules; diag; }

# restart: прокси к start с текущим режимом
restart(){ start "${1:-$PORT_MODE_DEFAULT}"; }

# ===== MAIN =====
# Загрузка UCI-конфига (если есть точная секция xray-proxy.main) — без grep по всему uci show
if command -v uci >/dev/null 2>&1; then
  if uci -q show xray-proxy.main >/dev/null 2>&1; then
    load_uci
  fi
fi

# Разбор аргументов и выполнение команды
parse_args "$@"

case "$SET_CMD" in
  start)   start "$SET_MODE" ;;
  stop)    stop ;;
  restart) restart "$SET_MODE" ;;
  status)  status ;;
  diag)    diag ;;
esac
