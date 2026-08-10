#!/bin/sh
# TPROXY via nftables (IPv4+IPv6, multi-iface, SRC only/bypass) — OpenWrt friendly
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
#     option nft_table    'tp_mgr'
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
#     option ports_file  '/etc/tproxy-manager/tproxy-manager.ports'
#     option bypass_v4_file '/etc/tproxy-manager/tproxy-manager.v4'
#     option bypass_v6_file '/etc/tproxy-manager/tproxy-manager.v6'
#     option src_mode          'off' # off|only|bypass
#     option src_only_v4_file  '/etc/tproxy-manager/tproxy-manager.src4.only'
#     option src_only_v6_file  '/etc/tproxy-manager/tproxy-manager.src6.only'
#     option src_bypass_v4_file '/etc/tproxy-manager/tproxy-manager.src4.bypass'
#     option src_bypass_v6_file '/etc/tproxy-manager/tproxy-manager.src6.bypass'
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
#   tproxy-manager start [-q] [bypass|only]
#   tproxy-manager restart [-q] [bypass|only]
#   tproxy-manager stop|status|diag [-q]

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

# Файл фактически применённого состояния. Нужен потому, что очистка «по
# текущему UCI» ломается ровно тогда, когда UCI поменяли: если сменить
# nft_table/fwmark/rttab и перезапуститься, старые объекты удалить уже
# нечем — их имена известны только из предыдущего запуска. Осиротевшая
# nft-таблица при этом остаётся с живым prerouting-хуком и продолжает
# заворачивать трафик в порт, где уже никто не слушает.
STATE_FILE="${STATE_FILE:-/var/run/tproxy-manager.state}"

# Резервный файл состояния. Пишется, когда основной state записать не
# удалось (например, /var/run переполнен или подменён каталогом): без него
# следующий запуск не знал бы, какие объекты уже созданы, и они остались бы
# висеть навсегда. Имеет приоритет над основным при чтении.
RECOVERY_FILE="${STATE_FILE}.recovery"

# Временные файлы одного запуска лежат в ПРИВАТНОМ каталоге 0700, а не прямо
# в /tmp по путям с $$. Прежняя схема была уязвима: PID предсказуем, /tmp имеет
# режим 1777, поэтому локальный пользователь заранее создавал симлинк по
# ожидаемому пути, и root писал nft-конфиг сквозь него в чужой файл — это
# воспроизведено на роутере. Каталог создаётся ЭКСКЛЮЗИВНО (`mkdir` без -p
# падает, если имя уже существует в любом виде) и проверяется по владельцу и
# режиму; внутрь него посторонний уже не заглянет.
TMP_ROOT="${TMP_ROOT:-/tmp}"
RUNDIR=""

# tmp_rand: короткая случайная строка. `od` есть не во всех сборках busybox,
# поэтому пробуем hexdump, затем md5sum от случайных байт. Случайность здесь
# нужна не для секретности, а чтобы предсказуемым именем нельзя было заранее
# занять путь и устроить отказ в обслуживании.
tmp_rand(){
  _r=""
  if command -v hexdump >/dev/null 2>&1; then
    _r="$(dd if=/dev/urandom bs=8 count=1 2>/dev/null | hexdump -v -e '1/1 "%02x"' 2>/dev/null)" || _r=""
  fi
  if [ -z "$_r" ] && command -v md5sum >/dev/null 2>&1; then
    _r="$(dd if=/dev/urandom bs=8 count=1 2>/dev/null | md5sum 2>/dev/null | cut -c1-16)" || _r=""
  fi
  [ -n "$_r" ] || _r="$$.$(date +%s 2>/dev/null || echo 0)"
  printf "%s" "$_r"
}

# rundir_create: приватный каталог этого запуска. Имя несёт PID, чтобы
# `sweep_stale_tmp` мог отличить брошенный каталог от живого.
rundir_create(){
  [ -n "$RUNDIR" ] && return 0
  _i=0
  while [ "$_i" -lt 8 ]; do
    _i=$((_i+1))
    _cand="$TMP_ROOT/.tpm-run.$$.$(tmp_rand)"
    if mkdir -m 0700 "$_cand" 2>/dev/null; then
      # Проверяем то, что получили: каталог, наш, 0700 — иначе не используем.
      _own="$(ls -ldn "$_cand" 2>/dev/null | awk '{print $1" "$3}')"
      case "$_own" in
        drwx------\ 0) RUNDIR="$_cand"; return 0 ;;
      esac
      rm -rf "$_cand" 2>/dev/null || true
      return 1
    fi
  done
  return 1
}

# Пути внутри RUNDIR присваиваются после его создания (rundir_init).
RULESET_NEW=""        # желаемый набор ip rule
RULESET_OLD=""        # набор из предыдущего состояния
CREATED_RULES=""      # созданное ИМЕННО этим запуском
CREATED_ROUTES=""
NFT_CONFIG=""         # собранный batch до nft --check
STALE_LEFT=""         # не удалённые чужие/старые объекты
STALE_ROUTES_LEFT=""
STALE_NFT_LEFT=""
RETRY_LEFT=""         # пережившие повторную попытку

rundir_init(){
  rundir_create || { echo "error: could not create a private temp directory under $TMP_ROOT" >&2; exit 1; }
  RULESET_NEW="$RUNDIR/rules-new"
  RULESET_OLD="$RUNDIR/rules-old"
  CREATED_RULES="$RUNDIR/rules-created"
  CREATED_ROUTES="$RUNDIR/routes-created"
  NFT_CONFIG="$RUNDIR/nft"
  STALE_LEFT="$RUNDIR/stale-rules"
  STALE_ROUTES_LEFT="$RUNDIR/stale-routes"
  STALE_NFT_LEFT="$RUNDIR/stale-nft"
  RETRY_LEFT="$RUNDIR/retry-left"
}

# ===== ГЛОБАЛЬНАЯ БЛОКИРОВКА ЖИЗНЕННОГО ЦИКЛА =====
# start/stop/restart меняют одни и те же объекты: policy-правила, nft-таблицу,
# файл состояния и его recovery. Запущенные одновременно (init.d + LuCI +
# watchdog — обычная ситуация), они перемешивали эти изменения: один запуск
# удалял правила, которые другой только что создал, а nft-commit и запись
# state приходили в произвольном порядке. Взаимное исключение — единственный
# способ этого не допустить.
#
# Реализация совпадает с остальным пакетом: каталог в root-only 0700 корне,
# `mkdir` как атомарный примитив, владелец в файле pid, и владелец считается
# мёртвым только когда его процесса действительно нет.
LOCK_ROOT="${LOCK_ROOT:-/var/lock/tproxy-manager}"
LIFECYCLE_LOCK="$LOCK_ROOT/tproxy-lifecycle.lock"
LOCK_HELD=0
LOCK_WAIT_SECONDS="${LOCK_WAIT_SECONDS:-30}"

lock_root_ok(){
  # /var/lock тоже 1777, поэтому корень либо создаём сами, либо принимаем
  # только настоящий каталог root:0700.
  if mkdir -m 0700 "$LOCK_ROOT" 2>/dev/null; then return 0; fi
  _lr="$(ls -ldn "$LOCK_ROOT" 2>/dev/null | awk '{print $1" "$3}')"
  case "$_lr" in
    drwx------\ 0) return 0 ;;
  esac
  chmod 0700 "$LOCK_ROOT" 2>/dev/null || true
  _lr="$(ls -ldn "$LOCK_ROOT" 2>/dev/null | awk '{print $1" "$3}')"
  case "$_lr" in
    drwx------\ 0) return 0 ;;
  esac
  return 1
}

lock_release(){
  [ "$LOCK_HELD" -eq 1 ] || return 0
  rm -rf "$LIFECYCLE_LOCK" 2>/dev/null || true
  LOCK_HELD=0
  return 0
}

# lock_acquire: ждём до LOCK_WAIT_SECONDS, затем отказываемся. Отказ лучше
# параллельного выполнения: вызывающий увидит ненулевой код и сообщение, а не
# наполовину переписанную конфигурацию.
lock_acquire(){
  lock_root_ok || { say "error: refusing to run: unsafe lock directory $LOCK_ROOT"; return 1; }
  _waited=0
  while :; do
    if mkdir "$LIFECYCLE_LOCK" 2>/dev/null; then
      # Записанный PID — единственное, по чему следующий вызов отличит живого
      # владельца от умершего. Если он не записался, замок остаётся ownerless,
      # и через пять секунд его снимет любой другой процесс прямо посреди нашей
      # работы. Поэтому такой замок сразу отдаём и отказываемся.
      if ! echo "$$" > "$LIFECYCLE_LOCK/pid" 2>/dev/null; then
        rm -rf "$LIFECYCLE_LOCK" 2>/dev/null || true
        say "error: could not record the lock owner pid"
        return 1
      fi
      _check="$(cat "$LIFECYCLE_LOCK/pid" 2>/dev/null || true)"
      if [ "$_check" != "$$" ]; then
        rm -rf "$LIFECYCLE_LOCK" 2>/dev/null || true
        say "error: could not record the lock owner pid"
        return 1
      fi
      LOCK_HELD=1
      return 0
    fi
    _owner="$(cat "$LIFECYCLE_LOCK/pid" 2>/dev/null || true)"
    case "$_owner" in
      ''|*[!0-9]*) _owner="" ;;
    esac
    if [ -n "$_owner" ] && [ ! -d "/proc/$_owner" ]; then
      # Владелец умер, не сняв замок.
      say "warning: removing a lock left by dead pid $_owner"
      rm -rf "$LIFECYCLE_LOCK" 2>/dev/null || true
      continue
    fi
    if [ -z "$_owner" ] && [ "$_waited" -ge 5 ]; then
      # Замок без владельца: либо кто-то между mkdir и записью pid (это
      # мгновение), либо он там умер. Пять секунд отделяют одно от другого.
      say "warning: removing an ownerless lock"
      rm -rf "$LIFECYCLE_LOCK" 2>/dev/null || true
      continue
    fi
    [ "$_waited" -ge "$LOCK_WAIT_SECONDS" ] && {
      say "error: another tproxy-manager lifecycle operation is in progress (pid ${_owner:-unknown})"
      return 1
    }
    sleep 1
    _waited=$((_waited+1))
  done
}

# Настраиваемые приоритеты ip rule
RULE_PRIO_TCP="${RULE_PRIO_TCP:-10000}"
RULE_PRIO_UDP="${RULE_PRIO_UDP:-10001}"

# Имя nft-таблицы и список интерфейсов источника
NFT_TABLE="${NFT_TABLE:-tp_mgr}"
LAN_IFACES="${LAN_IFACES:-br-lan}"

# Файлы с исключениями/портами
BYPASS_V4_FILE="${BYPASS_V4_FILE:-/etc/tproxy-manager/tproxy-manager.v4}"
BYPASS_V6_FILE="${BYPASS_V6_FILE:-/etc/tproxy-manager/tproxy-manager.v6}"
BYPASS_PORTS_FILE="${BYPASS_PORTS_FILE:-/etc/tproxy-manager/tproxy-manager.ports}"

# Режимы по источникам: off|only|bypass и файлы для них
SRC_MODE="${SRC_MODE:-off}"  # off|only|bypass
SRC_ONLY_V4_FILE="${SRC_ONLY_V4_FILE:-/etc/tproxy-manager/tproxy-manager.src4.only}"
SRC_ONLY_V6_FILE="${SRC_ONLY_V6_FILE:-/etc/tproxy-manager/tproxy-manager.src6.only}"
SRC_BYPASS_V4_FILE="${SRC_BYPASS_V4_FILE:-/etc/tproxy-manager/tproxy-manager.src4.bypass}"
SRC_BYPASS_V6_FILE="${SRC_BYPASS_V6_FILE:-/etc/tproxy-manager/tproxy-manager.src6.bypass}"

# Режим портов по умолчанию
PORT_MODE_DEFAULT="${PORT_MODE_DEFAULT:-bypass}"  # bypass|only

# Встроенные приватные сети (v4/v6), не отправляем в прокси
BYPASS_CIDRS4_DEFAULT="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8 169.254.0.0/16 224.0.0.0/4 240.0.0.0/4 100.64.0.0/10"
BYPASS_CIDRS6_DEFAULT="::1/128 fc00::/7 fe80::/10 ff00::/8"

# Логирование
LOGGER_TAG="${LOGGER_TAG:-tproxy-manager}"
LOG_ENABLED="${LOG_ENABLED:-1}"
QUIET="${QUIET:-0}"

# Включение IPv6
IPV6_ENABLED="${IPV6_ENABLED:-1}"

# ===== ХЕЛПЕРЫ =====
# say/log: единая точка вывода в stdout/syslog
say(){ [ "$QUIET" -eq 1 ] && return 0; echo "$*"; }
log(){ [ "$LOG_ENABLED" -eq 1 ] && logger -t "$LOGGER_TAG" -- "$*"; [ "$QUIET" -eq 1 ] || echo "$LOGGER_TAG: $*"; }

# sweep_stale_tmp: убрать собственные временные файлы, оставшиеся от
# прерванных запусков. Обычный путь чистит за собой сам, но процесс может
# быть убит (сигнал, ошибка под `set -e`), и без этой уборки такие файлы
# копились бы в tmpfs до перезагрузки. Трогаем строго свой префикс и
# только файлы, чей PID уже не существует.
sweep_stale_tmp(){
  # Каталоги этого пакета: .tpm-run.<pid>.<rand>. PID берётся из имени, а не из
  # конца строки — случайный суффикс идёт последним.
  for _d in "$TMP_ROOT"/.tpm-run.*; do
    [ -d "$_d" ] || continue
    _pid="${_d#*/.tpm-run.}"
    _pid="${_pid%%.*}"
    case "$_pid" in
      ''|*[!0-9]*) continue ;;
    esac
    [ "$_pid" = "$$" ] && continue
    [ -d "/proc/$_pid" ] && continue
    rm -rf "$_d" 2>/dev/null || true
  done
  # Плоские файлы прежней схемы: остаются на роутерах, обновившихся с
  # предыдущей версии, и без этого висели бы в tmpfs до перезагрузки.
  for _f in "$TMP_ROOT"/.tpm-rules-*.* "$TMP_ROOT"/.tpm-routes-*.* "$TMP_ROOT"/.tpm-nft.* \
            "$TMP_ROOT"/.tpm-stale-*.* "$TMP_ROOT"/.tpm-retry-left.*; do
    [ -f "$_f" ] || continue
    _pid="${_f##*.}"
    case "$_pid" in
      ''|*[!0-9]*) continue ;;
    esac
    [ "$_pid" = "$$" ] && continue
    [ -d "/proc/$_pid" ] && continue
    rm -f "$_f" 2>/dev/null || true
  done
  return 0
}

# preflight: проверка наличия необходимых утилит (BusyBox)
preflight(){
  sweep_stale_tmp
  # Приватный каталог этого запуска создаётся до первой временной записи.
  rundir_init
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
# load_uci: подстановка конфигурации из UCI (если есть секция tproxy-manager.main)
load_uci(){
  u_table="$(uci -q get tproxy-manager.main.nft_table 2>/dev/null || echo "")"
  u_ifaces="$(uci -q get tproxy-manager.main.ifaces 2>/dev/null || echo "")"
  u_log="$(uci -q get tproxy-manager.main.log_enabled 2>/dev/null || echo "")"
  u_ipv6="$(uci -q get tproxy-manager.main.ipv6_enabled 2>/dev/null || echo "")"
  [ -n "$u_table" ]  && NFT_TABLE="$u_table"
  [ -n "$u_ifaces" ] && LAN_IFACES="$u_ifaces"
  case "$u_log" in 0|1) LOG_ENABLED="$u_log" ;; esac
  case "$u_ipv6" in 0|1) IPV6_ENABLED="$u_ipv6" ;; esac

  u_tport="$(uci -q get tproxy-manager.main.tproxy_port 2>/dev/null || echo "")"
  u_tport_tcp="$(uci -q get tproxy-manager.main.tproxy_port_tcp 2>/dev/null || echo "")"
  u_tport_udp="$(uci -q get tproxy-manager.main.tproxy_port_udp 2>/dev/null || echo "")"
  if [ -n "$u_tport" ]; then TPORT_TCP="$u_tport"; TPORT_UDP="$u_tport"; fi
  [ -n "$u_tport_tcp" ] && TPORT_TCP="$u_tport_tcp"
  [ -n "$u_tport_udp" ] && TPORT_UDP="$u_tport_udp"

  u_fwmark_tcp="$(uci -q get tproxy-manager.main.fwmark_tcp 2>/dev/null || echo "")"
  u_fwmark_udp="$(uci -q get tproxy-manager.main.fwmark_udp 2>/dev/null || echo "")"
  u_rttab_tcp="$(uci -q get tproxy-manager.main.rttab_tcp 2>/dev/null || echo "")"
  u_rttab_udp="$(uci -q get tproxy-manager.main.rttab_udp 2>/dev/null || echo "")"
  [ -n "$u_fwmark_tcp" ] && FWMARK_TCP="$u_fwmark_tcp"
  [ -n "$u_fwmark_udp" ] && FWMARK_UDP="$u_fwmark_udp"
  [ -n "$u_rttab_tcp" ] && RTTAB_TCP="$u_rttab_tcp"
  [ -n "$u_rttab_udp" ] && RTTAB_UDP="$u_rttab_udp"

  u_mode="$(uci -q get tproxy-manager.main.port_mode 2>/dev/null || echo "")"
  u_ports_file="$(uci -q get tproxy-manager.main.ports_file 2>/dev/null || echo "")"
  case "$u_mode" in bypass|only) PORT_MODE_DEFAULT="$u_mode" ;; esac
  [ -n "$u_ports_file" ] && BYPASS_PORTS_FILE="$u_ports_file"

  u_bypass_v4="$(uci -q get tproxy-manager.main.bypass_v4_file 2>/dev/null || echo "")"
  u_bypass_v6="$(uci -q get tproxy-manager.main.bypass_v6_file 2>/dev/null || echo "")"
  [ -n "$u_bypass_v4" ] && BYPASS_V4_FILE="$u_bypass_v4"
  [ -n "$u_bypass_v6" ] && BYPASS_V6_FILE="$u_bypass_v6"

  u_srcmode="$(uci -q get tproxy-manager.main.src_mode 2>/dev/null || echo "")"
  u_src_only4="$(uci -q get tproxy-manager.main.src_only_v4_file 2>/dev/null || echo "")"
  u_src_only6="$(uci -q get tproxy-manager.main.src_only_v6_file 2>/dev/null || echo "")"
  u_src_byp4="$(uci -q get tproxy-manager.main.src_bypass_v4_file 2>/dev/null || echo "")"
  u_src_byp6="$(uci -q get tproxy-manager.main.src_bypass_v6_file 2>/dev/null || echo "")"
  case "$u_srcmode" in off|only|bypass) SRC_MODE="$u_srcmode" ;; esac
  [ -n "$u_src_only4" ] && SRC_ONLY_V4_FILE="$u_src_only4"
  [ -n "$u_src_only6" ] && SRC_ONLY_V6_FILE="$u_src_only6"
  [ -n "$u_src_byp4" ]  && SRC_BYPASS_V4_FILE="$u_src_byp4"
  [ -n "$u_src_byp6" ]  && SRC_BYPASS_V6_FILE="$u_src_byp6"
}

# ===== IO/ПАРСИНГ =====
# read_lines_file: читает файл, убирая CR, комментарии, хвостовые пробелы и пустые строки
read_lines_file(){ [ -f "$1" ] || return 0; sed -e 's/\r$//' -e 's/#.*$//' -e 's/[[:space:]]\+$//' -e '/^[[:space:]]*$/d' "$1"; }

# ===== ВАЛИДАЦИЯ ВХОДНЫХ ДАННЫХ =====
# Некорректная строка в списке раньше просто молча выпадала из набора:
# пользователь видел «применено», а половина его адресов не работала.
# Теперь любая непустая некорректная строка останавливает preflight с
# указанием файла и номера строки.
is_ipv4_cidr(){
  echo "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$' || return 1
  _ip="${1%%/*}"
  for _o in $(echo "$_ip" | tr '.' ' '); do
    [ "$_o" -le 255 ] 2>/dev/null || return 1
  done
  return 0
}
# The charset check alone accepted things nft then silently dropped from the
# set — "::::" passed, and the resulting bypass rule was simply absent from a
# start that reported success. Structure is what matters, so it is checked:
# at most one "::", and no more than 8 hextets (7 when "::" is present, since
# it stands for at least one zero group).
is_ipv6_cidr(){
  echo "$1" | grep -qE '^[0-9A-Fa-f:]+(/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8]))?$' || return 1
  _v6="${1%%/*}"
  echo "$_v6" | grep -q ':' || return 1
  # ":::" and beyond are never valid, and "::" may appear at most once.
  case "$_v6" in *:::*) return 1 ;; esac
  _dcol="$(printf '%s' "$_v6" | awk '{n=0; for(i=1;i<length($0);i++) if (substr($0,i,2)=="::") n++; print n}')"
  [ "$_dcol" -le 1 ] || return 1
  # A single colon may not start or end the address unless it is part of "::".
  case "$_v6" in
    ::*|*::) : ;;
    :*|*:) return 1 ;;
  esac
  # Count hextets and validate each one.
  _groups=0
  for _g in $(printf '%s' "$_v6" | tr ':' ' '); do
    echo "$_g" | grep -qE '^[0-9A-Fa-f]{1,4}$' || return 1
    _groups=$((_groups+1))
  done
  if [ "$_dcol" -eq 1 ]; then
    [ "$_groups" -le 7 ] || return 1
  else
    [ "$_groups" -eq 8 ] || return 1
  fi
  return 0
}
# A descending range such as "100-50" passed the per-number check and was then
# dropped by nft, so the port was silently never bypassed. The range has to be
# ordered, and a range must actually have two ends.
is_port_spec(){
  echo "$1" | grep -qE '^((tcp|udp|both):)?[0-9]+(-[0-9]+)?$' || return 1
  _spec="${1#*:}"
  for _p in $(echo "$_spec" | tr '-' ' '); do
    [ "$_p" -ge 1 ] 2>/dev/null && [ "$_p" -le 65535 ] 2>/dev/null || return 1
  done
  case "$_spec" in
    *-*)
      _lo="${_spec%%-*}"; _hi="${_spec##*-}"
      [ "$_lo" -le "$_hi" ] 2>/dev/null || return 1
      ;;
  esac
  return 0
}

# validate_list_file FILE KIND(v4|v6|port) — проверяет каждую значимую
# строку и печатает точное место ошибки.
validate_list_file(){
  _f="$1"; _kind="$2"
  [ -f "$_f" ] || return 0
  _n=0; _bad=0
  while IFS= read -r _raw || [ -n "$_raw" ]; do
    _n=$((_n+1))
    _line="$(printf '%s' "$_raw" | sed -e 's/\r$//' -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [ -z "$_line" ] && continue
    case "$_kind" in
      v4)   is_ipv4_cidr "$_line" || { say "error: $_f:$_n: not a valid IPv4 address/CIDR: $_line"; _bad=1; } ;;
      v6)   is_ipv6_cidr "$_line" || { say "error: $_f:$_n: not a valid IPv6 address/CIDR: $_line"; _bad=1; } ;;
      port) is_port_spec "$_line" || { say "error: $_f:$_n: not a valid port spec: $_line"; _bad=1; } ;;
    esac
  done < "$_f"
  [ "$_bad" -eq 0 ] || return 1
  return 0
}

# validate_ifaces: каждый настроенный интерфейс должен существовать.
# Без этого iifname-gate молча не совпадал бы ни с чем, и весь перехват
# тихо переставал работать.
validate_ifaces(){
  _missing=""
  for i in $LAN_IFACES; do
    ip link show "$i" >/dev/null 2>&1 || _missing="$_missing $i"
  done
  if [ -n "$_missing" ]; then
    say "error: configured LAN interface(s) do not exist:$_missing"
    return 1
  fi
  [ -n "$(printf '%s' "$LAN_IFACES" | tr -d '[:space:]')" ] || {
    say "error: no LAN interfaces configured"; return 1; }
  return 0
}

# validate_all_lists: единая точка вызова перед любыми изменениями сети.
validate_all_lists(){
  _rc=0
  validate_list_file "$BYPASS_PORTS_FILE" port || _rc=1
  validate_list_file "$BYPASS_V4_FILE" v4 || _rc=1
  validate_list_file "$SRC_ONLY_V4_FILE" v4 || _rc=1
  validate_list_file "$SRC_BYPASS_V4_FILE" v4 || _rc=1
  if [ "$IPV6_ENABLED" -eq 1 ]; then
    validate_list_file "$BYPASS_V6_FILE" v6 || _rc=1
    validate_list_file "$SRC_ONLY_V6_FILE" v6 || _rc=1
    validate_list_file "$SRC_BYPASS_V6_FILE" v6 || _rc=1
  fi
  return "$_rc"
}

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

# valid_octet: 0..255, только цифры
valid_octet(){ o="$1"; case "$o" in ''|*[!0-9]*) return 1;; esac; [ "$o" -ge 0 ] && [ "$o" -le 255 ]; }

# valid_ipv4: строгая проверка IPv4-адреса (защита от инъекции в generate-nft файл)
valid_ipv4(){
  ip="$1"
  printf '%s' "$ip" | grep -Eq '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || return 1
  o1="${ip%%.*}"; r="${ip#*.}"
  o2="${r%%.*}"; r="${r#*.}"
  o3="${r%%.*}"; o4="${r#*.}"
  valid_octet "$o1" && valid_octet "$o2" && valid_octet "$o3" && valid_octet "$o4"
}

# valid_ipv4_cidr: IPv4 + необязательный /prefix (0..32)
valid_ipv4_cidr(){
  spec="$1"
  case "$spec" in
    */*) addr="${spec%/*}"; prefix="${spec#*/}" ;;
    *) return 1 ;;
  esac
  valid_ipv4 "$addr" || return 1
  case "$prefix" in ''|*[!0-9]*) return 1;; esac
  [ "$prefix" -ge 0 ] && [ "$prefix" -le 32 ]
}

# valid_ipv6: разрешаем только hex-группы/двоеточия (и хвост IPv4 для v4-mapped адресов) —
# не полноценный RFC-парсер, но исключает любые символы, способные сломать синтаксис nft
valid_ipv6(){
  ip="$1"
  [ -n "$ip" ] || return 1
  case "$ip" in *[!0-9A-Fa-f:.]*) return 1;; esac
  case "$ip" in *:*) : ;; *) return 1;; esac
  case "$ip" in :::*|*:::*) return 1;; esac
  return 0
}

# valid_ipv6_cidr: IPv6 + необязательный /prefix (0..128)
valid_ipv6_cidr(){
  spec="$1"
  case "$spec" in
    */*) addr="${spec%/*}"; prefix="${spec#*/}" ;;
    *) return 1 ;;
  esac
  valid_ipv6 "$addr" || return 1
  case "$prefix" in ''|*[!0-9]*) return 1;; esac
  [ "$prefix" -ge 0 ] && [ "$prefix" -le 128 ]
}

# valid_ipv4_entry / valid_ipv6_entry: адрес ИЛИ CIDR (для sets с "flags interval")
valid_ipv4_entry(){ case "$1" in */*) valid_ipv4_cidr "$1";; *) valid_ipv4 "$1";; esac; }
valid_ipv6_entry(){ case "$1" in */*) valid_ipv6_cidr "$1";; *) valid_ipv6 "$1";; esac; }

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
# Policy-правило в delta-модели опознаётся четвёркой
# (family, mark, table, priority), маршрутная таблица — парой (family, table).
# Всё ниже оперирует ровно этими ключами: add/del/present обязаны говорить об
# одном и том же объекте, иначе запуск либо плодит дубликаты, либо считает
# удалённым то, что осталось в системе.

# ip_fam: ключ семейства для ip(8). Вынесен отдельно, чтобы ни одна ветка не
# забыла -6 и не выполнила v6-операцию над v4-таблицей.
ip_fam(){ if [ "$1" = "6" ]; then echo "-6"; else echo "-4"; fi; }

# norm_mark: ip(8) печатает fwmark всегда в hex, а в UCI марка допустима и
# десятичной ("1"), и шестнадцатеричной ("0x1"). Без приведения к одному виду
# rule_present не узнал бы собственное правило и каждый запуск добавлял бы
# ещё одну копию.
norm_mark(){ printf "0x%x" "$(( $1 ))"; }

# rt_alias: если номер таблицы описан в /etc/iproute2/rt_tables, ip(8)
# печатает в `rule show` ИМЯ, а не номер. Сравнение с номером тогда всегда
# ложно — правило считается отсутствующим и дублируется при каждом старте.
rt_alias(){
  _rta="$(sed -n "s/^[[:space:]]*$1[[:space:]]\{1,\}\([A-Za-z0-9_.-]\{1,\}\).*/\1/p" \
          /etc/iproute2/rt_tables 2>/dev/null | head -n1)"
  if [ -n "$_rta" ]; then printf "%s" "$_rta"; else printf "%s" "$1"; fi
}

# rule_present FAM MARK TABLE PRIO — существует ли ИМЕННО это правило.
rule_present(){
  _pm="$(norm_mark "$2")"; _pl="$(rt_alias "$3")"
  ip "$(ip_fam "$1")" rule show 2>/dev/null | \
    grep -Eq "^$4:[[:space:]].*fwmark ${_pm}/${_pm}[[:space:]].*lookup ${_pl}([[:space:]]|\$)"
}

rule_add_one(){
  _am="$(norm_mark "$2")"
  ip "$(ip_fam "$1")" rule add fwmark "$_am/$_am" lookup "$3" priority "$4" 2>/dev/null || true
}

rule_del_one(){
  _dm="$(norm_mark "$2")"
  ip "$(ip_fam "$1")" rule del fwmark "$_dm/$_dm" lookup "$3" priority "$4" 2>/dev/null || true
}

# route_present FAM TABLE — лежит ли в таблице наш local-маршрут. Проверяем
# именно его, а не «таблица непуста»: посторонняя запись не должна выдаваться
# за наш объект.
route_present(){
  ip "$(ip_fam "$1")" route show table "$2" 2>/dev/null | \
    grep -Eq "^local (default|0\.0\.0\.0/0|::/0)([[:space:]]|\$)"
}

route_add_one(){
  case "$1" in
    6) ip -6 route add local ::/0 dev lo table "$2" 2>/dev/null || true ;;
    *) ip -4 route add local 0.0.0.0/0 dev lo table "$2" 2>/dev/null || true ;;
  esac
}

route_del_table(){ ip "$(ip_fam "$1")" route flush table "$2" 2>/dev/null || true; }

# table_still_used FAM TABLE — нужна ли таблица новой конфигурации. Ровно этим
# защищена общая таблица для TCP и UDP: сняв одно из двух правил, вымывать её
# нельзя, пока второе живо.
table_still_used(){
  [ -s "$RULESET_NEW" ] || return 1
  awk -v f="$1" -v t="$2" '$1==f && $3==t{ok=1; exit} END{exit !ok}' "$RULESET_NEW"
}

# desired_rules: набор правил, который должна создать ТЕКУЩАЯ конфигурация.
desired_rules(){
  _dmt="$(norm_mark "$FWMARK_TCP")"; _dmu="$(norm_mark "$FWMARK_UDP")"
  echo "4 $_dmt $RTTAB_TCP $RULE_PRIO_TCP"
  echo "4 $_dmu $RTTAB_UDP $RULE_PRIO_UDP"
  if [ "$IPV6_ENABLED" -eq 1 ]; then
    echo "6 $_dmt $RTTAB_TCP $RULE_PRIO_TCP"
    echo "6 $_dmu $RTTAB_UDP $RULE_PRIO_UDP"
  fi
  return 0
}

# state_rules: набор правил, который ФАКТИЧЕСКИ создал предыдущий запуск.
# Берётся из state (или recovery — см. state_source), а не из текущего UCI:
# именно смена UCI и делает старые объекты неудаляемыми по текущим значениям.
# IPv6-строки выдаются по сохранённому флагу, иначе выключение IPv6 навсегда
# оставило бы v6-правила без учёта.
state_rules(){
  _s_v6="$(state_get IPV6_ENABLED)"
  for _s_set in "$(state_get FWMARK_TCP) $(state_get RTTAB_TCP) $(state_get RULE_PRIO_TCP)" \
                "$(state_get FWMARK_UDP) $(state_get RTTAB_UDP) $(state_get RULE_PRIO_UDP)"; do
    # shellcheck disable=SC2086
    set -- $_s_set
    [ -n "${1:-}" ] && [ -n "${2:-}" ] && [ -n "${3:-}" ] || continue
    # Марку из state пропускаем через тот же фильтр, что и всё остальное
    # оттуда: повреждённое значение не должно превращаться в 0x0 и подставно
    # «совпадать» с несуществующим правилом.
    case "$1" in
      0x*|0X*) case "${1#0[xX]}" in ''|*[!0-9a-fA-F]*) continue ;; esac ;;
      ''|*[!0-9]*) continue ;;
    esac
    _s_m="$(norm_mark "$1")"
    echo "4 $_s_m $2 $3"
    if [ "$_s_v6" = "1" ]; then echo "6 $_s_m $2 $3"; fi
  done
  return 0
}

# ===== RUNTIME STATE =====
# state_get: одно валидированное поле из STATE_FILE.
# Файл принципиально НЕ выполняется через `.`/source: он лежит в /var/run,
# и любое повреждение или подмена превратились бы в исполнение произвольного
# кода от root. Разбираем построчно и пропускаем только безопасный набор
# символов; всё остальное молча игнорируется как отсутствующее.
# Читаем основной state, а при его отсутствии/неполноте — recovery.
# state_source: выбирает ОДИН файл-источник целиком. Recovery пишется ровно
# тогда, когда основной state записать не удалось, поэтому при его наличии
# он и есть актуальное применённое состояние. Пофайловый выбор принципиален:
# поле-за-полем можно было бы взять NFT_TABLE из recovery, а FWMARK из
# старого основного state, собрав несуществующее «поколение» конфигурации.
state_source(){
  if [ -f "$RECOVERY_FILE" ]; then
    printf "%s" "$RECOVERY_FILE"
  elif [ -f "$STATE_FILE" ]; then
    printf "%s" "$STATE_FILE"
  else
    printf ""
  fi
}

state_get(){
  _src="$(state_source)"
  [ -n "$_src" ] || return 0
  sed -n "s/^$1=\([A-Za-z0-9_.:-]*\)\$/\1/p" "$_src" 2>/dev/null | head -n1
}

# state_get_from: чтение из КОНКРЕТНОГО файла, минуя выбор источника.
# Нужно для самопроверки записи: сравнивать записанное с тем, что вернёт
# state_get, нельзя — тот отдаст значение из ещё существующего recovery и
# объявит успешную запись неудачной.
state_get_from(){
  [ -f "$1" ] || return 0
  sed -n "s/^$2=\([A-Za-z0-9_.:-]*\)\$/\1/p" "$1" 2>/dev/null | head -n1
}

# write_state_file TARGET: атомарная проверяемая запись одного state-файла.
# Содержимое подаётся на stdin. Единая реализация для основного state и для
# recovery — раньше это были две копии с разными проверками, и recovery
# записывался без верификации результата.
# Возвращает 0 только если файл действительно оказался на месте, является
# обычным файлом и содержит ожидаемый маркер NFT_TABLE.
write_state_file(){
  _wsf_target="$1"; _wsf_expect="$2"
  _wsf_tmp="$_wsf_target.tmp.$$"
  cat > "$_wsf_tmp" 2>/dev/null || { rm -f "$_wsf_tmp" 2>/dev/null; return 1; }
  chmod 0600 "$_wsf_tmp" 2>/dev/null || true
  mv -f "$_wsf_tmp" "$_wsf_target" 2>/dev/null || { rm -f "$_wsf_tmp" 2>/dev/null; return 1; }
  # Проверяем РЕЗУЛЬТАТ, а не код возврата: если по пути оказался каталог,
  # `mv file dir` кладёт файл ВНУТРЬ него и возвращает 0.
  [ -f "$_wsf_target" ] || return 1
  [ "$(state_get_from "$_wsf_target" NFT_TABLE)" = "$_wsf_expect" ] || return 1
  chmod 0600 "$_wsf_target" 2>/dev/null || true
  return 0
}

# state_write: снимок фактически применённой конфигурации. Пишем только
# после полного успеха, атомарной подменой — половинчатый state хуже, чем
# его отсутствие, потому что по нему потом будут удалять объекты.
state_write(){
  _stale_lines(){
    [ -s "$STALE_LEFT" ] && while read -r _f _m _t _p; do
      [ -n "$_f" ] && echo "STALE_RULE=$_f,$_m,$_t,$_p"; done < "$STALE_LEFT"
    [ -s "$STALE_ROUTES_LEFT" ] && while read -r _f _t; do
      [ -n "$_f" ] && echo "STALE_ROUTE=$_f,$_t"; done < "$STALE_ROUTES_LEFT"
    [ -s "$STALE_NFT_LEFT" ] && while read -r _t; do
      [ -n "$_t" ] && echo "STALE_NFT=$_t"; done < "$STALE_NFT_LEFT"
    return 0
  }
  _state_body(){
    echo "NFT_TABLE=$NFT_TABLE"
    echo "FWMARK_TCP=$FWMARK_TCP"; echo "FWMARK_UDP=$FWMARK_UDP"
    echo "RTTAB_TCP=$RTTAB_TCP";   echo "RTTAB_UDP=$RTTAB_UDP"
    echo "RULE_PRIO_TCP=$RULE_PRIO_TCP"; echo "RULE_PRIO_UDP=$RULE_PRIO_UDP"
    echo "IPV6_ENABLED=$IPV6_ENABLED"
    _stale_lines
  }

  if _state_body | write_state_file "$STATE_FILE" "$NFT_TABLE"; then
    # Основной state записан и теперь авторитетен — recovery не нужен.
    rm -f "$RECOVERY_FILE" 2>/dev/null || true
    return 0
  fi

  # Основной state записать не удалось — сохраняем recovery тем же
  # проверяемым способом, чтобы следующий запуск знал, что вычищать.
  if _state_body | write_state_file "$RECOVERY_FILE" "$NFT_TABLE"; then
    return 1
  fi
  # Ни один файл записать не удалось.
  return 2
}

# iprules_del_set: снять конкретный набор policy-правил по ЯВНО переданным
# значениям, а не по текущему UCI. IPv6 чистится всегда, независимо от
# нынешнего IPV6_ENABLED: иначе выключение IPv6 оставляло бы v6-правила
# висеть навсегда, ведь при следующем запуске ветка их удаления не
# выполнится.
iprules_del_set(){
  _fwt="$1"; _fwu="$2"; _rtt="$3"; _rtu="$4"; _pt="$5"; _pu="$6"
  [ -n "$_fwt" ] && [ -n "$_rtt" ] && [ -n "$_pt" ] && {
    ip    rule del fwmark "$_fwt/$_fwt" lookup "$_rtt" priority "$_pt" 2>/dev/null || true
    ip -6 rule del fwmark "$_fwt/$_fwt" lookup "$_rtt" priority "$_pt" 2>/dev/null || true
    ip    route flush table "$_rtt" 2>/dev/null || true
    ip -6 route flush table "$_rtt" 2>/dev/null || true
  }
  [ -n "$_fwu" ] && [ -n "$_rtu" ] && [ -n "$_pu" ] && {
    ip    rule del fwmark "$_fwu/$_fwu" lookup "$_rtu" priority "$_pu" 2>/dev/null || true
    ip -6 rule del fwmark "$_fwu/$_fwu" lookup "$_rtu" priority "$_pu" 2>/dev/null || true
    ip    route flush table "$_rtu" 2>/dev/null || true
    ip -6 route flush table "$_rtu" 2>/dev/null || true
  }
  return 0
}

# apply_iprules: добавляет ТОЛЬКО отсутствующие правила и фиксирует, что
# именно создал этот запуск — чтобы при откате снести ровно их, не трогая
# совпадающие старые.
apply_iprules(){
  desired_rules > "$RULESET_NEW"
  state_rules   > "$RULESET_OLD" 2>/dev/null || : > "$RULESET_OLD"
  : > "$CREATED_RULES"; : > "$CREATED_ROUTES"
  while read -r fam mk tb pr; do
    [ -z "$fam" ] && continue
    # Маршрут таблицы — отдельно: он мог существовать до нас (общая таблица
    # для TCP/UDP), тогда создавать и откатывать его нельзя.
    if ! route_present "$fam" "$tb"; then
      route_add_one "$fam" "$tb"
      if route_present "$fam" "$tb"; then
        grep -qx "$fam $tb" "$CREATED_ROUTES" 2>/dev/null || echo "$fam $tb" >> "$CREATED_ROUTES"
      else
        say "error: could not add local route (family=$fam table=$tb)"
        return 1
      fi
    fi
    if rule_present "$fam" "$mk" "$tb" "$pr"; then
      continue
    fi
    rule_add_one "$fam" "$mk" "$tb" "$pr"
    if rule_present "$fam" "$mk" "$tb" "$pr"; then
      echo "$fam $mk $tb $pr" >> "$CREATED_RULES"
    else
      say "error: could not add ip rule (family=$fam mark=$mk table=$tb prio=$pr)"
      return 1
    fi
  done < "$RULESET_NEW"
  return 0
}

# remove_iprules_delta: снять только те старые правила, которых НЕТ в новой
# конфигурации; таблицу маршрутов вымывать только если она новой
# конфигурации больше не нужна.
remove_iprules_delta(){
  [ -s "$RULESET_OLD" ] || return 0
  while read -r fam mk tb pr; do
    [ -z "$fam" ] && continue
    _keep=0
    while read -r nfam nmk ntb npr; do
      [ "$fam $mk $tb $pr" = "$nfam $nmk $ntb $npr" ] && { _keep=1; break; }
    done < "$RULESET_NEW"
    [ "$_keep" = "1" ] && continue
    say "[state] removing stale ip rule (family=$fam mark=$mk table=$tb prio=$pr)"
    rule_del_one "$fam" "$mk" "$tb" "$pr"
    if rule_present "$fam" "$mk" "$tb" "$pr"; then
      # Не удалилось — запоминаем, чтобы следующий start/stop попробовал
      # снова, иначе объект остался бы сиротой навсегда.
      say "warning: stale rule survived deletion, will retry next run"
      echo "$fam $mk $tb $pr" >> "$STALE_LEFT"
    elif ! table_still_used "$fam" "$tb"; then
      route_del_table "$fam" "$tb"
      if route_present "$fam" "$tb"; then
        say "warning: stale route table survived flush, will retry next run"
        echo "$fam $tb" >> "$STALE_ROUTES_LEFT"
      fi
    fi
  done < "$RULESET_OLD"
  return 0
}

# retry_recorded_stale: повторная попытка снять объекты, которые прошлый
# запуск удалить не смог (они записаны в state как STALE_RULE/STALE_ROUTE,
# либо в recovery-файле, если основной state не записался).
retry_recorded_stale(){
  _still=0
  for _src in "$STATE_FILE" "$RECOVERY_FILE"; do
    [ -f "$_src" ] || continue
    # Пишем результат во временный файл: `while` в конвейере выполняется в
    # подоболочке, и присваивания внутри неё до нас бы не дошли.
    _tmp_left="$RETRY_LEFT"
    : > "$_tmp_left"
    sed -n 's/^STALE_RULE=\(.*\)$/\1/p' "$_src" 2>/dev/null | while IFS=, read -r _f _m _t _p; do
      [ -n "$_f" ] || continue
      say "[state] retrying removal of stale rule (family=$_f mark=$_m table=$_t prio=$_p)"
      rule_del_one "$_f" "$_m" "$_t" "$_p"
      # Проверяем ФАКТ удаления: иначе объект молча терялся из учёта и
      # оставался в системе навсегда.
      if rule_present "$_f" "$_m" "$_t" "$_p"; then
        say "warning: stale rule still present after retry"
        echo "R $_f $_m $_t $_p" >> "$_tmp_left"
      fi
    done
    sed -n 's/^STALE_ROUTE=\(.*\)$/\1/p' "$_src" 2>/dev/null | while IFS=, read -r _f _t; do
      [ -n "$_f" ] || continue
      say "[state] retrying flush of stale route table (family=$_f table=$_t)"
      route_del_table "$_f" "$_t"
      if route_present "$_f" "$_t"; then
        say "warning: stale route table still present after retry"
        echo "T $_f $_t" >> "$_tmp_left"
      fi
    done
    sed -n 's/^STALE_NFT=\(.*\)$/\1/p' "$_src" 2>/dev/null | while read -r _t; do
      [ -n "$_t" ] || continue
      say "[state] retrying removal of stale nft table $_t"
      nft delete table inet "$_t" 2>/dev/null || true
      if nft list table inet "$_t" >/dev/null 2>&1; then
        say "warning: stale nft table $_t still present after retry"
        echo "N $_t" >> "$_tmp_left"
      fi
    done
    if [ -s "$_tmp_left" ]; then
      _still=1
      # Переносим невычищенное в текущие списки, чтобы state_write записал
      # их снова и следующий запуск попробовал ещё раз.
      while read -r _kind _a _b _c _d; do
        case "$_kind" in
          R) echo "$_a $_b $_c $_d" >> "$STALE_LEFT" ;;
          T) echo "$_a $_b" >> "$STALE_ROUTES_LEFT" ;;
          N) echo "$_a" >> "$STALE_NFT_LEFT" ;;
        esac
      done < "$_tmp_left"
    fi
    rm -f "$_tmp_left"
  done
  # Recovery здесь НЕ удаляем даже при полной очистке: помимо STALE_*
  # он хранит фактически применённые table/marks/routes, которые нужны
  # ниже (apply_nft читает старое имя таблицы именно оттуда, когда
  # основной state записать не удалось). Его вытесняет успешный
  # state_write — там он и убирается.
  [ "$_still" -eq 0 ] || say "warning: recovery state kept - cleanup is still incomplete"
  return 0
}

# persist_leftovers_to_recovery: единая точка записи невычищенных объектов
# в recovery, ДО удаления временных файлов. Используется обеими ветками
# отката (ошибка policy routing и ошибка nft) — раньше это было записано
# только в nft-ветке, и сбой apply_iprules терял тот же самый учёт.
persist_leftovers_to_recovery(){
  [ -s "$STALE_LEFT" ] || [ -s "$STALE_ROUTES_LEFT" ] || [ -s "$STALE_NFT_LEFT" ] || return 0
  # Сначала СНИМАЕМ значения, потом пишем: прямое перенаправление в
  # recovery обрезало бы его до того, как state_get прочитает оттуда
  # единственный актуальный снимок.
  _p_tbl="$(state_get NFT_TABLE)"
  _p_fwt="$(state_get FWMARK_TCP)"; _p_fwu="$(state_get FWMARK_UDP)"
  _p_rtt="$(state_get RTTAB_TCP)";  _p_rtu="$(state_get RTTAB_UDP)"
  _p_pt="$(state_get RULE_PRIO_TCP)"; _p_pu="$(state_get RULE_PRIO_UDP)"
  _p_v6="$(state_get IPV6_ENABLED)"

  {
    echo "NFT_TABLE=$_p_tbl"
    echo "FWMARK_TCP=$_p_fwt"; echo "FWMARK_UDP=$_p_fwu"
    echo "RTTAB_TCP=$_p_rtt";  echo "RTTAB_UDP=$_p_rtu"
    echo "RULE_PRIO_TCP=$_p_pt"; echo "RULE_PRIO_UDP=$_p_pu"
    echo "IPV6_ENABLED=$_p_v6"
    [ -s "$STALE_LEFT" ] && while read -r _f _m _t _p; do
      [ -n "$_f" ] && echo "STALE_RULE=$_f,$_m,$_t,$_p"; done < "$STALE_LEFT"
    [ -s "$STALE_ROUTES_LEFT" ] && while read -r _f _t; do
      [ -n "$_f" ] && echo "STALE_ROUTE=$_f,$_t"; done < "$STALE_ROUTES_LEFT"
    [ -s "$STALE_NFT_LEFT" ] && while read -r _t; do
      [ -n "$_t" ] && echo "STALE_NFT=$_t"; done < "$STALE_NFT_LEFT"
  } | write_state_file "$RECOVERY_FILE" "$_p_tbl" || {
    # Возвращаем ОШИБКУ: молчаливый успех означал бы, что сетевые объекты
    # остались в системе вообще без учёта.
    say "ERROR: could not record leftover objects in $RECOVERY_FILE"
    return 1
  }
  say "recorded leftover objects in $RECOVERY_FILE for the next run"
  return 0
}

# rollback_created_rules: откат ровно того, что создал текущий запуск.
rollback_created_rules(){
  if [ -s "$CREATED_RULES" ]; then
    while read -r fam mk tb pr; do
      [ -z "$fam" ] && continue
      say "[rollback] removing rule added in this run (family=$fam mark=$mk table=$tb prio=$pr)"
      rule_del_one "$fam" "$mk" "$tb" "$pr"
      if rule_present "$fam" "$mk" "$tb" "$pr"; then
        say "warning: rollback could not remove rule - recorded for retry"
        echo "$fam $mk $tb $pr" >> "$STALE_LEFT"
      fi
    done < "$CREATED_RULES"
  fi
  # Маршруты откатываем только те, которых до нас не было: таблица могла
  # уже обслуживать второй протокол, и её очистка сломала бы рабочую
  # конфигурацию, которую откат обязан сохранить.
  if [ -s "$CREATED_ROUTES" ]; then
    while read -r fam tb; do
      [ -z "$fam" ] && continue
      say "[rollback] removing local route added in this run (family=$fam table=$tb)"
      route_del_table "$fam" "$tb"
      if route_present "$fam" "$tb"; then
        say "warning: rollback could not flush route table - recorded for retry"
        echo "$fam $tb" >> "$STALE_ROUTES_LEFT"
      fi
    done < "$CREATED_ROUTES"
  fi
  return 0
}

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

  while IFS= read -r raw || [ -n "$raw" ]; do
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
    while IFS= read -r it || [ -n "$it" ]; do
      it="${it%%#*}"
      it="$(printf "%s" "$it" | tr -d '\r' | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
      [ -z "$it" ] && continue
      case "$it" in
        */*) valid_ipv4_cidr "$it" && CIDR4_LIST="$CIDR4_LIST $it" ;;
        *)   valid_ipv4 "$it" && HOST4_LIST="$HOST4_LIST $it" ;;
      esac
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
      while IFS= read -r it || [ -n "$it" ]; do
        it="${it%%#*}"
        it="$(printf "%s" "$it" | tr -d '\r' | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
        [ -z "$it" ] && continue
        case "$it" in
          */*) valid_ipv6_cidr "$it" && CIDR6_LIST="$CIDR6_LIST $it" ;;
          *)   valid_ipv6 "$it" && HOST6_LIST="$HOST6_LIST $it" ;;
        esac
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
    while IFS= read -r it || [ -n "$it" ]; do
      it="${it%%#*}"; it="$(printf "%s" "$it" | tr -d '\r' | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
      [ -z "$it" ] || { valid_ipv4_entry "$it" && SRC_ONLY4_LIST="$SRC_ONLY4_LIST $it"; }
    done < "$SRC_ONLY_V4_FILE"
  fi
  if [ "$IPV6_ENABLED" -eq 1 ] && [ -f "$SRC_ONLY_V6_FILE" ]; then
    while IFS= read -r it || [ -n "$it" ]; do
      it="${it%%#*}"; it="$(printf "%s" "$it" | tr -d '\r' | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
      [ -z "$it" ] || { valid_ipv6_entry "$it" && SRC_ONLY6_LIST="$SRC_ONLY6_LIST $it"; }
    done < "$SRC_ONLY_V6_FILE"
  fi
  if [ -f "$SRC_BYPASS_V4_FILE" ]; then
    while IFS= read -r it || [ -n "$it" ]; do
      it="${it%%#*}"; it="$(printf "%s" "$it" | tr -d '\r' | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
      [ -z "$it" ] || { valid_ipv4_entry "$it" && SRC_BYP4_LIST="$SRC_BYP4_LIST $it"; }
    done < "$SRC_BYPASS_V4_FILE"
  fi
  if [ "$IPV6_ENABLED" -eq 1 ] && [ -f "$SRC_BYPASS_V6_FILE" ]; then
    while IFS= read -r it || [ -n "$it" ]; do
      it="${it%%#*}"; it="$(printf "%s" "$it" | tr -d '\r' | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
      [ -z "$it" ] || { valid_ipv6_entry "$it" && SRC_BYP6_LIST="$SRC_BYP6_LIST $it"; }
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

  # Атомарная подмена одной транзакцией.
  #
  # Раньше рабочая таблица удалялась ЗДЕСЬ, до сборки и проверки нового
  # конфига. Если потом `nft --check` падал, скрипт делал exit 1, но
  # таблицы на роутере уже не было: перехват тихо выключался и весь трафик
  # шёл мимо прокси (fail-open) без единого сообщения пользователю.
  #
  # Теперь удаление входит в тот же batch-файл, что и создание. Идиома
  # "create-empty / delete / create-new" нужна, чтобы `delete` не падал,
  # когда таблицы ещё нет (первый запуск). Весь файл сначала проверяется
  # `nft --check` (проверено: rc=1 на битом конфиге, ничего не создаёт), и
  # только потом применяется одной транзакцией: при ошибке старая рабочая
  # таблица остаётся нетронутой.
  # Пишем в файл, путь которого известен вызывающему коду (NFT_CONFIG),
  # и НЕ ставим здесь собственный trap: раньше `trap ... EXIT INT TERM` в
  # этой функции затирал trap, установленный start(), из-за чего по сигналу
  # или на ветке с ошибкой утекали ruleset-файлы вызывающего.
  tmpfile="$NFT_CONFIG"
  {
    # Если имя таблицы поменяли в UCI, старая таблица известна только из
    # state. Удаляем её в ТОЙ ЖЕ транзакции: иначе она остаётся с активным
    # prerouting-хуком и продолжает заворачивать трафик в TPROXY-порт,
    # которого уже нет.
    _old_tbl="$(state_get NFT_TABLE)"
    if [ -n "$_old_tbl" ] && [ "$_old_tbl" != "$NFT_TABLE" ]; then
      echo "table inet $_old_tbl {}"
      echo "delete table inet $_old_tbl"
    fi
    echo "table inet $NFT_TABLE {}"
    echo "delete table inet $NFT_TABLE"
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

    # Явный iifname-gate: перехватываем только трафик, реально пришедший
    # с настроенных LAN-интерфейсов. Гейт по подсетям (@lan_saddr*) ниже
    # остаётся вторым слоем, но сам по себе он пропустил бы пакет с
    # подходящим saddr, пришедший с любого другого интерфейса.
    _ifl=""
    for _i in $LAN_IFACES; do
      if [ -z "$_ifl" ]; then _ifl="\"$_i\""; else _ifl="$_ifl, \"$_i\""; fi
    done
    [ -n "$_ifl" ] && echo "    iifname != { $_ifl } return"

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
        # "only" = проксировать ТОЛЬКО перечисленные источники.
        # Пустой список для семейства раньше означал, что правило-фильтр
        # вообще не эмитилось, и через прокси уходили ВСЕ адреса этого
        # семейства — прямо противоположно тому, что просил пользователь
        # (fail-open). Теперь пустой список честно означает "ни один
        # источник этого семейства не проксируется": возвращаем весь
        # трафик семейства до TPROXY-правил.
        if [ -n "$SRC_ONLY4_SET" ]; then
          echo "    ip  saddr != @src_only4 return"
        else
          echo "    meta nfproto ipv4 return"
        fi
        if [ "$IPV6_ENABLED" -eq 1 ]; then
          if [ -n "$SRC_ONLY6_SET" ]; then
            echo "    ip6 saddr != @src_only6 return"
          else
            echo "    meta nfproto ipv6 return"
          fi
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

  return 0
}

# check_nft: валидация собранного конфига БЕЗ применения. Вызывается до
# любых изменений policy routing, чтобы невалидная конфигурация вообще не
# приводила к касанию сети (раньше правила уже были добавлены и их
# приходилось откатывать).
check_nft(){
  if ! nft --check -f "$NFT_CONFIG"; then
    say "nft validation failed"
    return 1
  fi
  return 0
}

# commit_nft: применение уже проверенного конфига одной транзакцией.
commit_nft(){
  if ! nft -f "$NFT_CONFIG"; then
    say "nft apply failed"
    return 1
  fi
  return 0
}

# remove_nft: удаление таблицы inet $NFT_TABLE (если есть)
remove_nft(){ nft delete table inet "$NFT_TABLE" 2>/dev/null || true; }

# diag: человекочитаемая диагностика текущей конфигурации/правил
diag(){
  # Обновим парсинг портов для корректного вывода
  parse_ports_file

  say "=== TPROXY DIAG ==="
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
  # ip(8) prints fwmark ALWAYS in hex, while UCI accepts decimal too: a config
  # with fwmark_tcp='1' made every check below fail and status report "degraded"
  # on a perfectly working setup. Compare the normalized form, the same way
  # rule_present() does.
  _s_mt="$(norm_mark "$FWMARK_TCP")"; _s_mu="$(norm_mark "$FWMARK_UDP")"
  ip rule   | grep -q "fwmark $_s_mt" || { say "degraded (no IPv4 rule TCP)"; miss=1; }
  ip rule   | grep -q "fwmark $_s_mu" || { say "degraded (no IPv4 rule UDP)"; miss=1; }
  if [ "$IPV6_ENABLED" -eq 1 ]; then
    ip -6 rule| grep -q "fwmark $_s_mt" || { say "degraded (no IPv6 rule TCP)"; miss=1; }
    ip -6 rule| grep -q "fwmark $_s_mu" || { say "degraded (no IPv6 rule UDP)"; miss=1; }
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
  # Взаимное исключение со stop и с другим start. Замок НЕ снимается через
  # trap намеренно: `apply_nft` ставит свой trap и в конце делает `trap - EXIT`,
  # затирая чужой. Аварийный выход оставляет замок с нашим PID, и следующий
  # вызов забирает его сразу же, увидев, что процесса нет, — поэтому явное
  # снятие ниже это оптимизация, а не условие корректности.
  lock_acquire || exit 1
  preflight
  # Жёсткая проверка: LAN_IFACES не должен быть пустым/состоять из одних пробелов/переводов строки.
  if [ -z "$(printf '%s' "$LAN_IFACES" | tr -d '[:space:]')" ]; then
    say "error: LAN_IFACES is empty (set e.g. LAN_IFACES='br-lan' or via UCI option ifaces)"; exit 1
  fi
  validate_marks     # (п.4)
  validate_tports    # (п.8)
  # Полная проверка входных данных ДО любых изменений сети.
  validate_ifaces  || exit 1
  validate_all_lists || { say "aborting: fix the list files above and retry"; exit 1; }
  # ВАЖНО: здесь НЕТ remove_nft. Раньше таблица сносилась прямо тут, до
  # сборки и проверки нового конфига, поэтому любая ошибка валидации в
  # apply_nft оставляла роутер вообще без таблицы — перехват молча
  # отключался, трафик шёл мимо прокси. Теперь apply_nft подменяет таблицу
  # одной транзакцией (create/delete/create в проверенном batch), и при
  # неудачной валидации прежняя рабочая таблица остаётся на месте.
  #
  # Порядок здесь тоже важен: сначала ДОБАВЛЯЕМ новые policy-правила
  # (операция аддитивная, старые продолжают работать), затем применяем
  # nft, и только после его успеха снимаем устаревшие правила. Раньше
  # правила сначала удалялись — и неудачный apply_nft оставлял систему
  # без policy routing вообще.
  # Явная уборка на КАЖДОЙ ветке выхода вместо опоры на trap: apply_nft
  # ставит собственный trap и в конце снимает его через `trap - EXIT`,
  # затирая наш — на ветках с ошибкой файлы иначе утекают в /tmp.
  # Убираем каталог целиком: все временные файлы этого запуска лежат внутри.
  rules_cleanup(){ [ -n "$RUNDIR" ] && rm -rf "$RUNDIR" 2>/dev/null; return 0; }
  trap 'rules_cleanup' INT TERM
  : > "$STALE_LEFT"; : > "$STALE_ROUTES_LEFT"; : > "$STALE_NFT_LEFT"
  retry_recorded_stale
  # Сначала собираем и ПРОВЕРЯЕМ nft-конфиг — до единого изменения в сети.
  # Раньше правила уже добавлялись, и невалидный конфиг приходилось
  # откатывать; теперь при ошибке валидации сеть вообще не трогается.
  if ! apply_nft "$MODE" || ! check_nft; then
    say "nft config is invalid - no network changes were made"
    rules_cleanup
    exit 1
  fi
  if ! apply_iprules; then
    say "policy routing setup failed - rolling back"
    rollback_created_rules
    persist_leftovers_to_recovery || \
      say "WARNING: leftover objects could not be recorded; they are now untracked"
    rules_cleanup
    exit 1
  fi
  if ! commit_nft; then
    say "nft apply failed - rolling back only what this run created"
    rollback_created_rules
    persist_leftovers_to_recovery || \
      say "WARNING: leftover objects could not be recorded; they are now untracked"
    rules_cleanup
    exit 1
  fi
  remove_iprules_delta
  # Не удалившиеся stale-объекты дописываем в state, чтобы следующий
  # start/stop попробовал их снова.
  if [ -s "$STALE_LEFT" ]; then
    say "warning: some stale objects could not be removed - recorded for retry"
  fi
  # `state_write` возвращает 1/2 как штатный сигнал, а не как аварию. Под
  # `set -e` вызов на отдельной строке завершал бы shell ДО чтения $?, и
  # ни предупреждение, ни ошибка, ни уборка не выполнялись бы вовсе.
  # `|| _sw_rc=$?` делает команду частью условия и снимает это поведение.
  _sw_rc=0
  state_write || _sw_rc=$?
  if [ "$_sw_rc" -eq 1 ]; then
    say "WARNING: primary runtime state could not be written; recorded in $RECOVERY_FILE instead"
  elif [ "$_sw_rc" -ne 0 ]; then
    # Ни основной state, ни recovery. Конфигурация применена, но следующий
    # запуск не будет знать, что именно вычищать — это degraded-состояние,
    # и молчать о нём нельзя.
    say "ERROR: configuration applied but NEITHER $STATE_FILE NOR $RECOVERY_FILE could be written"
    say "       cleanup on the next start/stop will be incomplete"
    rules_cleanup; trap - INT TERM
    lock_release
    diag
    exit 2
  fi
  rules_cleanup; trap - INT TERM
  lock_release
  diag
}

# stop: полная деинициализация и диагностика остаточного состояния.
# Чистим и по ТЕКУЩЕМУ UCI, и по сохранённому state: если идентификаторы
# успели поменять между start и stop, объекты предыдущего запуска известны
# только из state, и без него они остались бы висеть навсегда.
stop(){
  lock_acquire || exit 1
  rundir_init
  # Снимаем фактически применённые значения ДО любого удаления: после
  # teardown state может быть уже переписан, а UCI мог измениться — писать
  # в state текущий UCI вместо реально применённых объектов означало бы
  # запомнить не то, что осталось в системе.
  _a_tbl="$(state_get NFT_TABLE)"
  _a_fwt="$(state_get FWMARK_TCP)"; _a_fwu="$(state_get FWMARK_UDP)"
  _a_rtt="$(state_get RTTAB_TCP)";  _a_rtu="$(state_get RTTAB_UDP)"
  _a_pt="$(state_get RULE_PRIO_TCP)"; _a_pu="$(state_get RULE_PRIO_UDP)"
  # IPv6-флаг тоже снимаем ДО teardown: при неполном stop в state должен
  # попасть тот режим, при котором объекты были созданы, а не текущий UCI —
  # иначе следующий запуск не будет знать, что нужно чистить v6-объекты.
  _a_v6="$(state_get IPV6_ENABLED)"
  [ -n "$_a_v6" ] || _a_v6="$IPV6_ENABLED"

  # Все три списка инициализируются ДО retry_recorded_stale: тот дописывает
  # в них объекты, пережившие повторное удаление, и без предварительной
  # инициализации его результаты либо терялись, либо смешивались с
  # содержимым от прошлого запуска.
  : > "$STALE_LEFT" 2>/dev/null || true
  : > "$STALE_ROUTES_LEFT" 2>/dev/null || true
  : > "$STALE_NFT_LEFT" 2>/dev/null || true

  remove_nft
  [ -n "$_a_tbl" ] && [ "$_a_tbl" != "$NFT_TABLE" ] && \
    nft delete table inet "$_a_tbl" 2>/dev/null || true
  remove_iprules
  iprules_del_set "$_a_fwt" "$_a_fwu" "$_a_rtt" "$_a_rtu" "$_a_pt" "$_a_pu"
  retry_recorded_stale

  # Подтверждаем фактическое отсутствие ВСЕХ типов объектов: таблиц,
  # правил и маршрутов обоих семейств. Раньше маршруты не проверялись, и
  # незачищенная таблица маршрутов молча терялась из учёта.
  # STALE_NFT_LEFT здесь НЕ обнуляется: в нём уже могут лежать таблицы,
  # пережившие retry_recorded_stale, и их нужно сохранить.
  _left=0
  for _t in "$NFT_TABLE" "$_a_tbl"; do
    [ -n "$_t" ] || continue
    if nft list table inet "$_t" >/dev/null 2>&1; then
      say "warning: nft table $_t is still present after stop"
      # Записываем КАЖДУЮ уцелевшую таблицу: раньше сохранялась только
      # последняя, и если пережили обе (текущая из UCI и записанная в
      # state), одна из них теряла всякий учёт.
      grep -qx "$_t" "$STALE_NFT_LEFT" 2>/dev/null || echo "$_t" >> "$STALE_NFT_LEFT"
      _left=1
    fi
  done
  for _fam in 4 6; do
    for _set in "$_a_fwt $_a_rtt $_a_pt" "$_a_fwu $_a_rtu $_a_pu"; do
      set -- $_set
      [ -n "${1:-}" ] && [ -n "${2:-}" ] && [ -n "${3:-}" ] || continue
      if rule_present "$_fam" "$1" "$2" "$3"; then
        say "warning: policy rule still present after stop (family=$_fam mark=$1 table=$2)"
        echo "$_fam $1 $2 $3" >> "$STALE_LEFT"; _left=1
      fi
      if route_present "$_fam" "$2"; then
        say "warning: route table $2 still populated after stop (family=$_fam)"
        grep -qx "$_fam $2" "$STALE_ROUTES_LEFT" 2>/dev/null || echo "$_fam $2" >> "$STALE_ROUTES_LEFT"
        _left=1
      fi
    done
  done

  # Учитываем и то, что осталось после retry_recorded_stale: иначе объекты,
  # пережившие повторное удаление, считались бы вычищенными и state/recovery
  # удалялись бы вместе с последним знанием о них.
  [ -s "$STALE_LEFT" ] && _left=1
  [ -s "$STALE_ROUTES_LEFT" ] && _left=1
  [ -s "$STALE_NFT_LEFT" ] && _left=1

  if [ "$_left" -eq 0 ]; then
    rm -f "$STATE_FILE" "$RECOVERY_FILE" 2>/dev/null || true
  else
    say "warning: keeping runtime state - some objects could not be removed"
    # Пишем ИМЕННО оставшиеся применённые значения, а не текущий UCI.
    # NFT_TABLE берём первой из уцелевших; остальные всё равно попадут в
    # state как STALE_NFT, который пишет state_write.
    _first_left_tbl="$(head -n1 "$STALE_NFT_LEFT" 2>/dev/null)"
    _sw_rc=0
    NFT_TABLE="${_first_left_tbl:-$_a_tbl}" \
    FWMARK_TCP="$_a_fwt" FWMARK_UDP="$_a_fwu" \
    RTTAB_TCP="$_a_rtt" RTTAB_UDP="$_a_rtu" \
    RULE_PRIO_TCP="$_a_pt" RULE_PRIO_UDP="$_a_pu" \
    IPV6_ENABLED="$_a_v6" \
      state_write || _sw_rc=$?
    if [ "$_sw_rc" -eq 1 ]; then
      say "WARNING: leftover objects recorded in $RECOVERY_FILE (primary state unavailable)"
    elif [ "$_sw_rc" -ne 0 ]; then
      # Раньше результат глотался через `|| true`, и пользователь получал
      # сообщение о сохранённом состоянии, которого на диске нет.
      say "ERROR: objects survived stop and NEITHER state file could be written"
      say "       these objects are now untracked: inspect nft and ip rule manually"
    fi
  fi
  [ -n "$RUNDIR" ] && rm -rf "$RUNDIR" 2>/dev/null
  lock_release
  diag
}

# restart: прокси к start с текущим режимом
restart(){ start "${1:-$PORT_MODE_DEFAULT}"; }

# ===== MAIN =====
# Загрузка UCI-конфига (если есть точная секция tproxy-manager.main) — без grep по всему uci show
if command -v uci >/dev/null 2>&1; then
  if uci -q show tproxy-manager.main >/dev/null 2>&1; then
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