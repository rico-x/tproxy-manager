# shellcheck shell=sh

PKG="tproxy-manager"

STATE_FILE="/tmp/tproxy-manager-watchdog.state"
LINK_STATE_DIR="/tmp/tproxy-manager-watchdog-links"
LOCK_DIR="/tmp/tproxy-manager-watchdog.lock"
SCAN_LOCK_DIR="/tmp/tproxy-manager-watchdog-scan.lock"
LOG_FILE="/tmp/tproxy-manager-watchdog.log"
LOG_TAG_DEFAULT="tproxy-manager-watchdog"

PROXY_ENGINE_DEFAULT="xray"
CHECK_URL_DEFAULT="https://ifconfig.me/ip"
PROXY_URL_DEFAULT="socks5h://127.0.0.1:10808"
INTERVAL_DEFAULT="60"
FAIL_THRESHOLD_DEFAULT="3"
CONNECT_TIMEOUT_DEFAULT="15"
MAX_TIME_DEFAULT="20"
LINKS_FILE_DEFAULT="/etc/tproxy-manager/watchdog.links"
TEMPLATE_FILE_DEFAULT="/etc/tproxy-manager/watchdog-outbound.template.jsonc"
TEST_TEMPLATE_FILE_DEFAULT="/etc/tproxy-manager/watchdog-test-config.template.jsonc"
BATCH_TEST_TEMPLATE_FILE_DEFAULT="/etc/tproxy-manager/watchdog-batch-test-config.template.jsonc"
# Xray-only: Hysteria 2 is a stream transport there, not an outbound protocol.
# The name says so now -- read as "the hysteria template" these were easy to take
# for something every engine used.
XRAY_HY2_TEMPLATE_FILE_DEFAULT="/etc/tproxy-manager/watchdog-hysteria-outbound.template.jsonc"
XRAY_HY2_TEST_TEMPLATE_FILE_DEFAULT="/etc/tproxy-manager/watchdog-hysteria-test-config.template.jsonc"
XRAY_HY2_BATCH_TEST_TEMPLATE_FILE_DEFAULT="/etc/tproxy-manager/watchdog-hysteria-batch-test-config.template.jsonc"
MIHOMO_VLESS_OUTBOUND_TEMPLATE_FILE_DEFAULT="/etc/tproxy-manager/watchdog-mihomo-vless-outbound.template.yaml"
MIHOMO_HY2_OUTBOUND_TEMPLATE_FILE_DEFAULT="/etc/tproxy-manager/watchdog-mihomo-hysteria-outbound.template.yaml"
SINGBOX_VLESS_OUTBOUND_TEMPLATE_FILE_DEFAULT="/etc/tproxy-manager/watchdog-singbox-vless-outbound.template.jsonc"
SINGBOX_HY2_OUTBOUND_TEMPLATE_FILE_DEFAULT="/etc/tproxy-manager/watchdog-singbox-hysteria-outbound.template.jsonc"
MIHOMO_TEST_TEMPLATE_FILE_DEFAULT="/etc/tproxy-manager/watchdog-mihomo-test-config.template.yaml"
MIHOMO_BATCH_TEST_TEMPLATE_FILE_DEFAULT="/etc/tproxy-manager/watchdog-mihomo-batch-test-config.template.yaml"
SINGBOX_TEST_TEMPLATE_FILE_DEFAULT="/etc/tproxy-manager/watchdog-singbox-test-config.template.jsonc"
SINGBOX_BATCH_TEST_TEMPLATE_FILE_DEFAULT="/etc/tproxy-manager/watchdog-singbox-batch-test-config.template.jsonc"
OUTBOUND_FILE_DEFAULT="/etc/xray/04_outbounds.json"
VLESS2JSON_DEFAULT="/usr/bin/vless2json.sh"
PROXY2MIHOMO_DEFAULT="/usr/bin/proxy2mihomo.lua"
PROXY2SINGBOX_DEFAULT="/usr/bin/proxy2singbox.lua"
ENGINE_PROBE_INFO="${ENGINE_PROBE_INFO:-/usr/libexec/tproxy-manager/engine-probe-info}"
SERVICE_PATH_DEFAULT="/etc/init.d/xray"
RESTART_CMD_DEFAULT="restart"
TEST_COMMAND_DEFAULT="/usr/bin/xray -c {config}"
TPROXY_PORT_DEFAULT="61219"
MIHOMO_CONFIG_FILE_DEFAULT="/etc/mihomo/tproxy-manager.yaml"
MIHOMO_PROVIDER_FILE_DEFAULT="/etc/mihomo/tproxy-manager-proxies.yaml"
MIHOMO_CONFIG_DIR_DEFAULT="/etc/mihomo/tproxy-manager.d"
SINGBOX_CONFIG_FILE_DEFAULT="/etc/sing-box/tproxy-manager.json"
SINGBOX_OUTBOUNDS_FILE_DEFAULT="/etc/sing-box/tproxy-manager-outbounds.json"
SINGBOX_CONFIG_DIR_DEFAULT="/etc/sing-box/tproxy-manager.d"
SELECTION_MODE_DEFAULT="random"
EXCLUDE_DEAD_DEFAULT="0"
COOLDOWN_HOURS_DEFAULT="0"
COOLDOWN_MINUTES_DEFAULT="0"
TEST_PORT_DEFAULT="10881"
BACKGROUND_CHECK_ENABLED_DEFAULT="0"
BACKGROUND_CHECK_INTERVAL_DEFAULT="1800"
BATCH_CHECK_ENABLED_DEFAULT="1"
BATCH_CHECK_PORT_START_DEFAULT="10882"
BATCH_CHECK_BATCH_SIZE_DEFAULT="64"
BATCH_CHECK_CONCURRENCY_DEFAULT="8"
BATCH_CHECK_FALLBACK_DEFAULT="1"

TEST_PID=""
TEST_DIR=""

usage() {
    cat <<EOF
Использование:
  $0 once
  $0 run
  $0 status
  $0 reset
  $0 test-rotate
  $0 test-link <line_hash>
  $0 apply-link <line_hash>
  $0 check-all
  $0 help
EOF
}

log_msg() {
    msg="$*"
    ts="$(now_human)"
    printf '%s %s\n' "$ts" "$msg" >> "$LOG_FILE" 2>/dev/null || true
    logger -t "$LOG_TAG" "$msg" 2>/dev/null || true
    printf '%s\n' "$msg"
}

trim_text() {
    printf '%s' "$1" | sed -e 's/\r//g' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

validate_number() {
    case "$1" in
        ''|*[!0-9]*)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

require_number_or_default() {
    value="$1"
    fallback="$2"
    if validate_number "$value"; then
        printf '%s\n' "$value"
    else
        printf '%s\n' "$fallback"
    fi
}

shellescape() {
    case "$1" in
        '')
            printf "''"
            ;;
        *)
            printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
            ;;
    esac
}

now_ts() {
    date '+%s' 2>/dev/null || echo 0
}

now_human() {
    date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo unknown_time
}

ensure_runtime_dirs() {
    [ -d "$LINK_STATE_DIR" ] || mkdir -p "$LINK_STATE_DIR"
    : >> "$LOG_FILE" 2>/dev/null || true
}

uci_get() {
    key="$1"
    uci -q get "$PKG.main.$key" 2>/dev/null || true
}

# Ask the engine definitions how the active engine wants to be probed, instead of
# guessing from a stored command. tproxy_manager.engines is the only description
# of an engine in the package; keeping a second copy here is exactly how the
# probe came to run Xray whatever was active.
#
# Sets PROBE_KIND, PROBE_LOG_NAME, PROBE_CONFIG_EXT, PROBE_PROTOCOLS,
# PROBE_BATCH, PROBE_TEST_COMMAND, PROBE_ENGINE, PROBE_LABEL, PROBE_BINARY, plus
# PROBE_ENGINE_UNKNOWN when the configured engine is not one we know.
load_probe_descriptor() {
    PROBE_ENGINE=""
    PROBE_LABEL=""
    PROBE_KIND=""
    PROBE_LOG_NAME=""
    PROBE_CONFIG_EXT=""
    PROBE_PROTOCOLS=""
    PROBE_BATCH=""
    PROBE_TEST_COMMAND=""
    PROBE_BINARY=""
    PROBE_ENGINE_UNKNOWN=""
    # Both always defined. A caller may load the descriptor without having read
    # UCI first -- the suites do exactly that -- and under `set -u` reading an
    # unset TEST_COMMAND below would kill the shell.
    TEST_COMMAND="${TEST_COMMAND:-}"
    TEST_COMMAND_STALE="${TEST_COMMAND_STALE:-}"

    if [ -x "$ENGINE_PROBE_INFO" ]; then
        probe_info="$("$ENGINE_PROBE_INFO" "$PROXY_ENGINE" 2>/dev/null)"
        if [ -n "$probe_info" ]; then
            eval "$probe_info"
        else
            PROBE_ENGINE_UNKNOWN="$PROXY_ENGINE"
        fi
    fi

    # Without the helper (a partial install, or a stripped image) the watchdog has
    # to keep working, so the three engines we ship are described here as well.
    # This is a fallback, not a second source of truth: it only fills in what the
    # helper did not answer.
    if [ -z "$PROBE_KIND" ]; then
        case "$PROXY_ENGINE" in
            xray)
                PROBE_KIND="template"; PROBE_LOG_NAME="xray-test.log"; PROBE_CONFIG_EXT="json"
                PROBE_TEST_COMMAND="${PROBE_TEST_COMMAND:-$TEST_COMMAND_DEFAULT}"
                ;;
            mihomo)
                PROBE_KIND="mihomo"; PROBE_LOG_NAME="mihomo-test.log"; PROBE_CONFIG_EXT="yaml"
                PROBE_TEST_COMMAND="${PROBE_TEST_COMMAND:-/usr/bin/mihomo -f {config}}"
                ;;
            singbox)
                PROBE_KIND="singbox"; PROBE_LOG_NAME="singbox-test.log"; PROBE_CONFIG_EXT="json"
                PROBE_TEST_COMMAND="${PROBE_TEST_COMMAND:-/usr/bin/sing-box run -c {config}}"
                ;;
            *)
                # An engine nobody can describe is reported, not quietly turned into
                # Xray. Probing every link with the wrong engine marks them all dead,
                # which reads exactly like every server being down.
                PROBE_ENGINE_UNKNOWN="$PROXY_ENGINE"
                PROXY_ENGINE="$PROXY_ENGINE_DEFAULT"
                PROBE_KIND="template"; PROBE_LOG_NAME="xray-test.log"; PROBE_CONFIG_EXT="json"
                PROBE_TEST_COMMAND="${PROBE_TEST_COMMAND:-$TEST_COMMAND_DEFAULT}"
                ;;
        esac
        PROBE_ENGINE="$PROXY_ENGINE"
    fi
    [ -n "$PROBE_LABEL" ] || PROBE_LABEL="$PROBE_ENGINE"
    # Deliberately outside the fallback: an empty PROBE_PROTOCOLS would make
    # engine_supports_protocol() refuse every link, and the whole list would come
    # back "unsupported" from one missing line of helper output.
    [ -n "$PROBE_PROTOCOLS" ] || PROBE_PROTOCOLS="vless hy2"
    [ -n "$PROBE_BATCH" ] || PROBE_BATCH="1"

    # The stored command can fall out of step with the active engine: a fresh
    # install that is not on Xray, a restored backup, a hand edit, or saving the
    # Watchdog form. Running the wrong binary against a config it cannot read
    # fails every probe, which is indistinguishable from every server being
    # down -- so the engine's own profile wins and the disagreement is reported.
    #
    # Reconciled HERE, not in load_config, so that this function is the only
    # thing a caller has to re-run after PROXY_ENGINE changes. With it in the
    # caller, refreshing the descriptor alone kept the previous engine's command:
    # a Mihomo YAML config handed to Xray, and every link reported dead.
    if [ -n "$PROBE_TEST_COMMAND" ]; then
        if [ -z "$TEST_COMMAND" ] || [ "$TEST_COMMAND" = "$PROBE_TEST_COMMAND" ]; then
            TEST_COMMAND="$PROBE_TEST_COMMAND"
            TEST_COMMAND_STALE=""
        else
            TEST_COMMAND_STALE="$TEST_COMMAND"
            TEST_COMMAND="$PROBE_TEST_COMMAND"
        fi
    fi
}

engine_supports_protocol() {
    for supported in $PROBE_PROTOCOLS; do
        [ "$supported" = "$1" ] && return 0
    done
    return 1
}

load_config() {
    PROXY_ENGINE="$(uci_get proxy_engine)"
    CHECK_URL="$(uci_get watchdog_check_url)"
    PROXY_URL="$(uci_get watchdog_proxy_url)"
    INTERVAL="$(uci_get watchdog_interval)"
    FAIL_THRESHOLD="$(uci_get watchdog_fail_threshold)"
    CONNECT_TIMEOUT="$(uci_get watchdog_connect_timeout)"
    MAX_TIME="$(uci_get watchdog_max_time)"
    LINKS_FILE="$(uci_get watchdog_links_file)"
    TEMPLATE_FILE="$(uci_get watchdog_template_file)"
    TEST_TEMPLATE_FILE="$(uci_get watchdog_test_template_file)"
    BATCH_TEST_TEMPLATE_FILE="$(uci_get watchdog_batch_test_template_file)"
    XRAY_HY2_TEMPLATE_FILE="$(uci_get watchdog_hysteria_template_file)"
    XRAY_HY2_TEST_TEMPLATE_FILE="$(uci_get watchdog_hysteria_test_template_file)"
    XRAY_HY2_BATCH_TEST_TEMPLATE_FILE="$(uci_get watchdog_hysteria_batch_test_template_file)"
    MIHOMO_VLESS_OUTBOUND_TEMPLATE_FILE="$(uci_get watchdog_mihomo_vless_outbound_template_file)"
    MIHOMO_HY2_OUTBOUND_TEMPLATE_FILE="$(uci_get watchdog_mihomo_hysteria_outbound_template_file)"
    SINGBOX_VLESS_OUTBOUND_TEMPLATE_FILE="$(uci_get watchdog_singbox_vless_outbound_template_file)"
    SINGBOX_HY2_OUTBOUND_TEMPLATE_FILE="$(uci_get watchdog_singbox_hysteria_outbound_template_file)"
    MIHOMO_TEST_TEMPLATE_FILE="$(uci_get watchdog_mihomo_test_template_file)"
    MIHOMO_BATCH_TEST_TEMPLATE_FILE="$(uci_get watchdog_mihomo_batch_test_template_file)"
    SINGBOX_TEST_TEMPLATE_FILE="$(uci_get watchdog_singbox_test_template_file)"
    SINGBOX_BATCH_TEST_TEMPLATE_FILE="$(uci_get watchdog_singbox_batch_test_template_file)"
    OUTBOUND_FILE="$(uci_get watchdog_outbound_file)"
    VLESS2JSON="$(uci_get watchdog_vless2json)"
    PROXY2MIHOMO="$(uci_get watchdog_proxy2mihomo)"
    PROXY2SINGBOX="$(uci_get watchdog_proxy2singbox)"
    SERVICE_PATH="$(uci_get watchdog_service_path)"
    RESTART_CMD="$(uci_get watchdog_restart_cmd)"
    TEST_COMMAND="$(uci_get watchdog_test_command)"
    TPROXY_PORT="$(uci_get tproxy_port)"
    MIHOMO_CONFIG_FILE="$(uci_get mihomo_profile_config_file)"
    MIHOMO_PROVIDER_FILE="$(uci_get mihomo_profile_managed_provider_file)"
    MIHOMO_CONFIG_DIR="$(uci_get mihomo_profile_config_dir)"
    SINGBOX_CONFIG_FILE="$(uci_get singbox_profile_config_file)"
    SINGBOX_OUTBOUNDS_FILE="$(uci_get singbox_profile_managed_outbounds_file)"
    SINGBOX_CONFIG_DIR="$(uci_get singbox_profile_config_dir)"
    SELECTION_MODE="$(uci_get watchdog_selection_mode)"
    if [ -n "${WATCHDOG_SELECTION_MODE:-}" ]; then
        SELECTION_MODE="$WATCHDOG_SELECTION_MODE"
    fi
    EXCLUDE_DEAD="$(uci_get watchdog_exclude_dead)"
    COOLDOWN_HOURS="$(uci_get watchdog_dead_cooldown_hours)"
    COOLDOWN_MINUTES="$(uci_get watchdog_dead_cooldown_minutes)"
    TEST_PORT="$(uci_get watchdog_test_port)"
    BACKGROUND_CHECK_ENABLED="$(uci_get watchdog_background_check_enabled)"
    BACKGROUND_CHECK_INTERVAL="$(uci_get watchdog_background_check_interval)"
    BATCH_CHECK_ENABLED="$(uci_get watchdog_batch_check_enabled)"
    BATCH_CHECK_PORT_START="$(uci_get watchdog_batch_check_port_start)"
    BATCH_CHECK_BATCH_SIZE="$(uci_get watchdog_batch_check_batch_size)"
    BATCH_CHECK_CONCURRENCY="$(uci_get watchdog_batch_check_concurrency)"
    BATCH_CHECK_FALLBACK="$(uci_get watchdog_batch_check_fallback)"
    MIHOMO_MANAGED_FILE="$(uci_get mihomo_profile_managed_file)"
    SINGBOX_MANAGED_FILE="$(uci_get singbox_profile_managed_file)"
    LOG_TAG="$(uci_get watchdog_log_tag)"

    [ -n "$PROXY_ENGINE" ] || PROXY_ENGINE="$PROXY_ENGINE_DEFAULT"
    case "$PROXY_ENGINE" in
        sing-box|sing_box) PROXY_ENGINE="singbox" ;;
    esac
    load_probe_descriptor
    [ -n "$CHECK_URL" ] || CHECK_URL="$CHECK_URL_DEFAULT"
    [ -n "$PROXY_URL" ] || PROXY_URL="$PROXY_URL_DEFAULT"
    [ -n "$LINKS_FILE" ] || LINKS_FILE="$LINKS_FILE_DEFAULT"
    [ -n "$TEMPLATE_FILE" ] || TEMPLATE_FILE="$TEMPLATE_FILE_DEFAULT"
    [ -n "$TEST_TEMPLATE_FILE" ] || TEST_TEMPLATE_FILE="$TEST_TEMPLATE_FILE_DEFAULT"
    [ -n "$BATCH_TEST_TEMPLATE_FILE" ] || BATCH_TEST_TEMPLATE_FILE="$BATCH_TEST_TEMPLATE_FILE_DEFAULT"
    [ -n "$XRAY_HY2_TEMPLATE_FILE" ] || XRAY_HY2_TEMPLATE_FILE="$XRAY_HY2_TEMPLATE_FILE_DEFAULT"
    [ -n "$XRAY_HY2_TEST_TEMPLATE_FILE" ] || XRAY_HY2_TEST_TEMPLATE_FILE="$XRAY_HY2_TEST_TEMPLATE_FILE_DEFAULT"
    [ -n "$XRAY_HY2_BATCH_TEST_TEMPLATE_FILE" ] || XRAY_HY2_BATCH_TEST_TEMPLATE_FILE="$XRAY_HY2_BATCH_TEST_TEMPLATE_FILE_DEFAULT"
    [ -n "$MIHOMO_VLESS_OUTBOUND_TEMPLATE_FILE" ] || MIHOMO_VLESS_OUTBOUND_TEMPLATE_FILE="$MIHOMO_VLESS_OUTBOUND_TEMPLATE_FILE_DEFAULT"
    [ -n "$MIHOMO_HY2_OUTBOUND_TEMPLATE_FILE" ] || MIHOMO_HY2_OUTBOUND_TEMPLATE_FILE="$MIHOMO_HY2_OUTBOUND_TEMPLATE_FILE_DEFAULT"
    [ -n "$SINGBOX_VLESS_OUTBOUND_TEMPLATE_FILE" ] || SINGBOX_VLESS_OUTBOUND_TEMPLATE_FILE="$SINGBOX_VLESS_OUTBOUND_TEMPLATE_FILE_DEFAULT"
    [ -n "$SINGBOX_HY2_OUTBOUND_TEMPLATE_FILE" ] || SINGBOX_HY2_OUTBOUND_TEMPLATE_FILE="$SINGBOX_HY2_OUTBOUND_TEMPLATE_FILE_DEFAULT"
    [ -n "$MIHOMO_TEST_TEMPLATE_FILE" ] || MIHOMO_TEST_TEMPLATE_FILE="$MIHOMO_TEST_TEMPLATE_FILE_DEFAULT"
    [ -n "$MIHOMO_BATCH_TEST_TEMPLATE_FILE" ] || MIHOMO_BATCH_TEST_TEMPLATE_FILE="$MIHOMO_BATCH_TEST_TEMPLATE_FILE_DEFAULT"
    [ -n "$SINGBOX_TEST_TEMPLATE_FILE" ] || SINGBOX_TEST_TEMPLATE_FILE="$SINGBOX_TEST_TEMPLATE_FILE_DEFAULT"
    [ -n "$SINGBOX_BATCH_TEST_TEMPLATE_FILE" ] || SINGBOX_BATCH_TEST_TEMPLATE_FILE="$SINGBOX_BATCH_TEST_TEMPLATE_FILE_DEFAULT"
    [ -n "$OUTBOUND_FILE" ] || OUTBOUND_FILE="$OUTBOUND_FILE_DEFAULT"
    [ -n "$VLESS2JSON" ] || VLESS2JSON="$VLESS2JSON_DEFAULT"
    [ -n "$PROXY2MIHOMO" ] || PROXY2MIHOMO="$PROXY2MIHOMO_DEFAULT"
    [ -n "$PROXY2SINGBOX" ] || PROXY2SINGBOX="$PROXY2SINGBOX_DEFAULT"
    [ -n "$SERVICE_PATH" ] || SERVICE_PATH="$SERVICE_PATH_DEFAULT"
    [ -n "$RESTART_CMD" ] || RESTART_CMD="$RESTART_CMD_DEFAULT"
    [ -n "$TEST_COMMAND" ] || TEST_COMMAND="$TEST_COMMAND_DEFAULT"
    [ -n "$MIHOMO_CONFIG_FILE" ] || MIHOMO_CONFIG_FILE="$MIHOMO_CONFIG_FILE_DEFAULT"
    [ -n "$MIHOMO_PROVIDER_FILE" ] || MIHOMO_PROVIDER_FILE="$MIHOMO_PROVIDER_FILE_DEFAULT"
    [ -n "$MIHOMO_CONFIG_DIR" ] || MIHOMO_CONFIG_DIR="$MIHOMO_CONFIG_DIR_DEFAULT"
    [ -n "$SINGBOX_CONFIG_FILE" ] || SINGBOX_CONFIG_FILE="$SINGBOX_CONFIG_FILE_DEFAULT"
    [ -n "$SINGBOX_OUTBOUNDS_FILE" ] || SINGBOX_OUTBOUNDS_FILE="$SINGBOX_OUTBOUNDS_FILE_DEFAULT"
    [ -n "$SINGBOX_CONFIG_DIR" ] || SINGBOX_CONFIG_DIR="$SINGBOX_CONFIG_DIR_DEFAULT"
    # Единственный файл, который пакет перезаписывает у активного ядра. Остальное
    # в каталоге конфигов принадлежит пользователю.
    [ -n "$MIHOMO_MANAGED_FILE" ] || MIHOMO_MANAGED_FILE="$MIHOMO_PROVIDER_FILE"
    [ -n "$SINGBOX_MANAGED_FILE" ] || SINGBOX_MANAGED_FILE="$SINGBOX_OUTBOUNDS_FILE"
    [ -n "$LOG_TAG" ] || LOG_TAG="$LOG_TAG_DEFAULT"

    INTERVAL="$(require_number_or_default "$INTERVAL" "$INTERVAL_DEFAULT")"
    FAIL_THRESHOLD="$(require_number_or_default "$FAIL_THRESHOLD" "$FAIL_THRESHOLD_DEFAULT")"
    CONNECT_TIMEOUT="$(require_number_or_default "$CONNECT_TIMEOUT" "$CONNECT_TIMEOUT_DEFAULT")"
    MAX_TIME="$(require_number_or_default "$MAX_TIME" "$MAX_TIME_DEFAULT")"
    TPROXY_PORT="$(require_number_or_default "$TPROXY_PORT" "$TPROXY_PORT_DEFAULT")"
    COOLDOWN_HOURS="$(require_number_or_default "$COOLDOWN_HOURS" "$COOLDOWN_HOURS_DEFAULT")"
    COOLDOWN_MINUTES="$(require_number_or_default "$COOLDOWN_MINUTES" "$COOLDOWN_MINUTES_DEFAULT")"
    TEST_PORT="$(require_number_or_default "$TEST_PORT" "$TEST_PORT_DEFAULT")"
    BACKGROUND_CHECK_INTERVAL="$(require_number_or_default "$BACKGROUND_CHECK_INTERVAL" "$BACKGROUND_CHECK_INTERVAL_DEFAULT")"
    BATCH_CHECK_PORT_START="$(require_number_or_default "$BATCH_CHECK_PORT_START" "$BATCH_CHECK_PORT_START_DEFAULT")"
    BATCH_CHECK_BATCH_SIZE="$(require_number_or_default "$BATCH_CHECK_BATCH_SIZE" "$BATCH_CHECK_BATCH_SIZE_DEFAULT")"
    BATCH_CHECK_CONCURRENCY="$(require_number_or_default "$BATCH_CHECK_CONCURRENCY" "$BATCH_CHECK_CONCURRENCY_DEFAULT")"

    [ "$INTERVAL" -ge 1 ] || INTERVAL="$INTERVAL_DEFAULT"
    [ "$FAIL_THRESHOLD" -ge 1 ] || FAIL_THRESHOLD="$FAIL_THRESHOLD_DEFAULT"
    [ "$CONNECT_TIMEOUT" -ge 1 ] || CONNECT_TIMEOUT="$CONNECT_TIMEOUT_DEFAULT"
    [ "$MAX_TIME" -ge "$CONNECT_TIMEOUT" ] || MAX_TIME="$MAX_TIME_DEFAULT"
    [ "$MAX_TIME" -ge "$CONNECT_TIMEOUT" ] || MAX_TIME="$CONNECT_TIMEOUT"
    [ "$TPROXY_PORT" -ge 1 ] && [ "$TPROXY_PORT" -le 65535 ] || TPROXY_PORT="$TPROXY_PORT_DEFAULT"
    [ "$TEST_PORT" -ge 1 ] && [ "$TEST_PORT" -le 65535 ] || TEST_PORT="$TEST_PORT_DEFAULT"
    [ "$BACKGROUND_CHECK_INTERVAL" -ge 1 ] || BACKGROUND_CHECK_INTERVAL="$BACKGROUND_CHECK_INTERVAL_DEFAULT"
    [ "$BATCH_CHECK_PORT_START" -ge 1 ] && [ "$BATCH_CHECK_PORT_START" -le 65535 ] || BATCH_CHECK_PORT_START="$BATCH_CHECK_PORT_START_DEFAULT"
    [ "$BATCH_CHECK_BATCH_SIZE" -ge 1 ] || BATCH_CHECK_BATCH_SIZE="$BATCH_CHECK_BATCH_SIZE_DEFAULT"
    [ "$BATCH_CHECK_CONCURRENCY" -ge 1 ] || BATCH_CHECK_CONCURRENCY="$BATCH_CHECK_CONCURRENCY_DEFAULT"
    batch_end=$((BATCH_CHECK_PORT_START + BATCH_CHECK_BATCH_SIZE - 1))
    if [ "$BATCH_CHECK_PORT_START" -le "$TEST_PORT" ] && [ "$batch_end" -ge "$TEST_PORT" ] && [ "$TEST_PORT" -lt 65535 ]; then
        BATCH_CHECK_PORT_START=$((TEST_PORT + 1))
    fi
    max_batch_size=$((65535 - BATCH_CHECK_PORT_START + 1))
    [ "$BATCH_CHECK_BATCH_SIZE" -le "$max_batch_size" ] || BATCH_CHECK_BATCH_SIZE="$max_batch_size"
    [ "$BATCH_CHECK_CONCURRENCY" -le "$BATCH_CHECK_BATCH_SIZE" ] || BATCH_CHECK_CONCURRENCY="$BATCH_CHECK_BATCH_SIZE"

    case "$SELECTION_MODE" in
        random|ordered|fastest) : ;;
        *) SELECTION_MODE="$SELECTION_MODE_DEFAULT" ;;
    esac
    case "$EXCLUDE_DEAD" in
        0|1) : ;;
        *) EXCLUDE_DEAD="$EXCLUDE_DEAD_DEFAULT" ;;
    esac
    case "$BACKGROUND_CHECK_ENABLED" in
        0|1) : ;;
        *) BACKGROUND_CHECK_ENABLED="$BACKGROUND_CHECK_ENABLED_DEFAULT" ;;
    esac
    case "$BATCH_CHECK_ENABLED" in
        0|1) : ;;
        *) BATCH_CHECK_ENABLED="$BATCH_CHECK_ENABLED_DEFAULT" ;;
    esac
    case "$BATCH_CHECK_FALLBACK" in
        0|1) : ;;
        *) BATCH_CHECK_FALLBACK="$BATCH_CHECK_FALLBACK_DEFAULT" ;;
    esac

    COOLDOWN_SECONDS=$((COOLDOWN_HOURS * 3600 + COOLDOWN_MINUTES * 60))

    ensure_runtime_dirs

    if [ -n "$PROBE_ENGINE_UNKNOWN" ]; then
        log_msg "внимание: движок '$PROBE_ENGINE_UNKNOWN' неизвестен, проверка идёт через $PROBE_LABEL; исправьте proxy_engine"
    fi
    if [ -n "$TEST_COMMAND_STALE" ]; then
        log_msg "внимание: команда проверки '$TEST_COMMAND_STALE' не соответствует активному ядру $PROBE_LABEL, используется '$TEST_COMMAND'"
    fi
}

state_get() {
    key="$1"
    if [ -f "$STATE_FILE" ]; then
        sed -n "s/^${key}=//p" "$STATE_FILE" 2>/dev/null | tail -n 1
    fi
}

state_snapshot() {
    OVERALL_FAILCOUNT="$(state_get FAILCOUNT)"
    validate_number "$OVERALL_FAILCOUNT" || OVERALL_FAILCOUNT=0
    OVERALL_LAST_HTTP_CODE="$(state_get LAST_HTTP_CODE)"
    OVERALL_LAST_STATUS="$(state_get LAST_STATUS)"
    OVERALL_LAST_TS="$(state_get LAST_TS)"
    OVERALL_LAST_HUMAN="$(state_get LAST_TS_HUMAN)"
    OVERALL_LAST_SUCCESS_HASH="$(state_get LAST_SUCCESS_HASH)"
    OVERALL_LAST_APPLIED_HASH="$(state_get LAST_APPLIED_HASH)"
    OVERALL_LAST_LINK_SCAN_TS="$(state_get LAST_LINK_SCAN_TS)"
    OVERALL_LAST_LINK_SCAN_HUMAN="$(state_get LAST_LINK_SCAN_HUMAN)"
    OVERALL_LAST_LINK_SCAN_STATUS="$(state_get LAST_LINK_SCAN_STATUS)"
    OVERALL_LAST_LINK_SCAN_ALIVE="$(state_get LAST_LINK_SCAN_ALIVE)"
    OVERALL_LAST_LINK_SCAN_TOTAL="$(state_get LAST_LINK_SCAN_TOTAL)"

    [ -n "$OVERALL_LAST_HTTP_CODE" ] || OVERALL_LAST_HTTP_CODE="-"
    [ -n "$OVERALL_LAST_STATUS" ] || OVERALL_LAST_STATUS="-"
    [ -n "$OVERALL_LAST_TS" ] || OVERALL_LAST_TS="0"
    [ -n "$OVERALL_LAST_HUMAN" ] || OVERALL_LAST_HUMAN="-"
    validate_number "$OVERALL_LAST_LINK_SCAN_TS" || OVERALL_LAST_LINK_SCAN_TS=0
    [ -n "$OVERALL_LAST_LINK_SCAN_HUMAN" ] || OVERALL_LAST_LINK_SCAN_HUMAN="-"
    [ -n "$OVERALL_LAST_LINK_SCAN_STATUS" ] || OVERALL_LAST_LINK_SCAN_STATUS="-"
    validate_number "$OVERALL_LAST_LINK_SCAN_ALIVE" || OVERALL_LAST_LINK_SCAN_ALIVE=0
    validate_number "$OVERALL_LAST_LINK_SCAN_TOTAL" || OVERALL_LAST_LINK_SCAN_TOTAL=0
}

state_write() {
    cat > "$STATE_FILE" <<EOF
FAILCOUNT=$OVERALL_FAILCOUNT
LAST_HTTP_CODE=$OVERALL_LAST_HTTP_CODE
LAST_STATUS=$OVERALL_LAST_STATUS
LAST_TS=$OVERALL_LAST_TS
LAST_TS_HUMAN=$OVERALL_LAST_HUMAN
LAST_SUCCESS_HASH=$OVERALL_LAST_SUCCESS_HASH
LAST_APPLIED_HASH=$OVERALL_LAST_APPLIED_HASH
LAST_LINK_SCAN_TS=$OVERALL_LAST_LINK_SCAN_TS
LAST_LINK_SCAN_HUMAN=$OVERALL_LAST_LINK_SCAN_HUMAN
LAST_LINK_SCAN_STATUS=$OVERALL_LAST_LINK_SCAN_STATUS
LAST_LINK_SCAN_ALIVE=$OVERALL_LAST_LINK_SCAN_ALIVE
LAST_LINK_SCAN_TOTAL=$OVERALL_LAST_LINK_SCAN_TOTAL
EOF
}

set_failcount() {
    state_snapshot
    OVERALL_FAILCOUNT="$1"
    state_write
}

set_last_result() {
    code="$1"
    status="$2"
    state_snapshot
    OVERALL_LAST_HTTP_CODE="$code"
    OVERALL_LAST_STATUS="$status"
    OVERALL_LAST_TS="$(now_ts)"
    OVERALL_LAST_HUMAN="$(now_human)"
    state_write
}

set_last_success_hash() {
    state_snapshot
    OVERALL_LAST_SUCCESS_HASH="$1"
    state_write
}

set_last_applied_hash() {
    state_snapshot
    OVERALL_LAST_APPLIED_HASH="$1"
    state_write
}

set_last_link_scan() {
    status="$1"
    alive="$2"
    total="$3"
    state_snapshot
    OVERALL_LAST_LINK_SCAN_TS="$(now_ts)"
    OVERALL_LAST_LINK_SCAN_HUMAN="$(now_human)"
    OVERALL_LAST_LINK_SCAN_STATUS="$status"
    OVERALL_LAST_LINK_SCAN_ALIVE="$alive"
    OVERALL_LAST_LINK_SCAN_TOTAL="$total"
    state_write
}

read_failcount() {
    state_snapshot
    echo "$OVERALL_FAILCOUNT"
}

reset_failcount() {
    state_snapshot
    OVERALL_FAILCOUNT=0
    state_write
}

read_last_success_hash() {
    state_snapshot
    printf '%s\n' "$OVERALL_LAST_SUCCESS_HASH"
}

link_state_file() {
    printf '%s/%s.state\n' "$LINK_STATE_DIR" "$1"
}

link_state_get() {
    hash="$1"
    key="$2"
    file="$(link_state_file "$hash")"
    if [ -f "$file" ]; then
        sed -n "s/^${key}=//p" "$file" 2>/dev/null | tail -n 1
    fi
}

write_link_state() {
    hash="$1"
    status="$2"
    code="$3"
    checked_ts="$4"
    checked_human="$5"
    cooldown_ts="$6"
    cooldown_human="$7"
    request_ms="${8:-0}"
    request_text="${9:-}"
    validate_number "$request_ms" || request_ms=0
    [ -n "$request_text" ] || request_text="-"
    cat > "$(link_state_file "$hash")" <<EOF
LINK_HASH=$hash
LAST_STATUS=$status
LAST_HTTP_CODE=$code
LAST_CHECKED_TS=$checked_ts
LAST_CHECKED_HUMAN=$checked_human
LAST_REQUEST_TIME_MS=$request_ms
LAST_REQUEST_TIME_TEXT=$request_text
COOLDOWN_UNTIL_TS=$cooldown_ts
COOLDOWN_UNTIL_HUMAN=$cooldown_human
EOF
}

mark_link_alive() {
    hash="$1"
    code="$2"
    request_ms="${3:-0}"
    request_text="${4:-}"
    ts="$(now_ts)"
    human="$(now_human)"
    write_link_state "$hash" "alive" "$code" "$ts" "$human" "0" "-" "$request_ms" "$request_text"
}

mark_link_dead() {
    hash="$1"
    code="$2"
    request_ms="${3:-0}"
    request_text="${4:-}"
    ts="$(now_ts)"
    human="$(now_human)"
    cooldown_ts=0
    cooldown_human="-"
    if [ "$EXCLUDE_DEAD" = "1" ] && [ "$COOLDOWN_SECONDS" -gt 0 ]; then
        cooldown_ts=$((ts + COOLDOWN_SECONDS))
        cooldown_human="$(date -d "@$cooldown_ts" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$cooldown_ts")"
    fi
    write_link_state "$hash" "dead" "$code" "$ts" "$human" "$cooldown_ts" "$cooldown_human" "$request_ms" "$request_text"
}

# A link whose protocol the active engine cannot run. Distinct from dead: nothing
# was measured, the server was never contacted, and switching engines can make it
# usable again with no change to the link. It gets no cooldown for the same
# reason -- there is no failure to back off from.
mark_link_unsupported() {
    hash="$1"
    reason="${2:-unknown}"
    ts="$(now_ts)"
    human="$(now_human)"
    # The converter's wording when it gave one -- it names the transport, not just
    # the protocol -- otherwise the protocol name is all we have.
    case "$reason" in
        *" "*) text="$reason" ;;
        *) text="$reason не поддерживается ядром ${PROBE_LABEL:-$PROXY_ENGINE}" ;;
    esac
    write_link_state "$hash" "unsupported" "000" "$ts" "$human" "0" "-" "0" "$text"
}

cooldown_active() {
    hash="$1"
    [ "$EXCLUDE_DEAD" = "1" ] || return 1
    until_ts="$(link_state_get "$hash" COOLDOWN_UNTIL_TS)"
    validate_number "$until_ts" || return 1
    [ "$until_ts" -gt "$(now_ts)" ]
}


cleanup_test_instance() {
    if [ -n "$TEST_PID" ]; then
        kill "$TEST_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$TEST_PID" 2>/dev/null || true
        TEST_PID=""
    fi
    if [ -n "$TEST_DIR" ] && [ -d "$TEST_DIR" ]; then
        rm -rf "$TEST_DIR"
        TEST_DIR=""
    fi
}

acquire_lock_dir() {
    lock_dir="$1"
    busy_msg="$2"
    if mkdir "$lock_dir" 2>/dev/null; then
        printf '%s\n' "$$" > "$lock_dir/pid" 2>/dev/null || true
        return 0
    fi
    holder_pid=""
    if [ -f "$lock_dir/pid" ]; then
        holder_pid="$(cat "$lock_dir/pid" 2>/dev/null)"
    fi
    if ! validate_number "$holder_pid" || ! kill -0 "$holder_pid" 2>/dev/null; then
        rm -f "$lock_dir/pid" 2>/dev/null || true
        rmdir "$lock_dir" 2>/dev/null || true
        if mkdir "$lock_dir" 2>/dev/null; then
            printf '%s\n' "$$" > "$lock_dir/pid" 2>/dev/null || true
            log_msg "обнаружен stale lock, выполнено восстановление"
            return 0
        fi
    fi
    [ -n "$busy_msg" ] && log_msg "$busy_msg"
    return 1
}

release_lock_dir() {
    lock_dir="$1"
    rm -f "$lock_dir/pid" 2>/dev/null || true
    rmdir "$lock_dir" 2>/dev/null || true
}

acquire_lock() {
    acquire_lock_dir "$LOCK_DIR" "watchdog занят другой операцией"
}

acquire_scan_lock() {
    acquire_lock_dir "$SCAN_LOCK_DIR" "check-all уже выполняется"
}

release_lock() {
    cleanup_test_instance
    release_lock_dir "$LOCK_DIR"
}

release_scan_lock() {
    cleanup_test_instance
    release_lock_dir "$SCAN_LOCK_DIR"
}

with_lock_begin() {
    acquire_lock || return 1
}

with_lock_end() {
    release_lock
}

with_scan_lock_begin() {
    acquire_scan_lock || return 1
}

with_scan_lock_end() {
    release_scan_lock
}
