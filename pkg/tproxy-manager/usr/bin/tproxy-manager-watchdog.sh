#!/bin/sh

PATH="/usr/sbin:/usr/bin:/sbin:/bin"

WATCHDOG_LIB_DIR="/usr/libexec/tproxy-manager/watchdog"

[ -f "$WATCHDOG_LIB_DIR/common.sh" ] || {
    echo "watchdog library not found: $WATCHDOG_LIB_DIR/common.sh" >&2
    exit 1
}

. "$WATCHDOG_LIB_DIR/common.sh"
. "$WATCHDOG_LIB_DIR/render_apply.sh"
. "$WATCHDOG_LIB_DIR/probe.sh"
. "$WATCHDOG_LIB_DIR/links.sh"
. "$WATCHDOG_LIB_DIR/loop_status.sh"

MODE="${1:-help}"

load_config

case "$MODE" in
    once)
        run_once
        ;;
    run)
        loop_run
        ;;
    status)
        show_status
        ;;
    reset)
        reset_failcount
        log_msg "счётчик ошибок сброшен"
        ;;
    test-rotate)
        test_rotate
        ;;
    test-link)
        [ -n "${2:-}" ] || { usage >&2; exit 1; }
        run_test_link "$2"
        ;;
    apply-link)
        [ -n "${2:-}" ] || { usage >&2; exit 1; }
        run_apply_link "$2"
        ;;
    check-all)
        run_check_all
        ;;
    help|-h|--help)
        usage
        ;;
    *)
        usage >&2
        exit 1
        ;;
esac
