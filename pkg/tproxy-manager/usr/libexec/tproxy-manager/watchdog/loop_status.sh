check_current_proxy() {
    log_msg "check start: proxy=$PROXY_URL url=$CHECK_URL"
    code="$(probe_proxy_url "$PROXY_URL")"

    if [ "$code" = "200" ]; then
        old_failcount="$(read_failcount)"
        if [ "$old_failcount" -ne 0 ]; then
            log_msg "проверка успешна, код=200, сброс счётчика ошибок $old_failcount -> 0"
        fi
        set_last_result "$code" "OK"
        reset_failcount
        return 0
    fi

    failcount="$(read_failcount)"
    failcount=$((failcount + 1))
    set_failcount "$failcount"
    set_last_result "$code" "FAIL"
    log_msg "ошибка проверки, код=$code, счётчик=$failcount/$FAIL_THRESHOLD, url=$CHECK_URL"

    if [ "$failcount" -ge "$FAIL_THRESHOLD" ]; then
        log_msg "достигнут порог ошибок, выполняется смена outbound"
        if rotate_candidates; then
            set_last_result "$code" "ROTATED"
            reset_failcount
            return 0
        fi
        set_last_result "$code" "ROTATE_FAILED"
        return 1
    fi

    return 1
}

run_once() {
    with_lock_begin || return 1
    check_current_proxy
    rc=$?
    with_lock_end
    return $rc
}

test_rotate() {
    with_lock_begin || return 1
    rotate_candidates
    rc=$?
    if [ $rc -eq 0 ]; then
        set_last_result "-" "ROTATED"
        reset_failcount
    fi
    with_lock_end
    return $rc
}

run_test_link() {
    hash="$1"
    entry="$(find_link_by_hash "$hash")"
    if [ -z "$entry" ]; then
        log_msg "ошибка: ссылка $hash не найдена"
        return 1
    fi
    link="$(printf '%s\n' "$entry" | awk -F '\t' '{print $2}')"

    with_lock_begin || return 1
    probe_link_runtime "$hash" "$link"
    rc=$?
    with_lock_end
    return $rc
}

run_apply_link() {
    hash="$1"
    entry="$(find_link_by_hash "$hash")"
    if [ -z "$entry" ]; then
        log_msg "ошибка: ссылка $hash не найдена"
        return 1
    fi
    link="$(printf '%s\n' "$entry" | awk -F '\t' '{print $2}')"

    with_lock_begin || return 1
    apply_link_runtime "$hash" "$link"
    rc=$?
    if [ $rc -eq 0 ]; then
        set_last_result "200" "APPLIED"
        reset_failcount
    fi
    with_lock_end
    return $rc
}

run_check_all() {
    with_lock_begin || return 1
    tmp_file="$(mktemp /tmp/tproxy-manager-watchdog-all.XXXXXX 2>/dev/null || printf '')"
    if [ -z "$tmp_file" ]; then
        with_lock_end
        log_msg "ошибка: не удалось создать временный список ссылок"
        return 1
    fi

    build_links_index > "$tmp_file"
    total=0
    alive=0
    while IFS="$(printf '\t')" read -r hash link comment lineno; do
        [ -n "$hash" ] || continue
        total=$((total + 1))
        if probe_link_runtime "$hash" "$link"; then
            alive=$((alive + 1))
        fi
        cleanup_test_instance
    done < "$tmp_file"

    rm -f "$tmp_file"
    set_last_link_scan "OK" "$alive" "$total"
    log_msg "проверка всех ссылок завершена: alive=$alive total=$total"
    with_lock_end
    return 0
}

maybe_run_background_check() {
    [ "$BACKGROUND_CHECK_ENABLED" = "1" ] || return 1
    state_snapshot
    now="$(now_ts)"
    last="$OVERALL_LAST_LINK_SCAN_TS"
    validate_number "$last" || last=0
    if [ "$last" -gt 0 ] && [ $((now - last)) -lt "$BACKGROUND_CHECK_INTERVAL" ]; then
        return 1
    fi
    log_msg "запуск фоновой проверки ссылок по таймеру"
    run_check_all
}

show_status() {
    state_snapshot
    if [ -x /etc/init.d/tproxy-manager-watchdog ] && /etc/init.d/tproxy-manager-watchdog status >/dev/null 2>&1; then
        running="yes"
    else
        running="no"
    fi
    cat <<EOF
RUNNING=$running
CHECK_URL=$CHECK_URL
PROXY_URL=$PROXY_URL
INTERVAL=$INTERVAL
FAIL_THRESHOLD=$FAIL_THRESHOLD
CONNECT_TIMEOUT=$CONNECT_TIMEOUT
MAX_TIME=$MAX_TIME
LINKS_FILE=$LINKS_FILE
TEMPLATE_FILE=$TEMPLATE_FILE
TEST_TEMPLATE_FILE=$TEST_TEMPLATE_FILE
OUTBOUND_FILE=$OUTBOUND_FILE
VLESS2JSON=$VLESS2JSON
SERVICE_PATH=$SERVICE_PATH
RESTART_CMD=$RESTART_CMD
TEST_COMMAND=$TEST_COMMAND
SELECTION_MODE=$SELECTION_MODE
EXCLUDE_DEAD=$EXCLUDE_DEAD
DEAD_COOLDOWN_HOURS=$COOLDOWN_HOURS
DEAD_COOLDOWN_MINUTES=$COOLDOWN_MINUTES
TEST_PORT=$TEST_PORT
BACKGROUND_CHECK_ENABLED=$BACKGROUND_CHECK_ENABLED
BACKGROUND_CHECK_INTERVAL=$BACKGROUND_CHECK_INTERVAL
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
STATE_FILE=$STATE_FILE
LINK_STATE_DIR=$LINK_STATE_DIR
LOG_FILE=$LOG_FILE
LOG_TAG=$LOG_TAG
EOF
}

loop_run() {
    log_msg "watchdog запущен, интервал=${INTERVAL}s, фоновая проверка ссылок=${BACKGROUND_CHECK_ENABLED}, таймер=${BACKGROUND_CHECK_INTERVAL}s"
    trap 'release_lock; exit 0' INT TERM
    while true; do
        run_once
        maybe_run_background_check >/dev/null 2>&1 || true
        sleep "$INTERVAL"
    done
}
